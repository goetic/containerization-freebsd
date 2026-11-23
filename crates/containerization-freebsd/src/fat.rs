//! FAT volumes that `prepare` writes without mounting them on the host: the
//! EFI system partition of a raw disk, and the NoCloud seed.

use crate::error::{Error, Result};
use fatfs::{FileSystem, FormatVolumeOptions, FsOptions, ReadWriteSeek};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// The sector size of the disks that `Volume::esp` reads.
const SECTOR: u64 = 512;
/// The EFI system partition's type GUID, C12A7328-F81F-11D2-BA4B-00A0C93EC93B,
/// as GPT stores it, with its first three fields little-endian.
const ESP_TYPE: [u8; 16] = [
  0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
/// Room in a new volume for its boot sector, tables, and root directory, and
/// for the unused end of each file's last cluster.
const OVERHEAD: u64 = 2 << 20;
const MIB: u64 = 1 << 20;

/// A FAT file system in a disk image, written in place.
pub(crate) struct Volume<T: ReadWriteSeek> {
  fs: FileSystem<T>,
  /// What errors call the volume, such as its image's path.
  name: String,
}

impl Volume<File> {
  /// Creates the image `path` and formats it as a FAT volume labelled
  /// `label`, with room for `contents` bytes of files.
  pub(crate) fn create(path: &Path, label: [u8; 11], contents: u64) -> Result<Self> {
    let name = path.display().to_string();
    let creating = || format!("creating {name}");
    let mut file = File::options()
      .read(true)
      .write(true)
      .create(true)
      .truncate(true)
      .open(path)
      .map_err(Error::io(creating()))?;

    // The FAT tables take under 1/64 of a volume of 512-byte or larger
    // clusters.
    file
      .set_len((contents + contents / 64 + OVERHEAD).next_multiple_of(MIB))
      .and_then(|()| fatfs::format_volume(&mut file, FormatVolumeOptions::new().volume_label(label)))
      .and_then(|()| file.rewind())
      .map_err(Error::io(creating()))?;
    let fs = FileSystem::new(file, FsOptions::new()).map_err(Error::io(creating()))?;
    Ok(Self { fs, name })
  }
}

impl Volume<Partition> {
  /// Opens the FAT file system in the EFI system partition of `disk`, a raw
  /// disk image with a GPT.
  pub(crate) fn esp(disk: &Path) -> Result<Self> {
    let name = format!("the EFI system partition of {}", disk.display());
    let file = File::options()
      .read(true)
      .write(true)
      .open(disk)
      .map_err(Error::io(format!("opening {}", disk.display())))?;
    let range = esp(&file).map_err(Error::io(format!("finding {name}")))?;
    let partition = Partition {
      file,
      start: range.start,
      length: range.end - range.start,
      position: 0,
    };
    let fs = FileSystem::new(partition, FsOptions::new()).map_err(Error::io(format!("reading {name}")))?;
    Ok(Self { fs, name })
  }
}

impl<T: ReadWriteSeek> Volume<T> {
  /// Writes `contents` to the file at `path`, creating its directories and
  /// replacing any file there. `path` separates names with `/`.
  pub(crate) fn write(&self, path: &str, contents: &mut impl Read) -> Result<()> {
    let writing = || format!("writing {path} on {}", self.name);
    let (parents, name) = path.rsplit_once('/').unwrap_or(("", path));
    let mut directory = self.fs.root_dir();

    for parent in parents.split('/').filter(|parent| !parent.is_empty()) {
      directory = directory.create_dir(parent).map_err(Error::io(writing()))?;
    }
    let mut file = directory.create_file(name).map_err(Error::io(writing()))?;
    // create_file opens a file that exists without truncating it.
    file
      .truncate()
      .and_then(|()| io::copy(contents, &mut file))
      .and_then(|_| file.flush())
      .map_err(Error::io(writing()))
  }

  /// Writes out what the volume still holds in memory and closes it.
  pub(crate) fn finish(self) -> Result<()> {
    self
      .fs
      .unmount()
      .map_err(Error::io(format!("closing {}", self.name)))
  }
}

/// The bytes of one partition of a disk image, read and written as a disk of
/// their own.
pub(crate) struct Partition {
  file: File,
  start: u64,
  length: u64,
  position: u64,
}

impl Partition {
  /// How many of `wanted` bytes from the position lie inside the partition.
  fn clamp(&self, wanted: usize) -> usize {
    let left = self.length.saturating_sub(self.position);

    wanted.min(usize::try_from(left).unwrap_or(usize::MAX))
  }
}

impl Read for Partition {
  fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
    let length = self.clamp(buffer.len());
    let read = self
      .file
      .read_at(&mut buffer[..length], self.start + self.position)?;

    self.position += read as u64;
    Ok(read)
  }
}

impl Write for Partition {
  /// Writes nothing at the partition's end, so `write_all` fails there.
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    let length = self.clamp(bytes.len());
    let written = self
      .file
      .write_at(&bytes[..length], self.start + self.position)?;

    self.position += written as u64;
    Ok(written)
  }

  fn flush(&mut self) -> io::Result<()> {
    self.file.flush()
  }
}

impl Seek for Partition {
  fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
    let position = match to {
      SeekFrom::Start(offset) => Some(offset),
      SeekFrom::End(offset) => self.length.checked_add_signed(offset),
      SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
    };

    self.position =
      position.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seeking before the partition's start"))?;
    Ok(self.position)
  }
}

/// The bytes of `disk` that its GPT gives its EFI system partition.
fn esp(disk: &File) -> io::Result<Range<u64>> {
  let invalid = |why: &str| io::Error::new(io::ErrorKind::InvalidData, why.to_string());
  let mut header = [0; 92];
  disk.read_exact_at(&mut header, SECTOR)?;
  if !header.starts_with(b"EFI PART") {
    return Err(invalid("the disk has no GPT"));
  }

  let entries = u64_at(&header, 72);
  let count = u32_at(&header, 80);
  let size = u32_at(&header, 84);
  if size < 128 {
    return Err(invalid("its GPT's entries are under 128 bytes"));
  }
  let mut entry = vec![0; size as usize];
  for index in 0..u64::from(count) {
    disk.read_exact_at(&mut entry, entries * SECTOR + index * u64::from(size))?;
    if entry.starts_with(&ESP_TYPE) {
      return Ok(u64_at(&entry, 32) * SECTOR..(u64_at(&entry, 40) + 1) * SECTOR);
    }
  }
  Err(invalid("its GPT lists no EFI system partition"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
  u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
  u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

#[cfg(test)]
mod tests {
  use super::*;

  /// The sectors of the EFI system partition that `disk` lays out.
  const ESP: Range<u64> = 2048..10240;

  /// Writes a raw disk image at `path` whose GPT lists a FreeBSD boot
  /// partition and then, if `with_esp`, an EFI system partition at `ESP`,
  /// formatted as FAT.
  fn disk(path: &Path, with_esp: bool) {
    let file = File::options()
      .read(true)
      .write(true)
      .create_new(true)
      .open(path)
      .unwrap();
    file.set_len(12 * MIB).unwrap();
    let mut header = [0u8; 92];
    header[..8].copy_from_slice(b"EFI PART");
    header[72..80].copy_from_slice(&2u64.to_le_bytes());
    header[80..84].copy_from_slice(&4u32.to_le_bytes());
    header[84..88].copy_from_slice(&128u32.to_le_bytes());
    file.write_all_at(&header, SECTOR).unwrap();
    // The FreeBSD boot partition type, 83BD6B9D-7F41-11DC-BE0B-001560B84F0F.
    let mut boot = [0u8; 128];
    boot[..16].copy_from_slice(&[
      0x9d, 0x6b, 0xbd, 0x83, 0x41, 0x7f, 0xdc, 0x11, 0xbe, 0x0b, 0x00, 0x15, 0x60, 0xb8, 0x4f, 0x0f,
    ]);
    boot[32..40].copy_from_slice(&40u64.to_le_bytes());
    boot[40..48].copy_from_slice(&1063u64.to_le_bytes());
    file.write_all_at(&boot, 2 * SECTOR).unwrap();
    if !with_esp {
      return;
    }

    let mut esp = [0u8; 128];
    esp[..16].copy_from_slice(&ESP_TYPE);
    esp[32..40].copy_from_slice(&ESP.start.to_le_bytes());
    esp[40..48].copy_from_slice(&(ESP.end - 1).to_le_bytes());
    file.write_all_at(&esp, 2 * SECTOR + 128).unwrap();
    let mut partition = Partition {
      file,
      start: ESP.start * SECTOR,
      length: (ESP.end - ESP.start) * SECTOR,
      position: 0,
    };
    fatfs::format_volume(&mut partition, FormatVolumeOptions::new()).unwrap();
    partition.rewind().unwrap();
    let fs = FileSystem::new(partition, FsOptions::new()).unwrap();
    // The directories are named in capitals, which writing must match, and
    // hold an older, longer loader.env, which writing must replace whole.
    fs.root_dir().create_dir("EFI").unwrap();
    fs.root_dir().create_dir("EFI/FREEBSD").unwrap();
    let mut old = fs.root_dir().create_file("EFI/FREEBSD/LOADER.ENV").unwrap();
    old.write_all(b"a longer, older loader.env\n").unwrap();
    drop(old);
    fs.unmount().unwrap();
  }

  fn read(volume: &Volume<impl ReadWriteSeek>, path: &str) -> String {
    let mut contents = String::new();
    volume
      .fs
      .root_dir()
      .open_file(path)
      .unwrap()
      .read_to_string(&mut contents)
      .unwrap();
    contents
  }

  #[test]
  fn writes_a_file_in_the_efi_system_partition() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("disk.raw");
    disk(&path, true);

    let esp = Volume::esp(&path).unwrap();
    esp
      .write("efi/freebsd/loader.env", &mut b"kern.racct.enable=1\n".as_slice())
      .unwrap();
    esp.finish().unwrap();

    let esp = Volume::esp(&path).unwrap();
    assert_eq!(read(&esp, "efi/freebsd/loader.env"), "kern.racct.enable=1\n");
    // Only the partition changed: the bytes after it are still zero.
    let file = File::open(&path).unwrap();
    let mut after = vec![1u8; (12 * MIB - ESP.end * SECTOR) as usize];
    file.read_exact_at(&mut after, ESP.end * SECTOR).unwrap();
    assert!(after.iter().all(|byte| *byte == 0));
  }

  #[test]
  fn refuses_a_disk_without_an_efi_system_partition() {
    let root = tempfile::tempdir().unwrap();
    let without = root.path().join("without.raw");
    disk(&without, false);
    let blank = root.path().join("blank.raw");
    File::create(&blank).unwrap().set_len(MIB).unwrap();

    for (path, why) in [(&without, "lists no EFI system partition"), (&blank, "has no GPT")] {
      let error = Volume::esp(path).err().unwrap();
      assert!(error.to_string().contains(why), "{error}");
    }
  }

  #[test]
  fn makes_a_labelled_volume_that_holds_its_files() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("seed.img");
    let bundle: Vec<u8> = (0..3 * MIB as usize)
      .map(|index| (index * 7 % 251) as u8)
      .collect();

    let seed = Volume::create(&path, *b"CIDATA     ", bundle.len() as u64 + 20).unwrap();
    seed
      .write("meta-data", &mut b"instance-id: one\n".as_slice())
      .unwrap();
    seed.write("bundle.tar.xz", &mut bundle.as_slice()).unwrap();
    seed.finish().unwrap();

    let file = File::options().read(true).write(true).open(&path).unwrap();
    let seed = Volume {
      fs: FileSystem::new(file, FsOptions::new()).unwrap(),
      name: String::new(),
    };
    assert_eq!(seed.fs.volume_label(), "CIDATA");
    assert_eq!(read(&seed, "meta-data"), "instance-id: one\n");
    let mut read_back = Vec::new();
    seed
      .fs
      .root_dir()
      .open_file("bundle.tar.xz")
      .unwrap()
      .read_to_end(&mut read_back)
      .unwrap();
    assert!(read_back == bundle);
  }
}
