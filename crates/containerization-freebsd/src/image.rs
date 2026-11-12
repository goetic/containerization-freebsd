//! FreeBSD's VM image, and the disks and volumes made from it on the host.

use crate::error::{Error, Result};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RELEASE: &str = "15.1-RELEASE";
pub const IMAGE: &str = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.raw.xz";
/// The decompressed image's name in the cache `base_disk` keeps.
pub const BASE_DISK: &str = "base.raw";

fn run(command: &mut Command) -> Result<String> {
  let description = format!("{command:?}");
  let failed = |failure: String| Error::Command {
    command: description.clone(),
    failure,
  };
  let output = command
    .output()
    .map_err(|error| failed(error.to_string()))?;

  if !output.status.success() {
    return Err(failed(format!(
      "exited {}: {}",
      output.status,
      String::from_utf8_lossy(&output.stderr)
    )));
  }

  Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn fetch(url: &str, destination: &Path) -> Result<()> {
  if destination.exists() {
    return Ok(());
  }

  let partial = destination.with_extension("partial");
  run(
    Command::new("curl")
      .args(["-fsSL", "--retry", "3", "-o"])
      .arg(&partial)
      .arg(url),
  )?;
  std::fs::rename(&partial, destination).map_err(Error::io(format!("moving {} into place", destination.display())))
}

fn sha256(path: &Path) -> Result<String> {
  let output = run(Command::new("shasum").args(["-a", "256"]).arg(path))?;

  Ok(
    output
      .split_whitespace()
      .next()
      .unwrap_or_default()
      .to_string(),
  )
}

fn verify(path: &Path, expected: &str) -> Result<()> {
  let actual = sha256(path)?;

  if actual == expected {
    Ok(())
  } else {
    let _ = std::fs::remove_file(path);
    Err(Error::Checksum {
      path: path.to_path_buf(),
      actual,
      expected: expected.to_string(),
    })
  }
}

/// The decompressed base disk in `cache`, downloaded and verified once.
pub fn base_disk(cache: &Path) -> Result<PathBuf> {
  base_disk_from(
    &format!("https://download.freebsd.org/releases/VM-IMAGES/{RELEASE}/aarch64/Latest"),
    cache,
  )
}

/// As `base_disk`, from the release directory at `directory`.
fn base_disk_from(directory: &str, cache: &Path) -> Result<PathBuf> {
  let raw = cache.join(BASE_DISK);

  if raw.exists() {
    return Ok(raw);
  }

  std::fs::create_dir_all(cache).map_err(Error::io(format!("making {}", cache.display())))?;
  let sums = cache.join("CHECKSUM.SHA256");
  let compressed = cache.join(IMAGE);

  fetch(&format!("{directory}/CHECKSUM.SHA256"), &sums)?;
  fetch(&format!("{directory}/{IMAGE}"), &compressed)?;

  let sums = std::fs::read_to_string(&sums).map_err(Error::io("reading CHECKSUM.SHA256"))?;
  let expected =
    published_sha256(&sums, IMAGE).ok_or_else(|| Error::Guest(format!("CHECKSUM.SHA256 does not list {IMAGE}")))?;
  verify(&compressed, expected)?;

  let partial = raw.with_extension("partial");
  decompress_sparse(&compressed, &partial)?;
  std::fs::rename(&partial, &raw).map_err(Error::io("moving the base disk into place"))?;

  Ok(raw)
}

/// The sha256 a `CHECKSUM.SHA256` lists for `name`: `SHA256 (name) = …`.
fn published_sha256<'a>(sums: &'a str, name: &str) -> Option<&'a str> {
  sums
    .lines()
    .find(|line| line.contains(&format!("({name})")))
    .and_then(|line| line.rsplit(' ').next())
}

/// Skips runs of zeros, so the image takes only the space its data needs.
fn decompress_sparse(source: &Path, destination: &Path) -> Result<()> {
  let decompressing = || format!("decompressing {}", source.display());
  let input = File::open(source).map_err(Error::io(decompressing()))?;
  let mut decoder = xz2::read::XzDecoder::new(BufReader::new(input));
  let mut output = File::create(destination).map_err(Error::io(decompressing()))?;
  let mut chunk = vec![0u8; 1 << 20];
  let mut length = 0u64;

  loop {
    let mut filled = 0;

    while filled < chunk.len() {
      match decoder.read(&mut chunk[filled..]) {
        Ok(0) => break,
        Ok(read) => filled += read,
        Err(error) => return Err(Error::io(decompressing())(error)),
      }
    }

    if filled == 0 {
      break;
    }

    let data = &chunk[..filled];
    if data.iter().all(|&byte| byte == 0) {
      output
        .seek(SeekFrom::Current(filled as i64))
        .map_err(Error::io(decompressing()))?;
    } else {
      output.write_all(data).map_err(Error::io(decompressing()))?;
    }
    length += filled as u64;
  }

  output.set_len(length).map_err(Error::io(decompressing()))
}

/// A copy-on-write clone of `base` (APFS `clonefile`, through `cp -c`), grown
/// to `size` bytes for the guest to expand into.
pub fn clone(base: &Path, destination: &Path, size: u64) -> Result<()> {
  let _ = std::fs::remove_file(destination);
  run(Command::new("cp").arg("-c").arg(base).arg(destination))?;

  let growing = || format!("growing {}", destination.display());
  let file = File::options()
    .write(true)
    .open(destination)
    .map_err(Error::io(growing()))?;
  if file.metadata().map_err(Error::io(growing()))?.len() < size {
    file.set_len(size).map_err(Error::io(growing()))?;
  }

  Ok(())
}

/// Writes `/efi/freebsd/loader.env` on the disk's EFI system partition:
/// variables FreeBSD's loader sets before `loader.conf`, and passes on to the
/// kernel as tunables. The partition is FAT, which the Mac mounts without root.
pub fn write_loader_env(disk: &Path, mount_point: &Path, contents: &str) -> Result<()> {
  let attached = run(
    Command::new("hdiutil")
      .args(["attach", "-nomount", "-imagekey", "diskimage-class=CRawDiskImage"])
      .arg(disk),
  )?;
  let whole = attached
    .split_whitespace()
    .next()
    .ok_or_else(|| Error::Guest(format!("hdiutil attached nothing of {}", disk.display())))?
    .to_string();

  let written = (|| {
    let partition = attached
      .lines()
      .find(|line| line.split_whitespace().nth(1) == Some("EFI"))
      .and_then(|line| line.split_whitespace().next())
      .ok_or_else(|| Error::Guest(format!("no EFI partition among:\n{attached}")))?;

    std::fs::create_dir_all(mount_point).map_err(Error::io(format!("making {}", mount_point.display())))?;
    run(
      Command::new("diskutil")
        .args(["mount", "-mountPoint"])
        .arg(mount_point)
        .arg(partition),
    )?;

    let directory = mount_point.join("efi/freebsd");
    let result = std::fs::create_dir_all(&directory)
      .and_then(|()| std::fs::write(directory.join("loader.env"), contents))
      .map_err(Error::io("writing loader.env"));

    run(Command::new("diskutil").arg("unmount").arg(mount_point))?;
    result
  })();

  run(Command::new("hdiutil").arg("detach").arg(&whole))?;
  written
}

/// A NoCloud seed volume, labelled `cidata`, holding `files`: each a name on
/// the volume, and the file to put there.
pub fn seed(directory: &Path, iso: &Path, files: &[(&str, &Path)]) -> Result<()> {
  let _ = std::fs::remove_dir_all(directory);
  let _ = std::fs::remove_file(iso);
  std::fs::create_dir_all(directory).map_err(Error::io(format!("making {}", directory.display())))?;

  for (name, source) in files {
    let target = directory.join(name);

    std::fs::hard_link(source, &target)
      .or_else(|_| std::fs::copy(source, &target).map(|_| ()))
      .map_err(Error::io(format!("putting {} on the seed volume", source.display())))?;
  }

  run(
    Command::new("hdiutil")
      .args([
        "makehybrid",
        "-quiet",
        "-iso",
        "-joliet",
        "-default-volume-name",
        "cidata",
        "-o",
      ])
      .arg(iso)
      .arg(directory),
  )?;

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_the_sha256_published_for_an_image() {
    let sums = "SHA256 (other.raw.xz) = 1111\nSHA256 (FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.raw.xz) = \
                abcd\n";

    assert_eq!(published_sha256(sums, IMAGE), Some("abcd"));
    assert_eq!(published_sha256(sums, "missing.raw.xz"), None);
  }

  #[test]
  fn decompresses_runs_of_zeros_to_holes_of_the_same_length() {
    let directory = tempfile::tempdir().unwrap();
    let directory = directory.path();
    let mut data = vec![0u8; 3 << 20];
    data[..5].copy_from_slice(b"start");
    data.extend_from_slice(b"end");

    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
    encoder.write_all(&data).unwrap();
    std::fs::write(directory.join("in.xz"), encoder.finish().unwrap()).unwrap();

    decompress_sparse(&directory.join("in.xz"), &directory.join("out")).unwrap();
    let out = std::fs::read(directory.join("out")).unwrap();

    assert_eq!(out, data);
  }

  /// A release directory holding `data` as the image, and a `CHECKSUM.SHA256`
  /// listing `listed` for it. Its `file://` URL.
  fn release(directory: &Path, data: &[u8], listed: Option<&str>) -> String {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
    encoder.write_all(data).unwrap();
    std::fs::write(directory.join(IMAGE), encoder.finish().unwrap()).unwrap();

    let sha256 = match listed {
      Some(listed) => listed.to_string(),
      None => sha256(&directory.join(IMAGE)).unwrap(),
    };
    std::fs::write(
      directory.join("CHECKSUM.SHA256"),
      format!("SHA256 ({IMAGE}) = {sha256}\n"),
    )
    .unwrap();

    format!("file://{}", directory.display())
  }

  #[test]
  fn downloads_verifies_and_decompresses_the_image_once() {
    let source = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let url = release(source.path(), b"disk", None);

    let raw = base_disk_from(&url, cache.path()).unwrap();
    assert_eq!(std::fs::read(&raw).unwrap(), b"disk");

    std::fs::remove_file(source.path().join(IMAGE)).unwrap();
    assert_eq!(base_disk_from(&url, cache.path()).unwrap(), raw);
  }

  #[test]
  fn refuses_and_discards_an_image_whose_sha256_differs() {
    let source = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let url = release(source.path(), b"disk", Some("0000"));

    let error = base_disk_from(&url, cache.path()).unwrap_err();
    assert!(matches!(error, Error::Checksum { .. }), "{error}");
    assert!(!cache.path().join(IMAGE).exists());
    assert!(!cache.path().join(BASE_DISK).exists());
  }

  #[test]
  fn fails_when_the_release_is_missing() {
    let cache = tempfile::tempdir().unwrap();
    let missing = cache.path().join("missing");

    let error = base_disk_from(&format!("file://{}", missing.display()), cache.path()).unwrap_err();
    assert!(matches!(error, Error::Command { .. }), "{error}");
  }
}
