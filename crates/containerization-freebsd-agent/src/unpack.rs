//! Unpacking an OCI image layer onto a root, which the host runs as the agent
//! binary's `unpack` subcommand, feeding it the layer's blob. The layer is
//! decompressed into a staging file, hashed and searched for whiteouts on the
//! way, and checked against its diff ID. Then its whiteouts delete files from
//! the layers beneath it, and bsdtar extracts it.

use crate::{mount, sys};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What a whiteout's name starts with.
const WHITEOUT: &str = ".wh.";
/// The name of an opaque whiteout, which empties its directory.
const OPAQUE: &str = ".wh..wh..opq";
/// A tar archive's block size.
const BLOCK: usize = 512;
/// The longest pax header or GNU long name to read.
const EXTENDED: u64 = 1 << 20;
/// How much to read at a time.
const CHUNK: usize = 128 << 10;

/// Unpacks the layer read from `input`, compressed with `compression`
/// (`gzip`, `zstd`, or `none`), onto `root`, staging it at `staging`, which
/// is removed whatever happens. Fails unless the layer's sha256 is
/// `diff_id`, in hex.
pub fn unpack(
  input: impl Read + Send + 'static,
  compression: &str,
  root: &Path,
  staging: &Path,
  diff_id: &str,
) -> io::Result<()> {
  let staged = Staged(staging.to_path_buf());
  let (sha256, whiteouts) = stage(input, compression, &staged.0)?;

  if sha256 != diff_id {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      format!("its sha256 is {sha256}, not the config's {diff_id}"),
    ));
  }
  for whiteout in &whiteouts {
    apply(root, whiteout)?;
  }
  extract(root, &staged.0)
}

/// A staging file, removed when this is dropped.
struct Staged(PathBuf);

impl Drop for Staged {
  fn drop(&mut self) {
    let _ = fs::remove_file(&self.0);
  }
}

/// Decompresses `input` into the file `staging`, and returns the sha256 of
/// what it wrote, in hex, and the whiteouts in it.
fn stage(input: impl Read + Send + 'static, compression: &str, staging: &Path) -> io::Result<(String, Vec<String>)> {
  let decompressor = match compression {
    "none" => None,
    "gzip" => Some(("gzip", "-dc")),
    "zstd" => Some(("zstd", "-dcq")),
    other => {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{other:?} is no compression the agent knows"),
      ));
    }
  };
  let mut file = File::create(staging)?;
  let mut hash = sys::Sha256::new();
  let mut listing = Listing::default();
  let take = |chunk: &[u8]| {
    hash.update(chunk);
    listing.push(chunk);
    file.write_all(chunk)
  };

  match decompressor {
    None => each_chunk(input, take)?,
    Some((program, flag)) => decompress(input, program, flag, take)?,
  }
  let whiteouts = listing.finish()?;
  let hex = hash
    .finish()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();
  Ok((hex, whiteouts))
}

/// Pipes `input` through `program` with `flag`, and passes each chunk of its
/// output to `take`.
fn decompress(
  mut input: impl Read + Send + 'static,
  program: &str,
  flag: &str,
  take: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
  let mut child = Command::new(program)
    .arg(flag)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()?;
  let (Some(mut stdin), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
    return Err(io::Error::other(format!("{program} has no pipes")));
  };
  // A thread feeds the decompressor, so that its output is read as it comes.
  // Dropping its stdin at the end lets it finish.
  let feeding = std::thread::spawn(move || io::copy(&mut input, &mut stdin).map(|_| ()));

  let read = each_chunk(output, take);
  if read.is_err() {
    // Otherwise it may block writing what nothing reads.
    let _ = child.kill();
  }
  let status = child.wait()?;
  let fed = feeding
    .join()
    .unwrap_or_else(|_| Err(io::Error::other("the thread feeding the decompressor panicked")));
  read?;
  if !status.success() {
    return Err(io::Error::other(format!("{program} exited with {status}")));
  }
  fed
}

/// Passes each chunk read from `reader` to `take`, until the end.
fn each_chunk(mut reader: impl Read, mut take: impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
  let mut buffer = vec![0; CHUNK];

  loop {
    match reader.read(&mut buffer) {
      Ok(0) => return Ok(()),
      Ok(read) => take(&buffer[..read])?,
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(error) => return Err(error),
    }
  }
}

/// The whiteouts of a tar stream, found in its headers as the stream goes
/// by.
#[derive(Default)]
struct Listing {
  whiteouts: Vec<String>,
  state: State,
  /// What has come of the header or extended header being read.
  pending: Vec<u8>,
  /// The name and size that a pax header or GNU long name gives the next
  /// entry.
  next_name: Option<String>,
  next_size: Option<u64>,
  /// Why the listing can't be trusted, if it can't.
  failed: Option<String>,
}

#[derive(Clone, Copy, Default)]
enum State {
  #[default]
  Header,
  /// Bytes to pass over: an entry's data and padding.
  Skip(u64),
  /// A pax header's or GNU long name's data, of `size` bytes, to read whole.
  Extended { kind: u8, size: u64 },
  /// Past the end-of-archive block.
  End,
}

impl Listing {
  fn push(&mut self, mut bytes: &[u8]) {
    while !bytes.is_empty() {
      let wanted = match self.state {
        State::End => return,
        State::Skip(left) => {
          let passed = left.min(bytes.len() as u64);
          bytes = &bytes[passed as usize..];
          self.state = match left - passed {
            0 => State::Header,
            left => State::Skip(left),
          };
          continue;
        }
        State::Header => BLOCK,
        State::Extended { size, .. } => padded(size) as usize,
      };
      let taken = (wanted - self.pending.len()).min(bytes.len());
      self.pending.extend_from_slice(&bytes[..taken]);
      bytes = &bytes[taken..];
      if self.pending.len() < wanted {
        continue;
      }
      let block = std::mem::take(&mut self.pending);
      self.state = match self.state {
        State::Extended { kind, size } => {
          self.extended(kind, &block[..size as usize]);
          State::Header
        }
        _ => self.header(&block),
      };
    }
  }

  /// The whiteouts, unless the stream couldn't be read.
  fn finish(self) -> io::Result<Vec<String>> {
    match self.failed {
      Some(why) => Err(io::Error::new(io::ErrorKind::InvalidData, why)),
      None => Ok(self.whiteouts),
    }
  }

  /// Reads a header block, notes its entry if it is a whiteout, and returns
  /// what comes next.
  fn header(&mut self, block: &[u8]) -> State {
    // The archive ends at a block of zeros.
    if block.iter().all(|&byte| byte == 0) {
      return State::End;
    }
    let Some(own_size) = number(&block[124..136]) else {
      return self.fail("a tar header's size is unreadable".to_string());
    };
    let kind = block[156];
    match kind {
      b'L' | b'x' if own_size > EXTENDED => {
        return self.fail(format!("a tar extended header of {own_size} bytes is too long"));
      }
      b'L' | b'x' => return State::Extended { kind, size: own_size },
      // A global pax header or a GNU long link name names no entry.
      b'g' | b'K' => return skip(own_size),
      _ => {}
    }
    let name = self.next_name.take().unwrap_or_else(|| ustar_name(block));
    let size = self.next_size.take().unwrap_or(own_size);
    let base = name
      .trim_end_matches('/')
      .rsplit('/')
      .next()
      .unwrap_or_default();
    if base.starts_with(WHITEOUT) {
      self.whiteouts.push(name);
    }
    match kind {
      // Symlinks, devices, directories, and FIFOs have no data, whatever
      // their size says.
      b'2'..=b'6' => State::Header,
      _ => skip(size),
    }
  }

  /// Reads a GNU long name or a pax header, which apply to the next entry.
  fn extended(&mut self, kind: u8, data: &[u8]) {
    if kind == b'L' {
      self.next_name = Some(String::from_utf8_lossy(field(data)).into_owned());
      return;
    }
    // Each record is `<length> <key>=<value>\n`, and its length counts all
    // of it.
    let mut records = data;
    while let Some(space) = records.iter().position(|&byte| byte == b' ') {
      let length = std::str::from_utf8(&records[..space])
        .ok()
        .and_then(|length| length.parse::<usize>().ok())
        .filter(|&length| length > space && length <= records.len());
      let Some(length) = length else {
        break;
      };
      let record = &records[space + 1..length];
      records = &records[length..];
      let record = record.strip_suffix(b"\n").unwrap_or(record);
      let Some(equals) = record.iter().position(|&byte| byte == b'=') else {
        continue;
      };
      let value = &record[equals + 1..];
      match &record[..equals] {
        b"path" => self.next_name = Some(String::from_utf8_lossy(value).into_owned()),
        b"size" => {
          self.next_size = std::str::from_utf8(value)
            .ok()
            .and_then(|size| size.parse().ok());
        }
        _ => {}
      }
    }
  }

  fn fail(&mut self, why: String) -> State {
    self.failed.get_or_insert(why);
    State::End
  }
}

/// Passing over `size` bytes of data, padded to a whole block.
fn skip(size: u64) -> State {
  match padded(size) {
    0 => State::Header,
    size => State::Skip(size),
  }
}

fn padded(size: u64) -> u64 {
  size.div_ceil(BLOCK as u64) * BLOCK as u64
}

/// A ustar header's path: its prefix, if it has one, then its name.
fn ustar_name(block: &[u8]) -> String {
  let name = field(&block[..100]);
  // Old GNU archives, whose magic differs, keep other fields there.
  let prefix = match &block[257..263] {
    b"ustar\0" => field(&block[345..500]),
    _ => &[],
  };
  let path = match prefix {
    [] => name.to_vec(),
    prefix => [prefix, b"/", name].concat(),
  };
  String::from_utf8_lossy(&path).into_owned()
}

/// A header field's bytes, up to its NUL.
fn field(bytes: &[u8]) -> &[u8] {
  bytes.split(|&byte| byte == 0).next().unwrap_or_default()
}

/// A header's number: octal, or base-256 for one too big for octal.
fn number(field: &[u8]) -> Option<u64> {
  if let [first, rest @ ..] = field
    && first & 0x80 != 0
  {
    return rest
      .iter()
      .try_fold(u64::from(first & 0x7f), |value, &byte| {
        value.checked_mul(256)?.checked_add(u64::from(byte))
      });
  }
  let digits = std::str::from_utf8(field)
    .ok()?
    .trim_matches(|char| char == '\0' || char == ' ');
  match digits {
    "" => Some(0),
    digits => u64::from_str_radix(digits, 8).ok(),
  }
}

/// Applies the whiteout `entry`, a path in the layer, to the tree at `root`:
/// an opaque whiteout empties its directory, and any other removes the file
/// it names. Paths resolve within the root, as in the jail it becomes, so a
/// whiteout reaches nothing outside it.
fn apply(root: &Path, entry: &str) -> io::Result<()> {
  let path = entry.trim_end_matches('/');
  let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
  let parent = mount::resolve(root, directory)?;

  if name == OPAQUE {
    let children = match fs::read_dir(&parent) {
      Ok(children) => children,
      Err(error) if missing(&error) => return Ok(()),
      Err(error) => return Err(error),
    };
    for child in children {
      remove(&child?.path())?;
    }
    return Ok(());
  }
  let hidden = name
    .strip_prefix(WHITEOUT)
    .filter(|hidden| !matches!(*hidden, "" | "." | ".."))
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("whiteout {entry:?} hides nothing")))?;
  let target = parent.join(hidden);
  match fs::symlink_metadata(&target) {
    Ok(_) => remove(&target),
    Err(error) if missing(&error) => Ok(()),
    Err(error) => Err(error),
  }
}

fn missing(error: &io::Error) -> bool {
  matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
}

/// Removes the file or tree at `path`, without following symlinks, clearing
/// file flags such as `schg` if they are in the way.
fn remove(path: &Path) -> io::Result<()> {
  match remove_tree(path) {
    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
      clear_flags(path)?;
      remove_tree(path)
    }
    removed => removed,
  }
}

fn remove_tree(path: &Path) -> io::Result<()> {
  if fs::symlink_metadata(path)?.is_dir() {
    fs::remove_dir_all(path)
  } else {
    fs::remove_file(path)
  }
}

/// Clears the flags of `path` and, if it is a directory, of everything under
/// it.
fn clear_flags(path: &Path) -> io::Result<()> {
  sys::clear_flags(path)?;
  if fs::symlink_metadata(path)?.is_dir() {
    for child in fs::read_dir(path)? {
      clear_flags(&child?.path())?;
    }
  }
  Ok(())
}

/// Extracts the tarball at `staging` onto `root` with bsdtar, which restores
/// file flags, ACLs, hard links, and devices, with the archive's numeric
/// owners, and leaves out whiteouts.
fn extract(root: &Path, staging: &Path) -> io::Result<()> {
  let status = Command::new("tar")
    .arg("-xpf")
    .arg(staging)
    .arg("-C")
    .arg(root)
    .args(["--numeric-owner", "--exclude", ".wh.*"])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .status()?;

  if !status.success() {
    return Err(io::Error::other(format!("tar exited with {status}")));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::os::unix::fs::symlink;

  /// Archives the files under `source` with bsdtar in `format`.
  fn archive(source: &Path, format: &str) -> Vec<u8> {
    let output = Command::new("tar")
      .args(["--format", format, "-cf", "-", "-C"])
      .arg(source)
      .arg(".")
      .output()
      .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    output.stdout
  }

  fn write(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
  }

  #[test]
  fn lists_whiteouts_in_every_header_format() {
    let source = tempfile::tempdir().unwrap();
    let long = "d".repeat(120);
    write(&source.path().join(".wh.top"), "");
    write(&source.path().join("dir/.wh.inner"), "");
    write(&source.path().join(format!("{long}/.wh.long")), "");
    // Data that looks like a header must be passed over.
    write(&source.path().join("dir/data"), &".wh.fake\0".repeat(200));
    let mut expected = ["./.wh.top", "./dir/.wh.inner", &format!("./{long}/.wh.long")].map(str::to_string);
    expected.sort();

    for format in ["ustar", "pax", "gnutar"] {
      let tar = archive(source.path(), format);
      let mut listing = Listing::default();
      // In odd pieces, so that headers and data straddle them.
      for piece in tar.chunks(509) {
        listing.push(piece);
      }
      let mut whiteouts = listing.finish().unwrap();
      whiteouts.sort();
      assert_eq!(whiteouts, expected, "in {format}");
    }
  }

  #[test]
  fn reads_octal_and_base_256_numbers() {
    assert_eq!(number(b"00000001750\0"), Some(1000));
    assert_eq!(number(b"     144 \0\0\0"), Some(100));
    assert_eq!(number(&[0x80, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0]), Some(2 << 24));
    assert_eq!(number(b"9"), None);
  }

  #[test]
  fn applies_whiteouts_within_the_root() {
    let (directory, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let root = directory.path();
    write(&root.join("gone"), "");
    write(&root.join("dir/old"), "");
    write(&root.join("opaque/a/b"), "");
    write(&outside.path().join("victim"), "");
    symlink("/dir", root.join("link")).unwrap();
    symlink(outside.path(), root.join("escape")).unwrap();

    for entry in [
      ".wh.gone",
      "link/.wh.old",
      "escape/.wh.victim",
      "./opaque/.wh..wh..opq",
      ".wh.missing",
    ] {
      apply(root, entry).unwrap();
    }

    assert!(!root.join("gone").exists() && !root.join("dir/old").exists());
    assert!(root.join("dir").is_dir());
    assert!(
      outside.path().join("victim").exists(),
      "a whiteout reached outside the root"
    );
    assert_eq!(fs::read_dir(root.join("opaque")).unwrap().count(), 0);
    assert!(
      apply(root, "dir/.wh..")
        .unwrap_err()
        .to_string()
        .contains("hides nothing")
    );
  }

  #[test]
  fn unpacks_a_layer_onto_the_layers_beneath() {
    let (directory, source, work) = (
      tempfile::tempdir().unwrap(),
      tempfile::tempdir().unwrap(),
      tempfile::tempdir().unwrap(),
    );
    let root = directory.path();
    write(&root.join("kept"), "lower");
    write(&root.join("gone"), "lower");
    write(&root.join("dir/old"), "lower");
    write(&source.path().join(".wh.gone"), "");
    write(&source.path().join("dir/.wh..wh..opq"), "");
    write(&source.path().join("dir/new"), "upper");
    write(&source.path().join("added"), "upper");
    let tar = archive(source.path(), "pax");
    let mut hash = sys::Sha256::new();
    hash.update(&tar);
    let diff_id: String = hash
      .finish()
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    let tarball = work.path().join("layer.tar");
    fs::write(&tarball, &tar).unwrap();
    let compressed = Command::new("gzip")
      .arg("-c")
      .arg(&tarball)
      .output()
      .unwrap()
      .stdout;
    let staging = work.path().join("staging.tar");

    let unpacked = unpack(io::Cursor::new(compressed), "gzip", root, &staging, &diff_id);

    unpacked.unwrap();
    assert_eq!(fs::read_to_string(root.join("kept")).unwrap(), "lower");
    assert!(!root.join("gone").exists() && !root.join("dir/old").exists());
    assert_eq!(fs::read_to_string(root.join("dir/new")).unwrap(), "upper");
    assert_eq!(fs::read_to_string(root.join("added")).unwrap(), "upper");
    assert!(!root.join(".wh.gone").exists() && !root.join("dir/.wh..wh..opq").exists());
    assert!(!staging.exists());

    let wrong = unpack(io::Cursor::new(tar), "none", root, &staging, &"0".repeat(64));
    assert!(wrong.unwrap_err().to_string().contains("not the config's"));
    assert!(!staging.exists());
    assert!(unpack(io::empty(), "lz4", root, &staging, &diff_id).is_err());
  }
}
