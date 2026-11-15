//! Images on the host, in an OCI image layout: `index.json` names each
//! image by its reference, and `blobs/sha256` holds their content. Like
//! Containerization's image store; where it lives is the caller's choice.

use crate::error::{Error, Result};
use crate::oci::{
  ContentStore, Credentials, Descriptor, ImageConfig, Index, Manifest, Platform, REF_NAME, Reference, RegistryClient,
  parse,
};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const LAYOUT: &str = r#"{"imageLayoutVersion":"1.0.0"}"#;
/// How an xz stream starts.
const XZ: &[u8] = b"\xfd7zXZ\0";

pub struct ImageStore {
  root: PathBuf,
  content: ContentStore,
}

/// An index or manifest the store names by the reference it was pulled or
/// tagged as.
#[derive(Clone, Debug)]
pub struct Image {
  pub reference: String,
  pub descriptor: Descriptor,
  content: ContentStore,
}

impl ImageStore {
  /// The store at `root`, made if need be.
  pub fn new(root: &Path) -> Result<Self> {
    let content = ContentStore::new(root)?;
    let layout = root.join("oci-layout");
    if !layout.exists() {
      std::fs::write(&layout, LAYOUT).map_err(Error::io(format!("writing {}", layout.display())))?;
    }

    Ok(Self {
      root: root.to_path_buf(),
      content,
    })
  }

  pub fn content(&self) -> &ContentStore {
    &self.content
  }

  /// Pulls `reference`'s image for `platform`: its index, if it has one,
  /// and the platform's manifest, config and layers. Blobs the store holds
  /// already aren't downloaded again.
  pub fn pull(&self, reference: &str, platform: &Platform, credentials: Option<Credentials>) -> Result<Image> {
    let reference = Reference::parse(reference)?;
    let client = RegistryClient::new(credentials);
    let top = client.fetch_manifest(&reference, reference.target(), &self.content)?;

    let manifest = if top.is_index() {
      let index: Index = parse(&self.content.read(&top.digest)?, &format!("{reference}'s index"))?;
      let chosen = choose(&index, platform).ok_or_else(|| {
        Error::Invalid(format!(
          "{reference} has no image for {platform}, only {}",
          platforms(&index)
        ))
      })?;
      if !self.content.has(&chosen.digest) {
        client.fetch_manifest(&reference, &chosen.digest, &self.content)?;
      }
      chosen
    } else {
      top.clone()
    };
    let manifest: Manifest = parse(
      &self.content.read(&manifest.digest)?,
      &format!("{reference}'s manifest"),
    )?;

    if !self.content.has(&manifest.config.digest) {
      client.fetch_blob(&reference, &manifest.config, &self.content)?;
    }
    let config: ImageConfig = parse(
      &self.content.read(&manifest.config.digest)?,
      &format!("{reference}'s config"),
    )?;
    if !platform.runs(&config.platform()) {
      return Err(Error::Invalid(format!(
        "{reference} is an image for {}, not {platform}",
        config.platform()
      )));
    }
    for layer in &manifest.layers {
      if !self.content.has(&layer.digest) {
        client.fetch_blob(&reference, layer, &self.content)?;
      }
    }

    self.create(&reference.to_string(), top)
  }

  /// Names `descriptor`, an index or manifest in the store, `reference`,
  /// replacing any image of that name.
  pub fn create(&self, reference: &str, descriptor: Descriptor) -> Result<Image> {
    let reference = Reference::parse(reference)?.to_string();
    if !self.content.has(&descriptor.digest) {
      return Err(Error::Invalid(format!(
        "the store has no blob {} for {reference}",
        descriptor.digest
      )));
    }

    let mut descriptor = descriptor;
    descriptor.platform = None;
    descriptor.annotations.clear();
    descriptor
      .annotations
      .insert(REF_NAME.to_string(), reference.clone());
    self.update(|index| {
      index
        .manifests
        .retain(|entry| name(entry) != Some(&reference));
      index.manifests.push(descriptor.clone());
      Ok(())
    })?;
    Ok(self.image(reference, descriptor))
  }

  pub fn get(&self, reference: &str) -> Result<Image> {
    let reference = Reference::parse(reference)?.to_string();

    self
      .list()?
      .into_iter()
      .find(|image| image.reference == reference)
      .ok_or_else(|| Error::Invalid(format!("the store has no image {reference}")))
  }

  pub fn list(&self) -> Result<Vec<Image>> {
    Ok(
      self
        .read_index()?
        .manifests
        .into_iter()
        .filter_map(|entry| Some(self.image(name(&entry)?.to_string(), entry)))
        .collect(),
    )
  }

  /// Names `existing`'s image `new` too.
  pub fn tag(&self, existing: &str, new: &str) -> Result<Image> {
    let image = self.get(existing)?;

    self.create(new, image.descriptor)
  }

  /// Forgets `reference`, and deletes the blobs no image needs any more.
  pub fn delete(&self, reference: &str) -> Result<()> {
    let reference = Reference::parse(reference)?.to_string();

    self.update(|index| {
      let before = index.manifests.len();
      index
        .manifests
        .retain(|entry| name(entry) != Some(&reference));
      if index.manifests.len() == before {
        return Err(Error::Invalid(format!("the store has no image {reference}")));
      }

      let needed = self.reachable(index)?;
      for digest in self.content.digests()? {
        if !needed.contains(&digest) {
          self.content.delete(&digest)?;
        }
      }
      Ok(())
    })
  }

  /// Loads the images in the OCI archive at `path`: a tar of an OCI image
  /// layout, plain or compressed with xz, as FreeBSD's container images on
  /// download.freebsd.org are. Each is named by its
  /// `org.opencontainers.image.ref.name`, normalized as references are:
  /// `freebsd-static:15.1-RELEASE-aarch64` is
  /// `docker.io/library/freebsd-static:15.1-RELEASE-aarch64`. Blobs the store
  /// holds already are skipped.
  pub fn load(&self, path: &Path) -> Result<Vec<Image>> {
    let reading = || format!("reading {}", path.display());
    let mut file = BufReader::new(File::open(path).map_err(Error::io(reading()))?);
    let compressed = file
      .fill_buf()
      .map_err(Error::io(reading()))?
      .starts_with(XZ);
    let reader: Box<dyn Read> = if compressed {
      Box::new(xz2::bufread::XzDecoder::new(file))
    } else {
      Box::new(file)
    };
    let mut archive = tar::Archive::new(reader);
    let mut index = None;

    for entry in archive.entries().map_err(Error::io(reading()))? {
      let mut entry = entry.map_err(Error::io(reading()))?;
      let name = entry
        .path()
        .map_err(Error::io(reading()))?
        .to_string_lossy()
        .into_owned();
      let name = name.trim_start_matches("./");
      if name == "index.json" {
        let mut bytes = Vec::new();
        entry
          .read_to_end(&mut bytes)
          .map_err(Error::io(reading()))?;
        index = Some(parse::<Index>(&bytes, &format!("{}'s index.json", path.display()))?);
      } else if let Some(hex) = name.strip_prefix("blobs/sha256/")
        && entry.header().entry_type().is_file()
      {
        let digest = format!("sha256:{hex}");
        if !self.content.has(&digest) {
          self.content.ingest_from(&mut entry, &digest)?;
        }
      }
    }

    let index =
      index.ok_or_else(|| Error::Invalid(format!("{} has no index.json: it isn't an OCI archive", path.display())))?;
    index
      .manifests
      .into_iter()
      .map(|descriptor| {
        let name = descriptor
          .annotations
          .get(REF_NAME)
          .cloned()
          .ok_or_else(|| Error::Invalid(format!("{} has an image with no {REF_NAME}", path.display())))?;
        let alone = Index {
          manifests: vec![descriptor.clone()],
          ..Index::default()
        };
        if let Some(missing) = self.missing(&alone)? {
          return Err(Error::Invalid(format!(
            "{} lacks blob {missing} of {name}",
            path.display()
          )));
        }
        self.create(&name, descriptor)
      })
      .collect()
  }

  /// Saves the images named `references` in an OCI archive at `path`, with
  /// every blob they need, for `load`. Its bytes depend only on what it
  /// holds.
  pub fn save(&self, references: &[&str], path: &Path) -> Result<()> {
    let images = references
      .iter()
      .map(|reference| self.get(reference))
      .collect::<Result<Vec<_>>>()?;
    let index = Index {
      manifests: images.into_iter().map(|image| image.descriptor).collect(),
      ..Index::default()
    };
    if let Some(missing) = self.missing(&index)? {
      return Err(Error::Invalid(format!(
        "the store lacks blob {missing} of {references:?}"
      )));
    }
    let blobs = self
      .reachable(&index)?
      .into_iter()
      .map(|digest| {
        Ok((
          format!("blobs/sha256/{}", &digest["sha256:".len()..]),
          self.content.path(&digest)?,
        ))
      })
      .collect::<Result<Vec<_>>>()?;
    let index = serde_json::to_vec(&index).map_err(|error| Error::Invalid(format!("an index to save: {error}")))?;

    let writing = || format!("writing {}", path.display());
    let file = File::create(path).map_err(Error::io(writing()))?;
    let written = (|| {
      let mut archive = tar::Builder::new(BufWriter::new(file));
      append(&mut archive, "oci-layout", LAYOUT.len() as u64, LAYOUT.as_bytes())?;
      append(&mut archive, "index.json", index.len() as u64, index.as_slice())?;
      for (name, blob) in &blobs {
        let blob = File::open(blob)?;
        let size = blob.metadata()?.len();
        append(&mut archive, name, size, blob)?;
      }
      archive.into_inner()?.flush()
    })();
    if written.is_err() {
      let _ = std::fs::remove_file(path);
    }
    written.map_err(Error::io(writing()))
  }

  /// A blob the index's images need that the store lacks, if any. A
  /// manifest for another platform may be missing, as a pull leaves it.
  fn missing(&self, index: &Index) -> Result<Option<String>> {
    Ok(
      self
        .reachable(index)?
        .into_iter()
        .find(|digest| !self.content.has(digest)),
    )
  }

  /// Every blob the index's images need that the store holds.
  fn reachable(&self, index: &Index) -> Result<BTreeSet<String>> {
    let mut needed = BTreeSet::new();
    let mut pending: Vec<Descriptor> = index.manifests.clone();

    while let Some(descriptor) = pending.pop() {
      if !self.content.has(&descriptor.digest) || !needed.insert(descriptor.digest.clone()) {
        continue;
      }
      let bytes = self.content.read(&descriptor.digest)?;
      if descriptor.is_index() {
        let index: Index = parse(&bytes, &format!("index {}", descriptor.digest))?;
        pending.extend(index.manifests);
      } else {
        let manifest: Manifest = parse(&bytes, &format!("manifest {}", descriptor.digest))?;
        needed.insert(manifest.config.digest);
        needed.extend(manifest.layers.into_iter().map(|layer| layer.digest));
      }
    }
    Ok(needed)
  }

  fn image(&self, reference: String, descriptor: Descriptor) -> Image {
    Image {
      reference,
      descriptor,
      content: self.content.clone(),
    }
  }

  fn read_index(&self) -> Result<Index> {
    let path = self.root.join("index.json");

    match std::fs::read(&path) {
      Ok(bytes) => parse(&bytes, &path.display().to_string()),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Index::default()),
      Err(error) => Err(Error::io(format!("reading {}", path.display()))(error)),
    }
  }

  /// Changes `index.json` under a lock, so stores in other processes don't
  /// lose each other's changes.
  fn update(&self, change: impl FnOnce(&mut Index) -> Result<()>) -> Result<()> {
    let lock_path = self.root.join("index.json.lock");
    let locking = || format!("locking {}", lock_path.display());
    let lock = File::create(&lock_path).map_err(Error::io(locking()))?;
    lock.lock().map_err(Error::io(locking()))?;

    let mut index = self.read_index()?;
    change(&mut index)?;
    let bytes =
      serde_json::to_vec_pretty(&index).map_err(|error| Error::Invalid(format!("the store's index: {error}")))?;
    let partial = self.root.join("index.json.partial");
    std::fs::write(&partial, bytes).map_err(Error::io(format!("writing {}", partial.display())))?;
    std::fs::rename(&partial, self.root.join("index.json")).map_err(Error::io("replacing index.json"))
  }
}

impl Image {
  /// The manifest for `platform`: its descriptor, and the manifest.
  pub fn manifest(&self, platform: &Platform) -> Result<(Descriptor, Manifest)> {
    let descriptor = if self.descriptor.is_index() {
      let index: Index = parse(
        &self.content.read(&self.descriptor.digest)?,
        &format!("{}'s index", self.reference),
      )?;
      choose(&index, platform).ok_or_else(|| {
        Error::Invalid(format!(
          "{} has no image for {platform}, only {}",
          self.reference,
          platforms(&index)
        ))
      })?
    } else {
      self.descriptor.clone()
    };
    let manifest = parse(
      &self.content.read(&descriptor.digest)?,
      &format!("{}'s manifest", self.reference),
    )?;

    Ok((descriptor, manifest))
  }

  /// The config for `platform`.
  pub fn config(&self, platform: &Platform) -> Result<ImageConfig> {
    let (_, manifest) = self.manifest(platform)?;

    parse(
      &self.content.read(&manifest.config.digest)?,
      &format!("{}'s config", self.reference),
    )
  }

  pub(crate) fn content(&self) -> &ContentStore {
    &self.content
  }
}

/// The index's manifest for `platform`, if it has one.
fn choose(index: &Index, platform: &Platform) -> Option<Descriptor> {
  index
    .manifests
    .iter()
    .find(|entry| {
      entry
        .platform
        .as_ref()
        .is_some_and(|other| platform.runs(other))
    })
    .cloned()
}

fn platforms(index: &Index) -> String {
  let names: Vec<String> = index
    .manifests
    .iter()
    .filter_map(|entry| entry.platform.as_ref().map(Platform::to_string))
    .collect();

  if names.is_empty() {
    "none".to_string()
  } else {
    names.join(", ")
  }
}

fn name(entry: &Descriptor) -> Option<&String> {
  entry.annotations.get(REF_NAME)
}

/// Adds the file `name` to `archive`, owned by root and dated 1970.
fn append(archive: &mut tar::Builder<impl Write>, name: &str, size: u64, data: impl Read) -> io::Result<()> {
  let mut header = tar::Header::new_ustar();
  header.set_entry_type(tar::EntryType::Regular);
  header.set_size(size);
  header.set_mode(0o644);
  header.set_uid(0);
  header.set_gid(0);
  header.set_mtime(0);
  archive.append_data(&mut header, name, data)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oci::{RootFs, RunConfig, media_type, sha256_digest};
  use std::collections::HashMap;
  use std::io::{BufRead, BufReader, Write};
  use std::net::TcpListener;

  const TOKEN: &str = "secret";

  fn descriptor(media_type: &str, bytes: &[u8], platform: Option<Platform>) -> Descriptor {
    Descriptor {
      media_type: media_type.into(),
      digest: sha256_digest(bytes),
      size: bytes.len() as u64,
      platform,
      annotations: Default::default(),
    }
  }

  fn json(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
  }

  /// An arm64 FreeBSD image of one layer: the layer, config and manifest.
  fn documents() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let layer = b"layer".to_vec();
    let config = json(&ImageConfig {
      architecture: "arm64".into(),
      os: "freebsd".into(),
      config: Some(RunConfig {
        cmd: Some(vec!["/bin/sh".into()]),
        ..RunConfig::default()
      }),
      rootfs: RootFs {
        kind: "layers".into(),
        diff_ids: vec![sha256_digest(&layer)],
      },
      ..ImageConfig::default()
    });
    let manifest = json(&Manifest {
      schema_version: 2,
      media_type: Some(media_type::MANIFEST.into()),
      config: descriptor(media_type::CONFIG, &config, None),
      layers: vec![descriptor(media_type::LAYER_GZIP, &layer, None)],
    });
    (layer, config, manifest)
  }

  /// A tar of `entries`, by name.
  fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, bytes) in entries {
      let mut header = tar::Header::new_ustar();
      header.set_size(bytes.len() as u64);
      header.set_mode(0o644);
      builder.append_data(&mut header, name, *bytes).unwrap();
    }
    builder.into_inner().unwrap()
  }

  /// A registry on loopback, serving `test/image:1` behind a bearer token as
  /// ghcr.io does: an index whose arm64 FreeBSD image it holds, and whose
  /// amd64 one it doesn't. Blobs redirect to storage, as registries' do.
  fn registry() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

    let (layer, config, manifest) = documents();
    let amd64 = Platform {
      architecture: "amd64".into(),
      ..Platform::default()
    };
    let index = json(&Index {
      manifests: vec![
        descriptor(media_type::MANIFEST, b"absent", Some(amd64)),
        descriptor(media_type::MANIFEST, &manifest, Some(Platform::default())),
      ],
      ..Index::default()
    });

    let mut documents: HashMap<String, (&str, Vec<u8>)> = HashMap::new();
    documents.insert("1".into(), (media_type::INDEX, index.clone()));
    documents.insert(sha256_digest(&index), (media_type::INDEX, index));
    documents.insert(sha256_digest(&manifest), (media_type::MANIFEST, manifest));
    let mut blobs: HashMap<String, Vec<u8>> = HashMap::new();
    blobs.insert(sha256_digest(&config), config);
    blobs.insert(sha256_digest(&layer), layer);

    let realm = format!("http://{address}/token");
    std::thread::spawn(move || {
      for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        let path = request
          .split_whitespace()
          .nth(1)
          .unwrap_or_default()
          .to_string();
        let mut authorized = false;
        loop {
          let mut line = String::new();
          reader.read_line(&mut line).unwrap();
          if line.trim().is_empty() {
            break;
          }
          authorized |= line.to_ascii_lowercase() == format!("authorization: bearer {TOKEN}\r\n");
        }

        let challenge = format!("WWW-Authenticate: Bearer realm=\"{realm}\",service=\"test\"\r\n");
        let (status, headers, body) =
          if path.starts_with("/token?") && path.contains("scope=repository%3Atest%2Fimage%3Apull") {
            (
              "200 OK",
              String::new(),
              format!(r#"{{"token":"{TOKEN}"}}"#).into_bytes(),
            )
          } else if let Some(digest) = path.strip_prefix("/storage/") {
            match blobs.get(digest) {
              Some(blob) => ("200 OK", String::new(), blob.clone()),
              None => ("404 Not Found", String::new(), Vec::new()),
            }
          } else if !authorized {
            ("401 Unauthorized", challenge, Vec::new())
          } else if let Some(target) = path.strip_prefix("/v2/test/image/manifests/") {
            match documents.get(target) {
              Some((kind, bytes)) => ("200 OK", format!("Content-Type: {kind}\r\n"), bytes.clone()),
              None => ("404 Not Found", String::new(), Vec::new()),
            }
          } else if let Some(digest) = path.strip_prefix("/v2/test/image/blobs/") {
            (
              "307 Temporary Redirect",
              format!("Location: /storage/{digest}\r\n"),
              Vec::new(),
            )
          } else {
            ("404 Not Found", String::new(), Vec::new())
          };

        let _ = write!(
          stream,
          "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
          body.len()
        );
        let _ = stream.write_all(&body);
      }
    });
    address
  }

  #[test]
  fn pulls_the_image_for_its_platform_through_a_token() {
    let root = tempfile::tempdir().unwrap();
    let store = ImageStore::new(root.path()).unwrap();
    let reference = format!("{}/test/image:1", registry());

    let image = store.pull(&reference, &Platform::default(), None).unwrap();

    assert_eq!(image.reference, reference);
    assert!(image.descriptor.is_index());
    let config = image.config(&Platform::default()).unwrap();
    assert_eq!(config.config.unwrap().cmd, Some(vec!["/bin/sh".to_string()]));
    let (_, manifest) = image.manifest(&Platform::default()).unwrap();
    assert!(store.content().has(&manifest.layers[0].digest));
    assert_eq!(store.get(&reference).unwrap().descriptor, image.descriptor);
    assert!(root.path().join("oci-layout").exists());
  }

  #[test]
  fn refuses_an_image_with_none_for_its_platform() {
    let root = tempfile::tempdir().unwrap();
    let store = ImageStore::new(root.path()).unwrap();
    let riscv = Platform {
      architecture: "riscv64".into(),
      ..Platform::default()
    };

    let error = store
      .pull(&format!("{}/test/image:1", registry()), &riscv, None)
      .unwrap_err();

    assert!(error.to_string().contains("freebsd/amd64, freebsd/arm64"), "{error}");
    assert!(store.list().unwrap().is_empty());
  }

  #[test]
  fn deletes_the_blobs_no_image_needs() {
    let root = tempfile::tempdir().unwrap();
    let store = ImageStore::new(root.path()).unwrap();
    let reference = format!("{}/test/image:1", registry());
    store.pull(&reference, &Platform::default(), None).unwrap();
    let blobs = store.content().digests().unwrap().len();

    store.tag(&reference, "ghcr.io/test/other:2").unwrap();
    store.delete(&reference).unwrap();
    assert_eq!(store.content().digests().unwrap().len(), blobs);

    store.delete("ghcr.io/test/other:2").unwrap();
    assert!(store.list().unwrap().is_empty());
    assert!(store.content().digests().unwrap().is_empty());
    assert!(store.delete("ghcr.io/test/other:2").is_err());
  }

  #[test]
  fn saves_images_in_an_archive_that_loads_them_again() {
    let (pulled, loaded, work) = (
      tempfile::tempdir().unwrap(),
      tempfile::tempdir().unwrap(),
      tempfile::tempdir().unwrap(),
    );
    let store = ImageStore::new(pulled.path()).unwrap();
    let reference = format!("{}/test/image:1", registry());
    store.pull(&reference, &Platform::default(), None).unwrap();
    store.tag(&reference, "ghcr.io/test/other:2").unwrap();
    let archive = work.path().join("images.tar");

    store
      .save(&[&reference, "ghcr.io/test/other:2"], &archive)
      .unwrap();
    let again = work.path().join("again.tar");
    store
      .save(&[&reference, "ghcr.io/test/other:2"], &again)
      .unwrap();
    assert_eq!(std::fs::read(&archive).unwrap(), std::fs::read(&again).unwrap());
    let other = ImageStore::new(loaded.path()).unwrap();
    let images = other.load(&archive).unwrap();

    let names: Vec<&str> = images
      .iter()
      .map(|image| image.reference.as_str())
      .collect();
    assert_eq!(names, [reference.as_str(), "ghcr.io/test/other:2"]);
    assert_eq!(
      other.get(&reference).unwrap().descriptor,
      store.get(&reference).unwrap().descriptor
    );
    let config = other
      .get(&reference)
      .unwrap()
      .config(&Platform::default())
      .unwrap();
    assert_eq!(config.config.unwrap().cmd, Some(vec!["/bin/sh".to_string()]));
    let mut digests = store.content().digests().unwrap();
    let mut loaded_digests = other.content().digests().unwrap();
    digests.sort_unstable();
    loaded_digests.sort_unstable();
    assert_eq!(loaded_digests, digests);
  }

  #[test]
  fn loads_an_xz_archive_naming_its_image_as_freebsd_does() {
    let root = tempfile::tempdir().unwrap();
    let store = ImageStore::new(root.path()).unwrap();
    let (layer, config, manifest) = documents();
    let mut entry = descriptor(media_type::MANIFEST, &manifest, None);
    entry
      .annotations
      .insert(REF_NAME.to_string(), "freebsd-static:15.1-RELEASE-aarch64".to_string());
    let index = json(&Index {
      manifests: vec![entry],
      ..Index::default()
    });
    let blob = |bytes: &[u8]| format!("blobs/sha256/{}", &sha256_digest(bytes)["sha256:".len()..]);
    let plain = tar(&[
      ("index.json", &index),
      ("oci-layout", LAYOUT.as_bytes()),
      (&blob(&manifest), &manifest),
      (&blob(&config), &config),
      (&blob(&layer), &layer),
    ]);
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
    encoder.write_all(&plain).unwrap();
    let archive = root.path().join("image.txz");
    std::fs::write(&archive, encoder.finish().unwrap()).unwrap();

    let images = store.load(&archive).unwrap();

    assert_eq!(
      images[0].reference,
      "docker.io/library/freebsd-static:15.1-RELEASE-aarch64"
    );
    assert!(store.content().has(&sha256_digest(&layer)));
  }

  #[test]
  fn refuses_an_archive_with_a_blob_missing_or_not_its_digest() {
    let root = tempfile::tempdir().unwrap();
    let store = ImageStore::new(root.path()).unwrap();
    let (layer, config, manifest) = documents();
    let mut entry = descriptor(media_type::MANIFEST, &manifest, None);
    entry
      .annotations
      .insert(REF_NAME.to_string(), "ghcr.io/test/image:1".to_string());
    let index = json(&Index {
      manifests: vec![entry],
      ..Index::default()
    });
    let blob = |bytes: &[u8]| format!("blobs/sha256/{}", &sha256_digest(bytes)["sha256:".len()..]);
    let write = |name: &str, entries: &[(&str, &[u8])]| {
      let path = root.path().join(name);
      std::fs::write(&path, tar(entries)).unwrap();
      path
    };

    let empty = write("empty.tar", &[("index.json", &index)]);
    let error = store.load(&empty).unwrap_err();
    assert!(error.to_string().contains(&sha256_digest(&manifest)), "{error}");

    let lacking = write(
      "lacking.tar",
      &[
        ("index.json", &index),
        (&blob(&manifest), &manifest),
        (&blob(&config), &config),
      ],
    );
    let error = store.load(&lacking).unwrap_err();
    assert!(error.to_string().contains(&sha256_digest(&layer)), "{error}");

    // The store has the manifest and config now, but not the layer.
    let forged = write(
      "forged.tar",
      &[("index.json", &index), (&blob(&layer), b"something else")],
    );
    assert!(matches!(store.load(&forged).unwrap_err(), Error::Checksum { .. }));
    assert!(store.list().unwrap().is_empty());
  }
}
