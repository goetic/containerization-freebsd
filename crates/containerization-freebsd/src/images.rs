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
use std::path::{Path, PathBuf};

const LAYOUT: &str = r#"{"imageLayoutVersion":"1.0.0"}"#;

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

  /// A registry on loopback, serving `test/image:1` behind a bearer token as
  /// ghcr.io does: an index whose arm64 FreeBSD image it holds, and whose
  /// amd64 one it doesn't. Blobs redirect to storage, as registries' do.
  fn registry() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

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
}
