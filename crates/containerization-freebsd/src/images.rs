//! The host's image store, kept as an OCI image layout: `index.json` names
//! each image by its reference, and `blobs/sha256` holds the content. It
//! mirrors Containerization's image store, and the caller chooses where it
//! lives.

use crate::error::{Error, Result};
use crate::oci::{
  ContentStore, Credentials, Descriptor, ImageConfig, Index, Manifest, Platform, REF_NAME, Reference, RegistryClient,
  parse, sha256_hex,
};
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

const LAYOUT: &str = r#"{"imageLayoutVersion":"1.0.0"}"#;

pub struct ImageStore {
  root: PathBuf,
  content: ContentStore,
}

/// An index or manifest in the store, named by the reference it was pulled
/// or tagged as.
#[derive(Clone, Debug)]
pub struct Image {
  pub reference: String,
  pub descriptor: Descriptor,
  content: ContentStore,
}

impl ImageStore {
  /// Opens the store at `root`, creating it if needed.
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

  /// Pulls `reference`'s image for `platform`: the index if there is one,
  /// and that platform's manifest, config and layers. Blobs already in the
  /// store are not downloaded again.
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

  /// Pushes the image named `reference` to the registry in that name, as
  /// Containerization's `push(reference:platform:)` does. Blobs the registry
  /// lacks go first, then the manifests, and an index's manifests before the
  /// index itself. To push under another name, tag the image first.
  ///
  /// With `platform`, an index is pushed as a new index of only that
  /// platform's manifests. Without it, the whole index is pushed, which needs
  /// every platform's manifest, and a pull fetches only one.
  pub fn push(&self, reference: &str, platform: Option<&Platform>, credentials: Option<Credentials>) -> Result<()> {
    let image = self.get(reference)?;
    let descriptor = self.for_platform(&image, platform)?;
    let reference = Reference::parse(reference)?;
    let client = RegistryClient::new(credentials);

    self.push_children(&client, &reference, &descriptor)?;
    client.push_manifest(&reference, reference.target(), &descriptor, &self.content)
  }

  /// The platforms `reference`'s image supports, as Containerization's
  /// `platforms(reference:)` reports them. Uses the store's image of that
  /// name if there is one, otherwise asks the registry without pulling
  /// layers.
  pub fn platforms(&self, reference: &str, credentials: Option<Credentials>) -> Result<Vec<Platform>> {
    let reference = Reference::parse(reference)?;
    let name = reference.to_string();
    if let Some(image) = self
      .list()?
      .into_iter()
      .find(|image| image.reference == name)
    {
      return self.platforms_of(&image.descriptor, None);
    }

    let client = RegistryClient::new(credentials);
    let top = client.fetch_manifest(&reference, reference.target(), &self.content)?;
    self.platforms_of(&top, Some((&client, &reference)))
  }

  /// The platforms of the index or manifest `descriptor`. For an index, these
  /// are its entries' platforms, excluding the `unknown/unknown` that marks
  /// attestations. For a manifest, it is its config's platform, with the
  /// config fetched from `remote` if the store lacks it.
  fn platforms_of(
    &self,
    descriptor: &Descriptor,
    remote: Option<(&RegistryClient, &Reference)>,
  ) -> Result<Vec<Platform>> {
    let bytes = self.content.read(&descriptor.digest)?;
    if descriptor.is_index() {
      let index: Index = parse(&bytes, &format!("index {}", descriptor.digest))?;
      return Ok(
        index
          .manifests
          .into_iter()
          .filter_map(|manifest| manifest.platform)
          .filter(|platform| platform.os != "unknown" && platform.architecture != "unknown")
          .collect(),
      );
    }

    let manifest: Manifest = parse(&bytes, &format!("manifest {}", descriptor.digest))?;
    if !self.content.has(&manifest.config.digest)
      && let Some((client, reference)) = remote
    {
      client.fetch_blob(reference, &manifest.config, &self.content)?;
    }
    let config: ImageConfig = parse(
      &self.content.read(&manifest.config.digest)?,
      &format!("config {}", manifest.config.digest),
    )?;
    Ok(vec![config.platform()])
  }

  /// The descriptor to push or save for `image` and `platform`. For an index,
  /// this is a new index in the store holding only `platform`'s manifests,
  /// unless they are all of them. Without `platform`, or for a manifest, it
  /// is the image's own descriptor.
  fn for_platform(&self, image: &Image, platform: Option<&Platform>) -> Result<Descriptor> {
    let Some(platform) = platform else {
      return Ok(image.descriptor.clone());
    };
    if !image.descriptor.is_index() {
      let config = image.config(platform)?;
      return if platform.runs(&config.platform()) {
        Ok(image.descriptor.clone())
      } else {
        Err(Error::Invalid(format!(
          "{} is an image for {}, not {platform}",
          image.reference,
          config.platform()
        )))
      };
    }

    let mut index: Index = parse(
      &self.content.read(&image.descriptor.digest)?,
      &format!("{}'s index", image.reference),
    )?;
    let all = index.manifests.len();
    index.manifests.retain(|manifest| {
      manifest
        .platform
        .as_ref()
        .is_some_and(|other| platform.runs(other))
    });
    if index.manifests.is_empty() {
      return Err(Error::Invalid(format!(
        "{} has no image for {platform}",
        image.reference
      )));
    }
    if index.manifests.len() == all {
      return Ok(image.descriptor.clone());
    }

    let bytes =
      serde_json::to_vec(&index).map_err(|error| Error::Invalid(format!("an index for {platform}: {error}")))?;
    Ok(Descriptor {
      media_type: image.descriptor.media_type.clone(),
      digest: self.content.ingest(&bytes)?,
      size: bytes.len() as u64,
      platform: None,
      annotations: image.descriptor.annotations.clone(),
    })
  }

  /// Pushes everything `descriptor` refers to: a manifest's config and
  /// layers, or an index's manifests (by digest) and their contents.
  fn push_children(&self, client: &RegistryClient, reference: &Reference, descriptor: &Descriptor) -> Result<()> {
    let bytes = self.content.read(&descriptor.digest)?;
    if !descriptor.is_index() {
      let manifest: Manifest = parse(&bytes, &format!("{reference}'s manifest"))?;
      return std::iter::once(&manifest.config)
        .chain(&manifest.layers)
        .try_for_each(|blob| client.push_blob(reference, blob, &self.content));
    }

    let index: Index = parse(&bytes, &format!("{reference}'s index"))?;
    for child in &index.manifests {
      if !self.content.has(&child.digest) {
        let platform = child
          .platform
          .as_ref()
          .map_or_else(|| child.digest.clone(), Platform::to_string);
        return Err(Error::Invalid(format!(
          "the store lacks {reference}'s manifest for {platform}: push the platforms it has, one at a time"
        )));
      }
      self.push_children(client, reference, child)?;
      client.push_manifest(reference, &child.digest, child, &self.content)?;
    }
    Ok(())
  }

  /// Names `descriptor`, an index or manifest in the store, as `reference`,
  /// replacing any existing image of that name.
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

  /// Adds the name `new` to the image named `existing`.
  pub fn tag(&self, existing: &str, new: &str) -> Result<Image> {
    let image = self.get(existing)?;

    self.create(new, image.descriptor)
  }

  /// Removes the name `reference`, then deletes every blob that no remaining
  /// image needs.
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

  /// Loads the images in the OCI image layout at `directory`, as
  /// Containerization's `load(from:)` does. An archived layout, such as
  /// FreeBSD's container images on download.freebsd.org, must be unpacked
  /// first. Each image is named by its `org.opencontainers.image.ref.name`
  /// annotation, normalized like any reference, so
  /// `freebsd-static:15.1-RELEASE-aarch64` becomes
  /// `docker.io/library/freebsd-static:15.1-RELEASE-aarch64`. Blobs already
  /// in the store are not copied.
  pub fn load(&self, directory: &Path) -> Result<Vec<Image>> {
    let path = directory.join("index.json");
    let bytes = std::fs::read(&path).map_err(Error::io(format!("reading {}", path.display())))?;
    let index: Index = parse(&bytes, &path.display().to_string())?;

    index
      .manifests
      .into_iter()
      .map(|descriptor| {
        let name = descriptor
          .annotations
          .get(REF_NAME)
          .cloned()
          .ok_or_else(|| Error::Invalid(format!("{} has an image with no {REF_NAME}", path.display())))?;
        self.import(directory, &descriptor)?;
        let alone = Index {
          manifests: vec![descriptor.clone()],
          ..Index::default()
        };
        if let Some(missing) = self.missing(&alone)? {
          return Err(Error::Invalid(format!(
            "{} lacks blob {missing} of {name}",
            directory.display()
          )));
        }
        self.create(&name, descriptor)
      })
      .collect()
  }

  /// Saves the images named `references`, with every blob they need, as an
  /// OCI image layout at `out`, as Containerization's
  /// `save(references:out:platform:)` does. With `platform`, an index is
  /// saved as a new index of only that platform's manifests. `out` is
  /// created if needed, and any `index.json` there is replaced.
  pub fn save(&self, references: &[&str], out: &Path, platform: Option<&Platform>) -> Result<()> {
    let manifests = references
      .iter()
      .map(|reference| self.for_platform(&self.get(reference)?, platform))
      .collect::<Result<Vec<_>>>()?;
    let index = Index {
      manifests,
      ..Index::default()
    };
    if let Some(missing) = self.missing(&index)? {
      return Err(Error::Invalid(format!(
        "the store lacks blob {missing} of {references:?}"
      )));
    }

    let blobs = out.join("blobs/sha256");
    std::fs::create_dir_all(&blobs).map_err(Error::io(format!("making {}", blobs.display())))?;
    for digest in self.reachable(&index)? {
      let saved = layout_blob(out, &digest)?;
      if !saved.exists() {
        std::fs::copy(self.content.path(&digest)?, &saved)
          .map_err(Error::io(format!("writing {}", saved.display())))?;
      }
    }
    let index = serde_json::to_vec(&index).map_err(|error| Error::Invalid(format!("an index to save: {error}")))?;
    for (name, bytes) in [("oci-layout", LAYOUT.as_bytes()), ("index.json", &index)] {
      let partial = out.join(format!("{name}.partial"));
      std::fs::write(&partial, bytes)
        .and_then(|()| std::fs::rename(&partial, out.join(name)))
        .map_err(Error::io(format!("writing {}", out.join(name).display())))?;
    }
    Ok(())
  }

  /// Copies `descriptor`'s blob, and the blobs it refers to, from the layout
  /// at `directory` into the store, skipping blobs the store already has. An
  /// index's manifests may be absent, as after a pull; this skips them, and
  /// later checks report any other absent blob.
  fn import(&self, directory: &Path, descriptor: &Descriptor) -> Result<()> {
    if !self.copy_in(directory, &descriptor.digest)? {
      return Ok(());
    }
    let bytes = self.content.read(&descriptor.digest)?;

    if descriptor.is_index() {
      let index: Index = parse(&bytes, &format!("index {}", descriptor.digest))?;
      index
        .manifests
        .iter()
        .try_for_each(|child| self.import(directory, child))
    } else {
      let manifest: Manifest = parse(&bytes, &format!("manifest {}", descriptor.digest))?;
      for blob in std::iter::once(&manifest.config).chain(&manifest.layers) {
        self.copy_in(directory, &blob.digest)?;
      }
      Ok(())
    }
  }

  /// Copies the blob `digest` from the layout at `directory` unless the
  /// store already has it. Returns whether the store has it afterwards.
  fn copy_in(&self, directory: &Path, digest: &str) -> Result<bool> {
    if self.content.has(digest) {
      return Ok(true);
    }
    let path = layout_blob(directory, digest)?;

    match File::open(&path) {
      Ok(mut file) => self.content.ingest_from(&mut file, digest).map(|()| true),
      Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
      Err(error) => Err(Error::io(format!("reading {}", path.display()))(error)),
    }
  }

  /// A blob that the index's images need and the store lacks, if any. A
  /// missing manifest is not reported, since a pull fetches only one
  /// platform's manifest.
  fn missing(&self, index: &Index) -> Result<Option<String>> {
    Ok(
      self
        .reachable(index)?
        .into_iter()
        .find(|digest| !self.content.has(digest)),
    )
  }

  /// Every blob the index's images need. Indexes and manifests the store
  /// lacks are skipped, but configs and layers are included whether or not
  /// the store has them.
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

  /// Applies `change` to `index.json` under a file lock, so that stores in
  /// other processes do not overwrite each other's changes.
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
  /// The manifest for `platform`, with its descriptor.
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

/// The first manifest in `index` that runs on `platform`, if any.
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

/// The path of the blob `digest` in the OCI image layout at `root`.
fn layout_blob(root: &Path, digest: &str) -> Result<PathBuf> {
  let hex = sha256_hex(digest).ok_or_else(|| Error::Invalid(format!("{digest:?} is not a sha256 digest")))?;

  Ok(root.join("blobs/sha256").join(hex))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oci::{RootFs, RunConfig, media_type, sha256_digest};
  use std::collections::HashMap;
  use std::io::{BufRead, BufReader, Read, Write};
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

  /// The layer, config and manifest of a one-layer arm64 FreeBSD image.
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

  /// A loopback registry that serves `test/image:1` behind a bearer token, as
  /// ghcr.io does. The image is an index listing arm64 and amd64 FreeBSD
  /// manifests, but the registry serves only the arm64 one. Blob requests
  /// redirect to a storage path, as real registries' often do.
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

  /// A loopback registry that accepts pushes and serves pulls for any
  /// repository behind a bearer token. POST and PUT need a push token; GET
  /// and HEAD accept a pull or push token. Blob uploads go to a separate
  /// upload location.
  fn writable_registry() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let realm = format!("http://{address}/token");
    let host = address.clone();

    std::thread::spawn(move || {
      let mut manifests: HashMap<String, (String, Vec<u8>)> = HashMap::new();
      let mut blobs: HashMap<String, Vec<u8>> = HashMap::new();
      let mut uploads = 0;

      for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut parts = line.split_whitespace();
        let (method, path) = (
          parts.next().unwrap_or_default().to_string(),
          parts.next().unwrap_or_default().to_string(),
        );
        let mut headers = HashMap::new();
        loop {
          let mut line = String::new();
          reader.read_line(&mut line).unwrap();
          match line.trim_end().split_once(':') {
            Some((name, value)) => headers.insert(name.to_ascii_lowercase(), value.trim().to_string()),
            None => break,
          };
        }
        let length = headers
          .get("content-length")
          .and_then(|length| length.parse().ok())
          .unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();

        let token = headers
          .get("authorization")
          .and_then(|value| value.strip_prefix("Bearer "));
        let allowed = match method.as_str() {
          "POST" | "PUT" => token == Some("push"),
          _ => matches!(token, Some("push" | "pull")),
        };
        let url = url::Url::parse(&format!("http://{host}{path}")).unwrap();
        let query = |name: &str| {
          url
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
        };
        let found = |found: Option<(String, Vec<u8>)>| match found {
          Some((kind, bytes)) => ("200 OK", format!("Content-Type: {kind}\r\n"), bytes),
          None => ("404 Not Found", String::new(), Vec::new()),
        };

        let (status, extra, response) = if url.path() == "/token" {
          let granted = if query("scope").is_some_and(|scope| scope.contains("push")) {
            "push"
          } else {
            "pull"
          };
          (
            "200 OK",
            String::new(),
            format!(r#"{{"token":"{granted}"}}"#).into_bytes(),
          )
        } else if !allowed {
          (
            "401 Unauthorized",
            format!("WWW-Authenticate: Bearer realm=\"{realm}\",service=\"test\"\r\n"),
            Vec::new(),
          )
        } else if url.path().starts_with("/upload/") {
          let digest = query("digest").unwrap_or_default();
          if sha256_digest(&body) == digest {
            blobs.insert(digest, body);
            ("201 Created", String::new(), Vec::new())
          } else {
            ("400 Bad Request", String::new(), Vec::new())
          }
        } else if let Some((repository, target)) = url.path().rsplit_once("/manifests/") {
          if method == "PUT" {
            let kind = headers.get("content-type").cloned().unwrap_or_default();
            manifests.insert(format!("{repository}/{target}"), (kind.clone(), body.clone()));
            manifests.insert(format!("{repository}/{}", sha256_digest(&body)), (kind, body));
            ("201 Created", String::new(), Vec::new())
          } else {
            found(manifests.get(&format!("{repository}/{target}")).cloned())
          }
        } else if url.path().ends_with("/blobs/uploads/") {
          uploads += 1;
          ("202 Accepted", format!("Location: /upload/{uploads}\r\n"), Vec::new())
        } else if let Some((_, digest)) = url.path().rsplit_once("/blobs/") {
          found(
            blobs
              .get(digest)
              .map(|blob| ("application/octet-stream".to_string(), blob.clone())),
          )
        } else {
          ("404 Not Found", String::new(), Vec::new())
        };

        let _ = write!(
          stream,
          "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
          response.len()
        );
        if method != "HEAD" {
          let _ = stream.write_all(&response);
        }
      }
    });
    address
  }

  #[test]
  fn pushes_images_that_pull_back() {
    let (pushed, pulled) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let store = ImageStore::new(pushed.path()).unwrap();
    let image = store
      .pull(&format!("{}/test/image:1", registry()), &Platform::default(), None)
      .unwrap();
    let writable = writable_registry();

    // The pull fetched only the index's arm64 manifest, so pushing the whole
    // index fails. Pushing for arm64 pushes a new index of that manifest.
    let whole = format!("{writable}/test/index:1");
    store.tag(&image.reference, &whole).unwrap();
    let error = store.push(&whole, None, None).unwrap_err();
    assert!(error.to_string().contains("freebsd/amd64"), "{error}");
    store
      .push(&whole, Some(&Platform::default()), None)
      .unwrap();

    // A single manifest, and an index of only that manifest, are pushed
    // unchanged.
    let (manifest, _) = image.manifest(&Platform::default()).unwrap();
    let single = format!("{writable}/test/single:1");
    store.create(&single, manifest.clone()).unwrap();
    let mut entry = manifest;
    entry.platform = Some(Platform::default());
    let index = json(&Index {
      manifests: vec![entry],
      ..Index::default()
    });
    let indexed = format!("{writable}/test/indexed:1");
    store
      .create(&indexed, blob_of(&store, media_type::INDEX, &index))
      .unwrap();
    for name in [&single, &indexed, &single] {
      store.push(name, Some(&Platform::default()), None).unwrap();
    }

    let other = ImageStore::new(pulled.path()).unwrap();
    for name in [&single, &indexed] {
      let back = other.pull(name, &Platform::default(), None).unwrap();
      assert_eq!(back.descriptor.digest, store.get(name).unwrap().descriptor.digest);
      let config = back.config(&Platform::default()).unwrap();
      assert_eq!(config.config.unwrap().cmd, Some(vec!["/bin/sh".to_string()]));
    }
    assert!(other.get(&indexed).unwrap().descriptor.is_index());
    let back = other.pull(&whole, &Platform::default(), None).unwrap();
    assert_ne!(back.descriptor.digest, image.descriptor.digest);
    assert_eq!(other.platforms(&whole, None).unwrap(), [Platform::default()]);
  }

  #[test]
  fn lists_an_images_platforms_from_the_store_or_the_registry() {
    let root = tempfile::tempdir().unwrap();
    let store = ImageStore::new(root.path()).unwrap();
    let reference = format!("{}/test/image:1", registry());
    let both = [
      Platform {
        architecture: "amd64".into(),
        ..Platform::default()
      },
      Platform::default(),
    ];

    assert_eq!(store.platforms(&reference, None).unwrap(), both);
    let image = store.pull(&reference, &Platform::default(), None).unwrap();
    assert_eq!(store.platforms(&reference, None).unwrap(), both);

    // A manifest's platform comes from its config.
    let (manifest, _) = image.manifest(&Platform::default()).unwrap();
    store.create("ghcr.io/test/single:1", manifest).unwrap();
    assert_eq!(
      store.platforms("ghcr.io/test/single:1", None).unwrap(),
      [Platform::default()]
    );
  }

  /// Stores `bytes` in `store` and returns a descriptor of `media_type` for
  /// them.
  fn blob_of(store: &ImageStore, media_type: &str, bytes: &[u8]) -> Descriptor {
    store.content().ingest(bytes).unwrap();
    descriptor(media_type, bytes, None)
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
  fn saves_images_as_a_layout_that_loads_them_again() {
    let (pulled, loaded, work) = (
      tempfile::tempdir().unwrap(),
      tempfile::tempdir().unwrap(),
      tempfile::tempdir().unwrap(),
    );
    let store = ImageStore::new(pulled.path()).unwrap();
    let reference = format!("{}/test/image:1", registry());
    store.pull(&reference, &Platform::default(), None).unwrap();
    store.tag(&reference, "ghcr.io/test/other:2").unwrap();
    let layout = work.path().join("layout");

    store
      .save(&[&reference, "ghcr.io/test/other:2"], &layout, None)
      .unwrap();
    assert_eq!(std::fs::read_to_string(layout.join("oci-layout")).unwrap(), LAYOUT);
    let other = ImageStore::new(loaded.path()).unwrap();
    let images = other.load(&layout).unwrap();

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

    // Saving for one platform writes a new index of only that platform's
    // manifest.
    let arm64 = work.path().join("arm64");
    store
      .save(&[&reference], &arm64, Some(&Platform::default()))
      .unwrap();
    let third = tempfile::tempdir().unwrap();
    let saved = ImageStore::new(third.path()).unwrap();
    let image = saved.load(&arm64).unwrap().remove(0);
    assert_ne!(
      image.descriptor.digest,
      store.get(&reference).unwrap().descriptor.digest
    );
    assert_eq!(saved.platforms(&reference, None).unwrap(), [Platform::default()]);
  }

  /// Writes an OCI image layout at `root` holding the blobs `files`, with an
  /// index that names `manifest`'s image `name`.
  fn layout(root: &Path, name: &str, manifest: &[u8], files: &[&[u8]]) -> PathBuf {
    let mut entry = descriptor(media_type::MANIFEST, manifest, None);
    entry
      .annotations
      .insert(REF_NAME.to_string(), name.to_string());
    let index = json(&Index {
      manifests: vec![entry],
      ..Index::default()
    });
    std::fs::create_dir_all(root.join("blobs/sha256")).unwrap();
    std::fs::write(root.join("index.json"), index).unwrap();
    for file in files {
      std::fs::write(layout_blob(root, &sha256_digest(file)).unwrap(), file).unwrap();
    }
    root.to_path_buf()
  }

  #[test]
  fn loads_a_layout_naming_its_image_as_freebsd_does() {
    let (root, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let store = ImageStore::new(root.path()).unwrap();
    let (layer, config, manifest) = documents();
    let directory = layout(
      work.path(),
      "freebsd-static:15.1-RELEASE-aarch64",
      &manifest,
      &[&manifest, &config, &layer],
    );

    let images = store.load(&directory).unwrap();

    assert_eq!(
      images[0].reference,
      "docker.io/library/freebsd-static:15.1-RELEASE-aarch64"
    );
    assert!(store.content().has(&sha256_digest(&layer)));
  }

  #[test]
  fn refuses_a_layout_with_a_blob_missing_or_not_its_digest() {
    let (root, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let store = ImageStore::new(root.path()).unwrap();
    let (layer, config, manifest) = documents();
    let name = "ghcr.io/test/image:1";

    let empty = layout(&work.path().join("empty"), name, &manifest, &[]);
    let error = store.load(&empty).unwrap_err();
    assert!(error.to_string().contains(&sha256_digest(&manifest)), "{error}");

    let lacking = layout(&work.path().join("lacking"), name, &manifest, &[&manifest, &config]);
    let error = store.load(&lacking).unwrap_err();
    assert!(error.to_string().contains(&sha256_digest(&layer)), "{error}");

    // The previous load left the manifest and config in the store, but not
    // the layer.
    let forged = layout(&work.path().join("forged"), name, &manifest, &[]);
    std::fs::write(layout_blob(&forged, &sha256_digest(&layer)).unwrap(), "something else").unwrap();
    assert!(matches!(store.load(&forged).unwrap_err(), Error::Checksum { .. }));
    assert!(store.list().unwrap().is_empty());
  }
}
