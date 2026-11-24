//! The host's image store, an OCI image layout at a path the caller chooses.
//! `index.json` names each image with a `REF_NAME` annotation. It mirrors
//! Containerization's image store.

mod layout;
mod registry;

use crate::error::{Error, Result};
use crate::oci::{
  ContentStore, Descriptor, Digest, Document, ImageConfig, Index, Manifest, Platform, REF_NAME, Reference, parse,
};
use std::collections::BTreeSet;
use std::fmt::Display;
use std::fs::File;
use std::path::{Path, PathBuf};

const LAYOUT: &str = r#"{"imageLayoutVersion":"1.0.0"}"#;
/// Locked while `index.json` is read and changed.
const INDEX_LOCK: &str = "index.json.lock";
/// Locked shared while an operation works with blobs that no entry in
/// `index.json` may reference yet, and exclusively while `delete` collects
/// garbage.
const BLOBS_LOCK: &str = "blobs.lock";

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
  /// Opens or creates the store at `root`.
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

  /// The descriptor to push or save for `image`, narrowed to `platform` if
  /// given. An index narrows to a new index in the store of only
  /// `platform`'s manifests, unless that is all of them. A manifest must run
  /// on `platform` and is returned as is.
  fn for_platform(&self, image: &Image, platform: Option<&Platform>) -> Result<Descriptor> {
    let Some(platform) = platform else {
      return Ok(image.descriptor.clone());
    };
    let mut index = match self.content.document(&image.descriptor)? {
      Document::Index(index) => index,
      Document::Manifest(manifest) => {
        check_runs(&self.content.config(&manifest)?, platform, &image.reference)?;
        return Ok(image.descriptor.clone());
      }
    };
    let all = index.manifests.len();
    index
      .manifests
      .retain(|manifest| manifest.runs_on(platform));
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
      annotations: image.descriptor.annotations.clone(),
      ..Descriptor::new(
        image.descriptor.media_type.clone(),
        self.content.ingest(&bytes)?,
        bytes.len() as u64,
      )
    })
  }

  /// Names `descriptor`, an index or manifest in the store, as `reference`,
  /// replacing any image of that name. Blobs written through `content` have
  /// no protection from garbage collection: a `delete` in another process
  /// can remove them before `create` adds an entry that references them.
  pub fn create(&self, reference: &str, descriptor: Descriptor) -> Result<Image> {
    let reference = Reference::parse(reference)?.to_string();
    let mut descriptor = descriptor;
    descriptor.platform = None;
    descriptor.annotations.clear();
    descriptor
      .annotations
      .insert(REF_NAME.to_string(), reference.clone());
    self.update(|index| {
      // Checked under the index lock, which garbage collection also holds, so
      // the blob can't be removed between this check and the new entry.
      if !self.content.has(&descriptor.digest) {
        return Err(Error::Invalid(format!(
          "the store has no blob {} for {reference}",
          descriptor.digest
        )));
      }
      index
        .manifests
        .retain(|entry| ref_name(entry) != Some(&reference));
      index.manifests.push(descriptor.clone());
      Ok(())
    })?;
    Ok(self.image(reference, descriptor))
  }

  pub fn get(&self, reference: &str) -> Result<Image> {
    self.named(&Reference::parse(reference)?)
  }

  /// The image named `reference`.
  fn named(&self, reference: &Reference) -> Result<Image> {
    self
      .find(reference)?
      .ok_or_else(|| Error::Invalid(format!("the store has no image {reference}")))
  }

  /// The image named `reference`, if the store has one.
  fn find(&self, reference: &Reference) -> Result<Option<Image>> {
    let name = reference.to_string();

    Ok(
      self
        .list()?
        .into_iter()
        .find(|image| image.reference == name),
    )
  }

  pub fn list(&self) -> Result<Vec<Image>> {
    Ok(
      self
        .read_index()?
        .manifests
        .into_iter()
        .filter_map(|entry| Some(self.image(ref_name(&entry)?.to_string(), entry)))
        .collect(),
    )
  }

  /// Adds the name `new` to the image named `existing`.
  pub fn tag(&self, existing: &str, new: &str) -> Result<Image> {
    let image = self.get(existing)?;

    self.create(new, image.descriptor)
  }

  /// Removes the name `reference`, then garbage-collects every blob no
  /// remaining image reaches. Collecting waits for pulls, loads, pushes,
  /// saves, and platform queries in progress in any process.
  pub fn delete(&self, reference: &str) -> Result<()> {
    let reference = Reference::parse(reference)?.to_string();

    self.update(|index| {
      let before = index.manifests.len();
      index
        .manifests
        .retain(|entry| ref_name(entry) != Some(&reference));
      if index.manifests.len() == before {
        return Err(Error::Invalid(format!("the store has no image {reference}")));
      }
      Ok(())
    })?;

    let _collecting = self.lock(BLOBS_LOCK, File::lock)?;
    let _index = self.lock(INDEX_LOCK, File::lock)?;
    let needed = self.reachable(&self.read_index()?.manifests)?;
    for digest in self.content.digests()? {
      if !needed.contains(&digest) {
        self.content.delete(&digest)?;
      }
    }
    Ok(())
  }

  /// Every blob reachable from `roots`, the roots included. Indexes and
  /// manifests the store lacks are skipped, but configs and layers are
  /// included either way.
  fn reachable(&self, roots: &[Descriptor]) -> Result<BTreeSet<Digest>> {
    let mut needed = BTreeSet::new();
    let mut pending = roots.to_vec();

    while let Some(descriptor) = pending.pop() {
      if !self.content.has(&descriptor.digest) || !needed.insert(descriptor.digest.clone()) {
        continue;
      }
      match self.content.document(&descriptor)? {
        Document::Index(index) => pending.extend(index.manifests),
        Document::Manifest(manifest) => needed.extend(manifest.blobs().map(|blob| blob.digest.clone())),
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

  /// Protects blobs from garbage collection until the returned file is
  /// dropped. Pulls and loads hold it until they have added their image to
  /// `index.json`. Pushes, saves, and platform queries hold it while they
  /// read blobs that no entry references, such as an index narrowed to one
  /// platform.
  fn using_blobs(&self) -> Result<File> {
    self.lock(BLOBS_LOCK, File::lock_shared)
  }

  /// Opens the store's lock file `name` and locks it with `lock`, either
  /// `File::lock` or `File::lock_shared`, which also exclude other processes.
  /// Dropping the file unlocks it.
  fn lock(&self, name: &str, lock: fn(&File) -> std::io::Result<()>) -> Result<File> {
    let path = self.root.join(name);
    let locking = || format!("locking {}", path.display());
    let file = File::create(&path).map_err(Error::io(locking()))?;
    lock(&file).map_err(Error::io(locking()))?;
    Ok(file)
  }

  /// Applies `change` to `index.json` under a file lock, so stores in other
  /// processes don't lose each other's updates.
  fn update(&self, change: impl FnOnce(&mut Index) -> Result<()>) -> Result<()> {
    let _index = self.lock(INDEX_LOCK, File::lock)?;
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
  /// The manifest for `platform` and its descriptor. A lone manifest is
  /// returned whatever its platform.
  pub fn manifest(&self, platform: &Platform) -> Result<(Descriptor, Manifest)> {
    match self.content.document(&self.descriptor)? {
      Document::Index(index) => {
        let descriptor = choose(&index, platform, &self.reference)?;
        let manifest = self.content.manifest(&descriptor)?;
        Ok((descriptor, manifest))
      }
      Document::Manifest(manifest) => Ok((self.descriptor.clone(), manifest)),
    }
  }

  pub fn config(&self, platform: &Platform) -> Result<ImageConfig> {
    let (_, manifest) = self.manifest(platform)?;

    self.content.config(&manifest)
  }

  pub(crate) fn content(&self) -> &ContentStore {
    &self.content
  }
}

/// The first manifest in `reference`'s index that runs on `platform`.
fn choose(index: &Index, platform: &Platform, reference: &impl Display) -> Result<Descriptor> {
  if let Some(chosen) = index.manifests.iter().find(|entry| entry.runs_on(platform)) {
    return Ok(chosen.clone());
  }

  let names: Vec<String> = index
    .manifests
    .iter()
    .filter_map(|entry| entry.platform.as_ref().map(Platform::to_string))
    .collect();
  let names = if names.is_empty() {
    "none".to_string()
  } else {
    names.join(", ")
  };
  Err(Error::Invalid(format!(
    "{reference} has no image for {platform}, only {names}"
  )))
}

fn check_runs(config: &ImageConfig, platform: &Platform, reference: &impl Display) -> Result<()> {
  if platform.runs(&config.platform()) {
    Ok(())
  } else {
    Err(Error::Invalid(format!(
      "{reference} is an image for {}, not {platform}",
      config.platform()
    )))
  }
}

fn ref_name(entry: &Descriptor) -> Option<&String> {
  entry.annotations.get(REF_NAME)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oci::{RegistryClient, RootFs, RunConfig, media_type};
  use crate::testing::FakeRegistry;
  use std::time::Duration;

  pub(super) fn descriptor(media_type: &str, bytes: &[u8], platform: Option<Platform>) -> Descriptor {
    Descriptor {
      platform,
      ..Descriptor::new(media_type, Digest::of(bytes), bytes.len() as u64)
    }
  }

  pub(super) fn json(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
  }

  /// The layer, config and manifest of a one-layer arm64 FreeBSD image.
  pub(super) fn documents() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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
        diff_ids: vec![Digest::of(&layer)],
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

  /// A loopback registry serving `test/image:1`: an index listing arm64 and
  /// amd64 FreeBSD manifests, of which it has only arm64.
  pub(super) fn registry() -> String {
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

    FakeRegistry::default()
      .manifest("test/image", "1", media_type::INDEX, &index)
      .manifest(
        "test/image",
        Digest::of(&manifest).as_str(),
        media_type::MANIFEST,
        &manifest,
      )
      .blob(&config)
      .blob(&layer)
      .serve()
  }

  #[test]
  fn deletes_the_blobs_no_image_needs() {
    let root = tempfile::tempdir().unwrap();
    let store = ImageStore::new(root.path()).unwrap();
    let reference = format!("{}/test/image:1", registry());
    store
      .pull(&reference, &Platform::default(), &RegistryClient::default())
      .unwrap();
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
  fn collects_garbage_once_pulls_have_named_their_images() {
    let root = tempfile::tempdir().unwrap();
    let store = ImageStore::new(root.path()).unwrap();
    let reference = format!("{}/test/image:1", registry());
    store
      .pull(&reference, &Platform::default(), &RegistryClient::default())
      .unwrap();
    // Simulate a pull in progress: take the shared blobs lock, then write a
    // manifest blob that no entry in index.json references yet.
    let pulling = store.using_blobs().unwrap();
    let manifest = json(&Manifest {
      schema_version: 2,
      media_type: Some(media_type::MANIFEST.into()),
      config: descriptor(media_type::CONFIG, b"{}", None),
      layers: Vec::new(),
    });
    let fetched = store.content().ingest(&manifest).unwrap();

    std::thread::scope(|scope| {
      let deleting = scope.spawn(|| store.delete(&reference));
      std::thread::sleep(Duration::from_millis(200));
      assert!(!deleting.is_finished());
      assert!(store.content().has(&fetched));
      // delete has already removed the image's entry from index.json and
      // released the index lock. It is waiting only for the blobs lock.
      assert!(store.list().unwrap().is_empty());
      store
        .create(
          "ghcr.io/test/pulled:1",
          descriptor(media_type::MANIFEST, &manifest, None),
        )
        .unwrap();
      drop(pulling);
      deleting.join().unwrap().unwrap();
    });

    assert_eq!(store.content().digests().unwrap(), [fetched]);
  }
}
