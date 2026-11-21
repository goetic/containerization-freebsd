//! Moving images between the store and registries: pull, push and asking
//! for an image's platforms.

use super::{Image, ImageStore, check_runs, choose};
use crate::error::{Error, Result};
use crate::oci::{Credentials, Descriptor, Document, Platform, Reference, RegistryClient};

impl ImageStore {
  /// Pulls `reference`'s image for `platform`: the index if there is one,
  /// and that platform's manifest, config and layers. Blobs already in the
  /// store are not downloaded again.
  pub fn pull(&self, reference: &str, platform: &Platform, credentials: Option<Credentials>) -> Result<Image> {
    let reference = Reference::parse(reference)?;
    let client = RegistryClient::new(credentials);
    let top = client.fetch_manifest(&reference, reference.target(), &self.content)?;

    let manifest = match self.content.document(&top)? {
      Document::Index(index) => {
        let chosen = choose(&index, platform, &reference)?;
        if !self.content.has(&chosen.digest) {
          client.fetch_manifest(&reference, &chosen.digest, &self.content)?;
        }
        self.content.manifest(&chosen)?
      }
      Document::Manifest(manifest) => manifest,
    };

    if !self.content.has(&manifest.config.digest) {
      client.fetch_blob(&reference, &manifest.config, &self.content)?;
    }
    check_runs(&self.content.config(&manifest)?, platform, &reference)?;
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
    match self.content.document(descriptor)? {
      Document::Index(index) => Ok(
        index
          .manifests
          .into_iter()
          .filter_map(|manifest| manifest.platform)
          .filter(|platform| platform.os != "unknown" && platform.architecture != "unknown")
          .collect(),
      ),
      Document::Manifest(manifest) => {
        if !self.content.has(&manifest.config.digest)
          && let Some((client, reference)) = remote
        {
          client.fetch_blob(reference, &manifest.config, &self.content)?;
        }
        Ok(vec![self.content.config(&manifest)?.platform()])
      }
    }
  }

  /// Pushes everything `descriptor` refers to: a manifest's config and
  /// layers, or an index's manifests (by digest) and their contents.
  fn push_children(&self, client: &RegistryClient, reference: &Reference, descriptor: &Descriptor) -> Result<()> {
    let index = match self.content.document(descriptor)? {
      Document::Index(index) => index,
      Document::Manifest(manifest) => {
        return manifest
          .blobs()
          .try_for_each(|blob| client.push_blob(reference, blob, &self.content));
      }
    };
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
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::images::tests::{descriptor, json, registry};
  use crate::oci::testing::FakeRegistry;
  use crate::oci::{Index, media_type};

  /// Stores `bytes` in `store` and returns a descriptor of `media_type` for
  /// them.
  fn blob_of(store: &ImageStore, media_type: &str, bytes: &[u8]) -> Descriptor {
    store.content().ingest(bytes).unwrap();
    descriptor(media_type, bytes, None)
  }

  #[test]
  fn pushes_images_that_pull_back() {
    let (pushed, pulled) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let store = ImageStore::new(pushed.path()).unwrap();
    let image = store
      .pull(&format!("{}/test/image:1", registry()), &Platform::default(), None)
      .unwrap();
    let writable = FakeRegistry::default().serve();

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
}
