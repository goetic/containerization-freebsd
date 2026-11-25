//! Pull, push and platform queries against registries.

use crate::{error, oci};

impl super::ImageStore {
  /// Pulls `reference`'s image for `platform` through `client`: the index if
  /// there is one, and that platform's manifest, config, and layers. The
  /// index or manifest `reference` names is always fetched; anything else
  /// the store has is not.
  pub fn pull(
    &self,
    reference: &str,
    platform: &oci::Platform,
    client: &oci::registry::RegistryClient,
  ) -> error::Result<super::Image> {
    let reference = oci::reference::Reference::parse(reference)?;
    let _blobs = self.using_blobs()?;
    let top = client.fetch_manifest(&reference, reference.target(), &self.content)?;

    let manifest = match self.content.document(&top)? {
      oci::Document::Index(index) => {
        let chosen = super::choose(&index, platform, &reference)?;
        if !self.content.has(&chosen.digest) {
          client.fetch_manifest(&reference, chosen.digest.as_str(), &self.content)?;
        }
        self.content.manifest(&chosen)?
      }
      oci::Document::Manifest(manifest) => manifest,
    };

    if !self.content.has(&manifest.config.digest) {
      client.fetch_blob(&reference, &manifest.config, &self.content)?;
    }
    super::check_runs(&self.content.config(&manifest)?, platform, &reference)?;
    for layer in &manifest.layers {
      if !self.content.has(&layer.digest) {
        client.fetch_blob(&reference, layer, &self.content)?;
      }
    }

    self.create(&reference.to_string(), top)
  }

  /// Pushes the image `reference` to the repository it names through
  /// `client`, like Containerization's `push(reference:platform:)`. Blobs
  /// the registry lacks go first, then child manifests by digest, then the
  /// top-level index or manifest, since registries may reject a manifest
  /// that references unknown content. To push under another name, tag
  /// first.
  ///
  /// With `platform`, an index is pushed as a new index of only that
  /// platform's manifests. Without it, the whole index is pushed, which needs
  /// every platform's manifest, and a pull fetches only one.
  pub fn push(
    &self,
    reference: &str,
    platform: Option<&oci::Platform>,
    client: &oci::registry::RegistryClient,
  ) -> error::Result<()> {
    let reference = oci::reference::Reference::parse(reference)?;
    let _blobs = self.using_blobs()?;
    let image = self.named(&reference)?;
    let descriptor = self.for_platform(&image, platform)?;

    self.push_children(client, &reference, &descriptor)?;
    client.push_manifest(&reference, reference.target(), &descriptor, &self.content)
  }

  /// The platforms `reference`'s image supports, like Containerization's
  /// `platforms(reference:)`. Uses the store's image of that name if there
  /// is one, otherwise asks the registry through `client` without pulling
  /// layers.
  pub fn platforms(
    &self,
    reference: &str,
    client: &oci::registry::RegistryClient,
  ) -> error::Result<Vec<oci::Platform>> {
    let reference = oci::reference::Reference::parse(reference)?;
    let _blobs = self.using_blobs()?;
    if let Some(image) = self.find(&reference)? {
      return self.platforms_of(&image.descriptor, None);
    }

    let top = client.fetch_manifest(&reference, reference.target(), &self.content)?;
    self.platforms_of(&top, Some((client, &reference)))
  }

  /// An index's entries' platforms, skipping those with an `unknown` OS or
  /// architecture, which mark attestation manifests; or a manifest's config's
  /// platform, fetching the config from `remote` if the store lacks it.
  fn platforms_of(
    &self,
    descriptor: &oci::Descriptor,
    remote: Option<(&oci::registry::RegistryClient, &oci::reference::Reference)>,
  ) -> error::Result<Vec<oci::Platform>> {
    match self.content.document(descriptor)? {
      oci::Document::Index(index) => Ok(
        index
          .manifests
          .into_iter()
          .filter_map(|manifest| manifest.platform)
          .filter(|platform| platform.os != "unknown" && platform.architecture != "unknown")
          .collect(),
      ),
      oci::Document::Manifest(manifest) => {
        if !self.content.has(&manifest.config.digest)
          && let Some((client, reference)) = remote
        {
          client.fetch_blob(reference, &manifest.config, &self.content)?;
        }
        Ok(vec![self.content.config(&manifest)?.platform()])
      }
    }
  }

  /// Pushes everything `descriptor` references: a manifest's config and
  /// layers, or an index's manifests, by digest, and their blobs.
  fn push_children(
    &self,
    client: &oci::registry::RegistryClient,
    reference: &oci::reference::Reference,
    descriptor: &oci::Descriptor,
  ) -> error::Result<()> {
    let index = match self.content.document(descriptor)? {
      oci::Document::Index(index) => index,
      oci::Document::Manifest(manifest) => {
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
          .map_or_else(|| child.digest.to_string(), oci::Platform::to_string);
        return Err(error::Error::Invalid(format!(
          "the store lacks {reference}'s manifest for {platform}: push the platforms it has, one at a time"
        )));
      }
      self.push_children(client, reference, child)?;
      client.push_manifest(reference, child.digest.as_str(), child, &self.content)?;
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oci::media_type;
  use crate::{images, testing};

  /// Ingests `bytes` and returns a `media_type` descriptor for them.
  fn blob_of(store: &images::ImageStore, media_type: &str, bytes: &[u8]) -> oci::Descriptor {
    store.content().ingest(bytes).unwrap();
    images::tests::descriptor(media_type, bytes, None)
  }

  #[test]
  fn pushes_images_that_pull_back() {
    let (pushed, pulled) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let store = images::ImageStore::new(pushed.path()).unwrap();
    let client = oci::registry::RegistryClient::default();
    let image = store
      .pull(
        &format!("{}/test/image:1", images::tests::registry()),
        &oci::Platform::default(),
        &client,
      )
      .unwrap();
    let writable = testing::FakeRegistry::default().serve();

    // The pull fetched only the index's arm64 manifest, so pushing the whole
    // index fails. Pushing for arm64 pushes a new index of that manifest.
    let whole = format!("{writable}/test/index:1");
    store.tag(&image.reference, &whole).unwrap();
    let error = store.push(&whole, None, &client).unwrap_err();
    assert!(error.to_string().contains("freebsd/amd64"), "{error}");
    store
      .push(&whole, Some(&oci::Platform::default()), &client)
      .unwrap();

    // A single manifest, and an index of only that manifest, are pushed
    // unchanged.
    let (manifest, _) = image.manifest(&oci::Platform::default()).unwrap();
    let single = format!("{writable}/test/single:1");
    store.create(&single, manifest.clone()).unwrap();
    let mut entry = manifest;
    entry.platform = Some(oci::Platform::default());
    let index = images::tests::json(&oci::Index {
      manifests: vec![entry],
      ..oci::Index::default()
    });
    let indexed = format!("{writable}/test/indexed:1");
    store
      .create(&indexed, blob_of(&store, media_type::INDEX, &index))
      .unwrap();
    for name in [&single, &indexed, &single] {
      store
        .push(name, Some(&oci::Platform::default()), &client)
        .unwrap();
    }

    let other = images::ImageStore::new(pulled.path()).unwrap();
    for name in [&single, &indexed] {
      let back = other
        .pull(name, &oci::Platform::default(), &client)
        .unwrap();
      assert_eq!(back.descriptor.digest, store.get(name).unwrap().descriptor.digest);
      let config = back.config(&oci::Platform::default()).unwrap();
      assert_eq!(config.config.unwrap().cmd, Some(vec!["/bin/sh".to_string()]));
    }
    assert!(other.get(&indexed).unwrap().descriptor.is_index());
    let back = other
      .pull(&whole, &oci::Platform::default(), &client)
      .unwrap();
    assert_ne!(back.descriptor.digest, image.descriptor.digest);
    assert_eq!(other.platforms(&whole, &client).unwrap(), [oci::Platform::default()]);
  }

  #[test]
  fn lists_an_images_platforms_from_the_store_or_the_registry() {
    let root = tempfile::tempdir().unwrap();
    let store = images::ImageStore::new(root.path()).unwrap();
    let reference = format!("{}/test/image:1", images::tests::registry());
    let both = [
      oci::Platform {
        architecture: "amd64".into(),
        ..oci::Platform::default()
      },
      oci::Platform::default(),
    ];

    let client = oci::registry::RegistryClient::default();

    assert_eq!(store.platforms(&reference, &client).unwrap(), both);
    let image = store
      .pull(&reference, &oci::Platform::default(), &client)
      .unwrap();
    assert_eq!(store.platforms(&reference, &client).unwrap(), both);

    // A manifest's platform comes from its config.
    let (manifest, _) = image.manifest(&oci::Platform::default()).unwrap();
    store.create("ghcr.io/test/single:1", manifest).unwrap();
    assert_eq!(
      store.platforms("ghcr.io/test/single:1", &client).unwrap(),
      [oci::Platform::default()]
    );
  }

  #[test]
  fn pulls_the_image_for_its_platform_through_a_token() {
    let root = tempfile::tempdir().unwrap();
    let store = images::ImageStore::new(root.path()).unwrap();
    let reference = format!("{}/test/image:1", images::tests::registry());

    let image = store
      .pull(
        &reference,
        &oci::Platform::default(),
        &oci::registry::RegistryClient::default(),
      )
      .unwrap();

    assert_eq!(image.reference, reference);
    assert!(image.descriptor.is_index());
    let config = image.config(&oci::Platform::default()).unwrap();
    assert_eq!(config.config.unwrap().cmd, Some(vec!["/bin/sh".to_string()]));
    let (_, manifest) = image.manifest(&oci::Platform::default()).unwrap();
    assert!(store.content().has(&manifest.layers[0].digest));
    assert_eq!(store.get(&reference).unwrap().descriptor, image.descriptor);
    assert!(root.path().join("oci-layout").exists());
  }

  #[test]
  fn refuses_an_image_with_none_for_its_platform() {
    let root = tempfile::tempdir().unwrap();
    let store = images::ImageStore::new(root.path()).unwrap();
    let riscv = oci::Platform {
      architecture: "riscv64".into(),
      ..oci::Platform::default()
    };

    let error = store
      .pull(
        &format!("{}/test/image:1", images::tests::registry()),
        &riscv,
        &oci::registry::RegistryClient::default(),
      )
      .unwrap_err();

    assert!(error.to_string().contains("freebsd/amd64, freebsd/arm64"), "{error}");
    assert!(store.list().unwrap().is_empty());
  }
}
