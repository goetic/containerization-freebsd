//! Loading images from, and saving them to, OCI image layouts.

use super::{Image, ImageStore, LAYOUT};
use crate::error::{Error, Result};
use crate::oci::{Descriptor, Document, Index, Platform, REF_NAME, parse, sha256_hex};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

impl ImageStore {
  /// Loads the images in the OCI image layout at `directory`, like
  /// Containerization's `load(from:)`. An archived layout, such as FreeBSD's
  /// container images on download.freebsd.org, must be extracted first. Each
  /// image is named by its `REF_NAME` annotation, normalized like any
  /// reference, so `freebsd-static:15.1-RELEASE-aarch64` becomes
  /// `docker.io/library/freebsd-static:15.1-RELEASE-aarch64`. Blobs already
  /// in the store are not copied.
  pub fn load(&self, directory: &Path) -> Result<Vec<Image>> {
    let path = directory.join("index.json");
    let bytes = std::fs::read(&path).map_err(Error::io(format!("reading {}", path.display())))?;
    let index: Index = parse(&bytes, &path.display().to_string())?;
    let _blobs = self.using_blobs()?;

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

  /// Saves the images `references`, with every blob they reach, as an OCI
  /// image layout at `out`, like Containerization's
  /// `save(references:out:platform:)`. With `platform`, an index is saved as
  /// a new index of only that platform's manifests. `out` is created if
  /// needed, and any `index.json` there is replaced.
  pub fn save(&self, references: &[&str], out: &Path, platform: Option<&Platform>) -> Result<()> {
    let _blobs = self.using_blobs()?;
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

  /// Copies `descriptor`'s blob and those it references from the layout at
  /// `directory`, skipping blobs the store has. Absent blobs are skipped
  /// too, since an index's manifests may be absent, as after a pull;
  /// `missing` reports any others afterwards.
  fn import(&self, directory: &Path, descriptor: &Descriptor) -> Result<()> {
    if !self.copy_in(directory, &descriptor.digest)? {
      return Ok(());
    }

    match self.content.document(descriptor)? {
      Document::Index(index) => index
        .manifests
        .iter()
        .try_for_each(|child| self.import(directory, child)),
      Document::Manifest(manifest) => manifest
        .blobs()
        .try_for_each(|blob| self.copy_in(directory, &blob.digest).map(drop)),
    }
  }

  /// Copies the blob `digest` from the layout at `directory` unless the
  /// store has it. Returns whether the store has it afterwards.
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

  /// A blob reachable from `index` that the store lacks. Missing manifests
  /// aren't reported, since a pull fetches only one platform's manifest.
  fn missing(&self, index: &Index) -> Result<Option<String>> {
    Ok(
      self
        .reachable(index)?
        .into_iter()
        .find(|digest| !self.content.has(digest)),
    )
  }
}

/// The path of the blob `digest` in the layout at `root`.
fn layout_blob(root: &Path, digest: &str) -> Result<PathBuf> {
  let hex = sha256_hex(digest).ok_or_else(|| Error::Invalid(format!("{digest:?} is not a sha256 digest")))?;

  Ok(root.join("blobs/sha256").join(hex))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::images::tests::{descriptor, documents, json, registry};
  use crate::oci::{media_type, sha256_digest};

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
