//! OCI images on the host: references, the image spec's documents, a
//! registry client and a content store.

mod content;
mod reference;
mod registry;

pub use content::ContentStore;
pub use reference::Reference;
pub use registry::{Credentials, RegistryClient};

use crate::agent::Exec;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

pub mod media_type {
  pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";
  pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
  pub const CONFIG: &str = "application/vnd.oci.image.config.v1+json";
  pub const LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
  pub const LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
  pub const LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
  pub const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
  pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
  pub const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
}

/// The annotation naming the reference an index entry was pulled or tagged as.
pub const REF_NAME: &str = "org.opencontainers.image.ref.name";

/// A blob by its media type, digest and size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
  pub media_type: String,
  pub digest: String,
  pub size: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub platform: Option<Platform>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub annotations: BTreeMap<String, String>,
}

impl Descriptor {
  /// Whether it describes an index (or Docker manifest list), not a manifest.
  pub fn is_index(&self) -> bool {
    matches!(
      self.media_type.as_str(),
      media_type::INDEX | media_type::DOCKER_MANIFEST_LIST
    )
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
  pub architecture: String,
  pub os: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub variant: Option<String>,
}

impl Default for Platform {
  /// The guests': FreeBSD on arm64.
  fn default() -> Self {
    Self {
      architecture: "arm64".into(),
      os: "freebsd".into(),
      variant: None,
    }
  }
}

impl Platform {
  /// Whether an image for `other` runs here: the same OS and architecture,
  /// and the same variant if both name one.
  pub fn runs(&self, other: &Platform) -> bool {
    self.os == other.os
      && self.architecture == other.architecture
      && (self.variant.is_none() || other.variant.is_none() || self.variant == other.variant)
  }
}

impl std::fmt::Display for Platform {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(formatter, "{}/{}", self.os, self.architecture)?;
    match &self.variant {
      Some(variant) => write!(formatter, "/{variant}"),
      None => Ok(()),
    }
  }
}

/// An image index: a manifest for each platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Index {
  pub schema_version: u32,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub media_type: Option<String>,
  pub manifests: Vec<Descriptor>,
}

impl Default for Index {
  fn default() -> Self {
    Self {
      schema_version: 2,
      media_type: Some(media_type::INDEX.into()),
      manifests: Vec::new(),
    }
  }
}

/// An image for one platform: its config and its layers, lowest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
  pub schema_version: u32,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub media_type: Option<String>,
  pub config: Descriptor,
  pub layers: Vec<Descriptor>,
}

/// An image's configuration: what it runs, and the digests of its layers
/// uncompressed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
  #[serde(default)]
  pub architecture: String,
  #[serde(default)]
  pub os: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub variant: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub config: Option<RunConfig>,
  pub rootfs: RootFs,
}

/// The defaults for a container of the image. The spec's keys are
/// PascalCase, but Go tools read them in any case, and FreeBSD's own images
/// write `cmd`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RunConfig {
  #[serde(default, alias = "user", skip_serializing_if = "Option::is_none")]
  pub user: Option<String>,
  #[serde(default, alias = "env", skip_serializing_if = "Vec::is_empty")]
  pub env: Vec<String>,
  #[serde(default, alias = "entrypoint", skip_serializing_if = "Option::is_none")]
  pub entrypoint: Option<Vec<String>>,
  #[serde(default, alias = "cmd", skip_serializing_if = "Option::is_none")]
  pub cmd: Option<Vec<String>>,
  #[serde(
    default,
    alias = "workingDir",
    alias = "workingdir",
    skip_serializing_if = "Option::is_none"
  )]
  pub working_dir: Option<String>,
  #[serde(
    default,
    alias = "stopSignal",
    alias = "stopsignal",
    skip_serializing_if = "Option::is_none"
  )]
  pub stop_signal: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootFs {
  #[serde(rename = "type")]
  pub kind: String,
  pub diff_ids: Vec<String>,
}

impl ImageConfig {
  /// The process a container of the image runs unless told otherwise: its
  /// entrypoint then command, its environment and its working directory.
  /// Its user isn't applied yet.
  pub fn process(&self) -> Exec {
    let run = self.config.clone().unwrap_or_default();

    Exec {
      argv: run
        .entrypoint
        .unwrap_or_default()
        .into_iter()
        .chain(run.cmd.unwrap_or_default())
        .collect(),
      env: run
        .env
        .iter()
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect(),
      cwd: run.working_dir.filter(|directory| !directory.is_empty()),
      pty: None,
    }
  }

  pub fn platform(&self) -> Platform {
    Platform {
      architecture: self.architecture.clone(),
      os: self.os.clone(),
      variant: self.variant.clone(),
    }
  }

  /// The chain id of each layer: the first's diff id, then each the sha256
  /// of the one before and its own diff id. A layer's chain id names it with
  /// everything beneath it.
  pub fn chain_ids(&self) -> Vec<String> {
    let mut chain: Vec<String> = Vec::with_capacity(self.rootfs.diff_ids.len());

    for diff_id in &self.rootfs.diff_ids {
      let next = match chain.last() {
        Some(below) => sha256_digest(format!("{below} {diff_id}").as_bytes()),
        None => diff_id.clone(),
      };
      chain.push(next);
    }
    chain
  }
}

/// `sha256:<hex>` of `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
  format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

/// `sha256:<hex>` of the file at `path`, and its length.
pub(crate) fn sha256_file(path: &Path) -> Result<(String, u64)> {
  let reading = || format!("reading {}", path.display());
  let mut file = std::fs::File::open(path).map_err(Error::io(reading()))?;
  let mut hasher = Sha256::new();
  let mut buffer = vec![0; 1 << 20];
  let mut length = 0;

  loop {
    let read = file.read(&mut buffer).map_err(Error::io(reading()))?;
    if read == 0 {
      break;
    }
    hasher.update(&buffer[..read]);
    length += read as u64;
  }
  Ok((format!("sha256:{}", hex(&hasher.finalize())), length))
}

fn hex(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The hex of a `sha256:<hex>` digest, if it is one.
pub fn sha256_hex(digest: &str) -> Option<&str> {
  digest.strip_prefix("sha256:").filter(|hex| {
    hex.len() == 64
      && hex
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
  })
}

/// Parses an image document, saying what it was when it isn't one.
pub(crate) fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T> {
  serde_json::from_slice(bytes).map_err(|error| Error::Invalid(format!("{what} is not valid: {error}")))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn chains_each_layer_to_those_beneath_it() {
    let config = ImageConfig {
      rootfs: RootFs {
        kind: "layers".into(),
        diff_ids: vec![sha256_digest(b"one"), sha256_digest(b"two")],
      },
      ..ImageConfig::default()
    };

    let chain = config.chain_ids();

    assert_eq!(chain[0], config.rootfs.diff_ids[0]);
    assert_eq!(
      chain[1],
      sha256_digest(format!("{} {}", chain[0], config.rootfs.diff_ids[1]).as_bytes())
    );
  }

  #[test]
  fn runs_the_entrypoint_then_the_command() {
    let config = ImageConfig {
      config: Some(RunConfig {
        entrypoint: Some(vec!["/bin/sh".into(), "-c".into()]),
        cmd: Some(vec!["echo $GREETING".into()]),
        env: vec!["GREETING=hello=world".into(), "PATH=/bin".into(), "broken".into()],
        working_dir: Some("/srv".into()),
        ..RunConfig::default()
      }),
      ..ImageConfig::default()
    };

    let process = config.process();

    assert_eq!(process.argv, ["/bin/sh", "-c", "echo $GREETING"]);
    assert_eq!(
      process.env,
      [
        ("GREETING".to_string(), "hello=world".to_string()),
        ("PATH".to_string(), "/bin".to_string())
      ]
    );
    assert_eq!(process.cwd.as_deref(), Some("/srv"));
    assert_eq!(ImageConfig::default().process(), Exec::default());
  }

  #[test]
  fn runs_images_of_its_os_and_architecture() {
    let here = Platform::default();
    let v8 = Platform {
      variant: Some("v8".into()),
      ..Platform::default()
    };
    let amd64 = Platform {
      architecture: "amd64".into(),
      ..Platform::default()
    };

    assert!(here.runs(&v8));
    assert!(v8.runs(&here));
    assert!(!here.runs(&amd64));
    assert_eq!(v8.to_string(), "freebsd/arm64/v8");
  }

  #[test]
  fn reads_the_freebsd_runtime_config() {
    let config: ImageConfig = parse(
      br#"{"created":"2026-06-12T09:52:54Z","architecture":"arm64","os":"freebsd","config":{"cmd":["/bin/sh"]},
          "rootfs":{"type":"layers","diff_ids":["sha256:6a43fd74a150299fd7f7319bcb751e513ba332088ef70c67a73ea31744884f9d"]},
          "history":[{"created":"2026-06-12T09:52:54Z","created_by":"make-oci-image.sh"}]}"#,
      "the config",
    )
    .unwrap();

    assert_eq!(config.platform(), Platform::default());
    assert_eq!(config.config.unwrap().cmd, Some(vec!["/bin/sh".to_string()]));
    assert_eq!(config.rootfs.diff_ids.len(), 1);
  }

  #[test]
  fn knows_a_sha256_digest() {
    let digest = sha256_digest(b"");

    assert_eq!(
      sha256_hex(&digest),
      Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(sha256_hex("sha256:E3B0"), None);
    assert_eq!(sha256_hex("sha512:00"), None);
  }
}
