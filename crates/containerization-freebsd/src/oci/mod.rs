//! Host-side OCI support: image references, image-spec documents, a
//! distribution API client, and a content-addressable store.

mod auth;
mod content;
mod reference;
mod registry;

pub use crate::digest::Digest;
pub use auth::{Credentials, Secret};
pub use content::ContentStore;
pub(crate) use content::{BLOBS, blob_path};
pub use reference::Reference;
pub use registry::RegistryClient;

use crate::agent::{Exec, User};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod media_type {
  pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";
  pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
  pub const CONFIG: &str = "application/vnd.oci.image.config.v1+json";
  pub const LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
  pub const LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
  pub const LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
  pub const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
  pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
  pub const DOCKER_LAYER: &str = "application/vnd.docker.image.rootfs.diff.tar";
  pub const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

  /// The index and manifest types a registry may answer a manifest request
  /// with.
  pub const MANIFESTS: [&str; 4] = [INDEX, MANIFEST, DOCKER_MANIFEST_LIST, DOCKER_MANIFEST];
}

/// The index annotation naming the reference an entry was pulled or tagged
/// as.
pub const REF_NAME: &str = "org.opencontainers.image.ref.name";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
  pub media_type: String,
  pub digest: Digest,
  pub size: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub platform: Option<Platform>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub annotations: BTreeMap<String, String>,
}

impl Descriptor {
  /// A descriptor with no platform or annotations.
  pub fn new(media_type: impl Into<String>, digest: Digest, size: u64) -> Self {
    Self {
      media_type: media_type.into(),
      digest,
      size,
      platform: None,
      annotations: BTreeMap::new(),
    }
  }

  /// Whether this names a platform whose images run on `platform`.
  pub fn runs_on(&self, platform: &Platform) -> bool {
    self.platform.as_ref().is_some_and(|own| platform.runs(own))
  }

  /// Whether this names an image index or a Docker manifest list.
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
  /// The guest's platform.
  fn default() -> Self {
    Self {
      architecture: "arm64".into(),
      os: "freebsd".into(),
      variant: None,
    }
  }
}

impl Platform {
  /// Whether an image built for `other` runs on this platform. OS and
  /// architecture must match; variants must match only if both are set.
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

/// An image index: one manifest descriptor per platform.
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

/// An image manifest: one platform's config and layers, base layer first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
  pub schema_version: u32,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub media_type: Option<String>,
  pub config: Descriptor,
  pub layers: Vec<Descriptor>,
}

impl Manifest {
  /// The config, then the layers.
  pub fn blobs(&self) -> impl Iterator<Item = &Descriptor> {
    std::iter::once(&self.config).chain(&self.layers)
  }
}

/// An index or manifest, chosen by the descriptor's media type.
pub(crate) enum Document {
  Index(Index),
  Manifest(Manifest),
}

/// An image config: the default process and the layers' diff IDs.
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

/// The config's execution defaults. The spec's keys are PascalCase, but Go's
/// encoding/json matches keys case-insensitively and FreeBSD's own images
/// write `cmd`, so lowercase and camelCase spellings are accepted too.
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
  pub diff_ids: Vec<Digest>,
}

impl ImageConfig {
  /// The container's default process: `Entrypoint` then `Cmd` as argv, with
  /// `Env`, `WorkingDir` and `User`. `User` is `user` or `user:group`, each a
  /// name or a numeric ID.
  pub fn process(&self) -> Exec {
    let run = self.config.clone().unwrap_or_default();
    let user = run
      .user
      .filter(|user| !user.is_empty())
      .map(|user| match user.split_once(':') {
        Some((name, group)) => User {
          name: name.to_string(),
          group: Some(group.to_string()),
          groups: Vec::new(),
        },
        None => User {
          name: user,
          ..User::default()
        },
      });

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
      user,
      ..Exec::default()
    }
  }

  pub fn platform(&self) -> Platform {
    Platform {
      architecture: self.architecture.clone(),
      os: self.os.clone(),
      variant: self.variant.clone(),
    }
  }

  /// Each layer's chain ID, per the image spec: the base layer's is its diff
  /// ID, and each later one is the sha256 of `<parent chain ID> <diff ID>`.
  /// A chain ID thus identifies a layer together with every layer beneath
  /// it.
  pub fn chain_ids(&self) -> Vec<Digest> {
    let mut chain: Vec<Digest> = Vec::with_capacity(self.rootfs.diff_ids.len());

    for diff_id in &self.rootfs.diff_ids {
      let next = match chain.last() {
        Some(below) => Digest::of(format!("{below} {diff_id}").as_bytes()),
        None => diff_id.clone(),
      };
      chain.push(next);
    }
    chain
  }
}

/// Parses an image document; errors name it as `what`.
pub(crate) fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T> {
  serde_json::from_slice(bytes).map_err(|error| Error::Invalid(format!("{what} is not valid: {error}")))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_an_index_with_a_digest_it_cannot_use() {
    let index: Index = parse(
      br#"{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha512:00ff","size":1}]}"#,
      "an index",
    )
    .unwrap();

    assert_eq!(index.manifests[0].digest.sha256_hex(), None);
  }

  #[test]
  fn chains_each_layer_to_those_beneath_it() {
    let config = ImageConfig {
      rootfs: RootFs {
        kind: "layers".into(),
        diff_ids: vec![Digest::of(b"one"), Digest::of(b"two")],
      },
      ..ImageConfig::default()
    };

    let chain = config.chain_ids();

    assert_eq!(chain[0], config.rootfs.diff_ids[0]);
    assert_eq!(
      chain[1],
      Digest::of(format!("{} {}", chain[0], config.rootfs.diff_ids[1]).as_bytes())
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
  fn runs_as_the_images_user_and_group() {
    let user = |user: &str| {
      ImageConfig {
        config: Some(RunConfig {
          user: Some(user.into()),
          ..RunConfig::default()
        }),
        ..ImageConfig::default()
      }
      .process()
      .user
    };

    assert_eq!(
      user("www"),
      Some(User {
        name: "www".into(),
        ..User::default()
      })
    );
    assert_eq!(
      user("1000:wheel"),
      Some(User {
        name: "1000".into(),
        group: Some("wheel".into()),
        groups: Vec::new(),
      })
    );
    assert_eq!(user(""), None);
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
}
