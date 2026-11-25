use crate::{digest, error};
use std::fmt;
use std::str::FromStr;

const DOCKER_HUB: &str = "docker.io";
const LEGACY_DOCKER_HUB: &str = "index.docker.io";

/// An image name plus the tag or digest that selects a version, normalized as
/// Docker does: `alpine`, `docker.io/alpine` and `index.docker.io/alpine` all
/// become `docker.io/library/alpine:latest`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Reference {
  domain: String,
  repository: String,
  tag: Option<String>,
  digest: Option<digest::Digest>,
}

impl Reference {
  pub fn parse(text: &str) -> error::Result<Self> {
    let invalid = |why: &str| error::Error::Invalid(format!("{text:?} is not an image reference: {why}"));

    let (rest, digest) = match text.split_once('@') {
      Some((rest, digest)) => (rest, Some(digest)),
      None => (text, None),
    };
    let last_slash = rest.rfind('/').map_or(0, |index| index + 1);
    let (name, tag) = match rest[last_slash..].rfind(':') {
      Some(colon) => (&rest[..last_slash + colon], Some(&rest[last_slash + colon + 1..])),
      None => (rest, None),
    };

    let (domain, remainder) = match name.split_once('/') {
      Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => (first, rest),
      _ => (DOCKER_HUB, name),
    };
    let domain = if domain == LEGACY_DOCKER_HUB {
      DOCKER_HUB
    } else {
      domain
    };
    let repository = if domain == DOCKER_HUB && !remainder.contains('/') {
      format!("library/{remainder}")
    } else {
      remainder.to_string()
    };

    if domain.is_empty()
      || !domain
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-:[]".contains(&byte))
    {
      return Err(invalid("its registry is not a host name"));
    }
    if !repository.split('/').all(valid_component) {
      return Err(invalid(
        "its name's parts must be lowercase letters and digits, joined by '.', '_' or '-'",
      ));
    }
    if let Some(tag) = tag
      && !valid_tag(tag)
    {
      return Err(invalid("its tag must be up to 128 letters, digits, '_', '.' and '-'"));
    }
    let digest = digest
      .map(|digest| {
        digest
          .parse::<digest::Digest>()
          .ok()
          .filter(|digest| digest.sha256_hex().is_some())
          .ok_or_else(|| invalid("its digest must be sha256:<64 lowercase hex digits>"))
      })
      .transpose()?;

    Ok(Self {
      domain: domain.to_string(),
      repository,
      tag: tag
        .map(str::to_string)
        .or_else(|| digest.is_none().then(|| "latest".to_string())),
      digest,
    })
  }

  /// The registry, such as `ghcr.io` or `localhost:5000`.
  pub fn domain(&self) -> &str {
    &self.domain
  }

  /// The repository, such as `freebsd/freebsd-runtime`.
  pub fn repository(&self) -> &str {
    &self.repository
  }

  /// The tag, which is `latest` if the reference has neither a tag nor a
  /// digest.
  pub fn tag(&self) -> Option<&str> {
    self.tag.as_deref()
  }

  /// The digest, such as `sha256:…`. Only sha256 is supported.
  pub fn digest(&self) -> Option<&digest::Digest> {
    self.digest.as_ref()
  }

  /// The manifest reference to request: the digest if set, else the tag.
  pub fn target(&self) -> &str {
    self
      .digest
      .as_ref()
      .map(digest::Digest::as_str)
      .or(self.tag.as_deref())
      .unwrap_or("latest")
  }

  /// Differs from `domain` for Docker Hub.
  pub(crate) fn api_host(&self) -> &str {
    if self.domain == DOCKER_HUB {
      "registry-1.docker.io"
    } else {
      &self.domain
    }
  }

  /// Loopback registries are reached over plain HTTP.
  pub(crate) fn is_loopback(&self) -> bool {
    let host = self
      .domain
      .rsplit_once(':')
      .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
      .map_or(self.domain.as_str(), |(host, _)| host);

    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
  }
}

/// Repository path components are lowercase alphanumerics separated by one
/// `.`, one or two `_`, or any number of `-`.
fn valid_component(part: &str) -> bool {
  let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
  let bytes = part.as_bytes();

  if bytes.is_empty() || !alphanumeric(bytes[0]) || !alphanumeric(bytes[bytes.len() - 1]) {
    return false;
  }
  part
    .split(|character: char| character.is_ascii_lowercase() || character.is_ascii_digit())
    .all(|separator| {
      separator.is_empty() || matches!(separator, "." | "_" | "__") || separator.bytes().all(|byte| byte == b'-')
    })
}

fn valid_tag(tag: &str) -> bool {
  let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';

  tag.len() <= 128
    && tag.bytes().next().is_some_and(word)
    && tag
      .bytes()
      .all(|byte| word(byte) || byte == b'.' || byte == b'-')
}

impl FromStr for Reference {
  type Err = error::Error;

  fn from_str(text: &str) -> error::Result<Self> {
    Self::parse(text)
  }
}

impl fmt::Display for Reference {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{}/{}", self.domain, self.repository)?;
    if let Some(tag) = &self.tag {
      write!(formatter, ":{tag}")?;
    }
    if let Some(digest) = &self.digest {
      write!(formatter, "@{digest}")?;
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const DIGEST: &str = "sha256:6b3b15d0fc37ca45a2636f3aaea695bfb42cc1b02c895ee939bdfef87521fbd7";

  fn normalized(text: &str) -> String {
    Reference::parse(text).unwrap().to_string()
  }

  #[test]
  fn normalizes_as_docker_does() {
    assert_eq!(normalized("alpine"), "docker.io/library/alpine:latest");
    assert_eq!(normalized("docker.io/alpine"), "docker.io/library/alpine:latest");
    assert_eq!(normalized("index.docker.io/alpine:3"), "docker.io/library/alpine:3");
    assert_eq!(
      normalized("index.docker.io/freebsd/freebsd-runtime"),
      "docker.io/freebsd/freebsd-runtime:latest"
    );
    assert_eq!(
      normalized("freebsd/freebsd-runtime:15.1"),
      "docker.io/freebsd/freebsd-runtime:15.1"
    );
    assert_eq!(
      normalized("ghcr.io/freebsd/freebsd-runtime:15.1"),
      "ghcr.io/freebsd/freebsd-runtime:15.1"
    );
    assert_eq!(
      normalized(&format!("localhost:5000/a/b@{DIGEST}")),
      format!("localhost:5000/a/b@{DIGEST}")
    );
    assert_eq!(
      normalized(&format!("ghcr.io/a/b:t@{DIGEST}")),
      format!("ghcr.io/a/b:t@{DIGEST}")
    );
  }

  #[test]
  fn asks_for_the_digest_over_the_tag() {
    let pinned = Reference::parse(&format!("ghcr.io/a/b:t@{DIGEST}")).unwrap();
    let tagged = Reference::parse("ghcr.io/a/b:t").unwrap();

    assert_eq!(pinned.target(), DIGEST);
    assert_eq!(tagged.target(), "t");
    assert_eq!(Reference::parse("alpine").unwrap().api_host(), "registry-1.docker.io");
  }

  #[test]
  fn reaches_only_this_machines_registries_over_http() {
    assert!(Reference::parse("localhost:5000/a").unwrap().is_loopback());
    assert!(Reference::parse("127.0.0.1:5000/a").unwrap().is_loopback());
    assert!(!Reference::parse("ghcr.io/a").unwrap().is_loopback());
    assert!(
      !Reference::parse("localhost.example.com/a")
        .unwrap()
        .is_loopback()
    );
  }

  #[test]
  fn refuses_what_is_not_a_reference() {
    for text in [
      "",
      "Upper/case",
      "a b",
      "ghcr.io/",
      "ghcr.io//a",
      "a:",
      "a@sha256:zz",
      "a-/b",
      "a..b",
      "a:-tag",
    ] {
      assert!(Reference::parse(text).is_err(), "{text:?}");
    }
  }
}
