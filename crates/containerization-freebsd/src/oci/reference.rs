use super::sha256_hex;
use crate::error::{Error, Result};
use std::fmt;
use std::str::FromStr;

const DOCKER_HUB: &str = "docker.io";

/// An image's name, and the tag or digest that picks a version of it, as
/// Docker normalizes them: `alpine` is `docker.io/library/alpine:latest`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Reference {
  /// The registry, such as `ghcr.io` or `localhost:5000`.
  pub domain: String,
  /// Such as `freebsd/freebsd-runtime`.
  pub repository: String,
  pub tag: Option<String>,
  /// Such as `sha256:…`; only sha256 is supported.
  pub digest: Option<String>,
}

impl Reference {
  pub fn parse(text: &str) -> Result<Self> {
    let invalid = |why: &str| Error::Invalid(format!("{text:?} is not an image reference: {why}"));

    let (rest, digest) = match text.split_once('@') {
      Some((rest, digest)) => (rest, Some(digest)),
      None => (text, None),
    };
    let last_slash = rest.rfind('/').map_or(0, |index| index + 1);
    let (name, tag) = match rest[last_slash..].rfind(':') {
      Some(colon) => (&rest[..last_slash + colon], Some(&rest[last_slash + colon + 1..])),
      None => (rest, None),
    };

    let (domain, repository) = match name.split_once('/') {
      Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => (first, rest.to_string()),
      _ if name.contains('/') => (DOCKER_HUB, name.to_string()),
      _ => (DOCKER_HUB, format!("library/{name}")),
    };

    if domain.is_empty()
      || !domain
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-:[]".contains(&byte))
    {
      return Err(invalid("its registry is not a host name"));
    }
    if !repository.split('/').all(component) {
      return Err(invalid(
        "its name's parts must be lowercase letters and digits, joined by '.', '_' or '-'",
      ));
    }
    if let Some(tag) = tag
      && !valid_tag(tag)
    {
      return Err(invalid("its tag must be up to 128 letters, digits, '_', '.' and '-'"));
    }
    if let Some(digest) = digest
      && sha256_hex(digest).is_none()
    {
      return Err(invalid("its digest must be sha256:<64 lowercase hex digits>"));
    }

    Ok(Self {
      domain: domain.to_string(),
      repository,
      tag: tag
        .map(str::to_string)
        .or_else(|| digest.is_none().then(|| "latest".to_string())),
      digest: digest.map(str::to_string),
    })
  }

  /// What the registry is asked for: the digest if there is one, else the tag.
  pub fn target(&self) -> &str {
    self
      .digest
      .as_deref()
      .or(self.tag.as_deref())
      .unwrap_or("latest")
  }

  /// The host the registry's API answers at.
  pub(crate) fn registry(&self) -> &str {
    if self.domain == DOCKER_HUB {
      "registry-1.docker.io"
    } else {
      &self.domain
    }
  }

  /// Whether the registry is this machine's, reached over plain HTTP.
  pub(crate) fn local(&self) -> bool {
    let host = self
      .domain
      .rsplit_once(':')
      .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
      .map_or(self.domain.as_str(), |(host, _)| host);

    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
  }
}

/// A part of a name: lowercase letters and digits, separated by one `.` or
/// `_`, two `_`, or any number of `-`.
fn component(part: &str) -> bool {
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
  type Err = Error;

  fn from_str(text: &str) -> Result<Self> {
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
    assert_eq!(Reference::parse("alpine").unwrap().registry(), "registry-1.docker.io");
  }

  #[test]
  fn reaches_only_this_machines_registries_over_http() {
    assert!(Reference::parse("localhost:5000/a").unwrap().local());
    assert!(Reference::parse("127.0.0.1:5000/a").unwrap().local());
    assert!(!Reference::parse("ghcr.io/a").unwrap().local());
    assert!(!Reference::parse("localhost.example.com/a").unwrap().local());
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
