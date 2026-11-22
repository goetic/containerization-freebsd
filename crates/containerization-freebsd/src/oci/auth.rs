//! Registry authentication: credentials, the authorization sent with each
//! request, and the WWW-Authenticate challenges that ask for it.

use super::Reference;
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::fmt;

/// A password or token, redacted by `Display` and `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
  pub fn expose(&self) -> &str {
    &self.0
  }
}

impl From<String> for Secret {
  fn from(text: String) -> Self {
    Self(text)
  }
}

impl From<&str> for Secret {
  fn from(text: &str) -> Self {
    Self(text.to_string())
  }
}

impl fmt::Display for Secret {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("********")
  }
}

impl fmt::Debug for Secret {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Display::fmt(self, formatter)
  }
}

/// Sent as basic auth to the registry or to its token realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
  pub username: String,
  pub password: Secret,
}

#[derive(Clone, Debug)]
pub(super) enum Auth {
  None,
  Bearer(Secret),
  Basic(Credentials),
}

/// What a request does to a repository, and so what its token must grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Access {
  Pull,
  /// Pushing also reads, as a HEAD that checks for a blob does.
  Push,
}

impl Access {
  /// The actions a token scope names for this access.
  fn actions(self) -> &'static str {
    match self {
      Self::Pull => "pull",
      Self::Push => "pull,push",
    }
  }
}

#[derive(serde::Deserialize)]
pub(super) struct TokenResponse {
  pub(super) token: Option<String>,
  pub(super) access_token: Option<String>,
}

/// The token request URL: a bearer challenge's `realm`, with its `service`
/// and `scope` as query parameters. Without a challenge scope, the scope is
/// `reference`'s repository with the actions `access` needs.
pub(super) fn token_url(
  reference: &Reference,
  access: Access,
  challenge: &str,
  parameters: &HashMap<String, String>,
) -> Result<url::Url> {
  let realm = parameters
    .get("realm")
    .ok_or_else(|| Error::Guest(format!("{} named no token realm: {challenge}", reference.domain)))?;
  let scope = format!("repository:{}:{}", reference.repository, access.actions());
  let mut url = url::Url::parse(realm)
    .map_err(|error| Error::Invalid(format!("{}'s token realm {realm:?}: {error}", reference.domain)))?;

  let mut query = url.query_pairs_mut();
  if let Some(service) = parameters.get("service") {
    query.append_pair("service", service);
  }
  query.append_pair("scope", parameters.get("scope").unwrap_or(&scope));
  drop(query);
  Ok(url)
}

/// Splits a WWW-Authenticate challenge, such as
/// `Bearer realm="https://ghcr.io/token",service="ghcr.io"`, into its scheme
/// and parameters, with the parameter names lowercased.
pub(super) fn parse_challenge(challenge: &str) -> (String, HashMap<String, String>) {
  let challenge = challenge.trim();
  let (scheme, rest) = challenge.split_once(' ').unwrap_or((challenge, ""));
  let mut parameters = HashMap::new();
  let mut characters = rest.chars().peekable();

  loop {
    let key: String = characters
      .by_ref()
      .skip_while(|character| *character == ',' || character.is_whitespace())
      .take_while(|character| *character != '=')
      .collect();
    if key.is_empty() {
      break;
    }

    let mut value = String::new();
    if characters.peek() == Some(&'"') {
      characters.next();
      while let Some(character) = characters.next() {
        match character {
          '\\' => value.extend(characters.next()),
          '"' => break,
          character => value.push(character),
        }
      }
    } else {
      value = characters
        .by_ref()
        .take_while(|character| *character != ',')
        .collect();
    }
    parameters.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
  }
  (scheme.to_string(), parameters)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_a_bearer_challenge() {
    let (scheme, parameters) = parse_challenge(
      r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:freebsd/freebsd-runtime:pull""#,
    );

    assert_eq!(scheme, "Bearer");
    assert_eq!(parameters["realm"], "https://ghcr.io/token");
    assert_eq!(parameters["service"], "ghcr.io");
    assert_eq!(parameters["scope"], "repository:freebsd/freebsd-runtime:pull");
  }

  #[test]
  fn reads_unquoted_and_escaped_parameters() {
    let (scheme, parameters) = parse_challenge(r#"Basic realm="a \"quoted\" realm", charset=UTF-8"#);

    assert_eq!(scheme, "Basic");
    assert_eq!(parameters["realm"], r#"a "quoted" realm"#);
    assert_eq!(parameters["charset"], "UTF-8");
  }

  #[test]
  fn asks_for_a_token_to_the_repository() {
    let reference = Reference::parse("ghcr.io/a/b").unwrap();
    let (_, parameters) = parse_challenge(r#"Bearer realm="https://ghcr.io/token",service="ghcr.io""#);

    assert_eq!(
      token_url(&reference, Access::Push, "", &parameters)
        .unwrap()
        .as_str(),
      "https://ghcr.io/token?service=ghcr.io&scope=repository%3Aa%2Fb%3Apull%2Cpush"
    );
  }
}
