use super::curl::{self, Auth, Request, Response};
use super::{ContentStore, Descriptor, Reference, media_type, sha256_file, sha256_hex};
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

/// 4 MiB: the distribution spec says registries should accept manifests at
/// least this large.
const MAX_MANIFEST: u64 = 4 << 20;
const ACCEPT_MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, \
                                application/vnd.oci.image.manifest.v1+json, \
                                application/vnd.docker.distribution.manifest.list.v2+json, \
                                application/vnd.docker.distribution.manifest.v2+json";

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

/// A distribution API client over curl(1), which gets tokens and passwords
/// on stdin rather than in its arguments.
#[derive(Debug, Default)]
pub struct RegistryClient {
  credentials: Option<Credentials>,
  /// Bearer tokens, keyed by `<API host>/<repository>` and whether they
  /// grant push.
  tokens: Mutex<HashMap<(String, bool), Secret>>,
}

impl RegistryClient {
  pub fn new(credentials: Option<Credentials>) -> Self {
    Self {
      credentials,
      tokens: Mutex::default(),
    }
  }

  /// Fetches the manifest or index `target`, a tag or digest, from
  /// `reference`'s repository into `store`, verifying it if `target` is a
  /// digest.
  pub fn fetch_manifest(&self, reference: &Reference, target: &str, store: &ContentStore) -> Result<Descriptor> {
    let partial = store.partial();
    let result = (|| {
      let response = self.get(
        reference,
        &format!("manifests/{target}"),
        Some(ACCEPT_MANIFESTS),
        &partial,
      )?;
      let (digest, size) = sha256_file(&partial)?;
      if size > MAX_MANIFEST {
        return Err(Error::Invalid(format!(
          "{reference}'s manifest {target} is {size} bytes, over the {MAX_MANIFEST}-byte limit"
        )));
      }
      if sha256_hex(target).is_some() && digest != target {
        return Err(Error::Checksum {
          path: partial.clone(),
          actual: digest,
          expected: target.to_string(),
        });
      }

      let bytes = std::fs::read(&partial).map_err(Error::io("reading a manifest"))?;
      let descriptor = Descriptor {
        media_type: media_type_of(response.header("content-type"), &bytes),
        digest,
        size,
        platform: None,
        annotations: Default::default(),
      };
      store.ingest_file(&partial, &descriptor)?;
      Ok(descriptor)
    })();

    let _ = std::fs::remove_file(&partial);
    result
  }

  pub fn fetch_blob(&self, reference: &Reference, descriptor: &Descriptor, store: &ContentStore) -> Result<()> {
    let partial = store.partial();
    let result = self
      .get(reference, &format!("blobs/{}", descriptor.digest), None, &partial)
      .and_then(|_| store.ingest_file(&partial, descriptor));

    let _ = std::fs::remove_file(&partial);
    result
  }

  /// Uploads `descriptor`'s blob unless a HEAD finds it in the repository,
  /// as a monolithic upload: a POST opens the session and one PUT sends the
  /// blob.
  pub fn push_blob(&self, reference: &Reference, descriptor: &Descriptor, store: &ContentStore) -> Result<()> {
    let path = format!("blobs/{}", descriptor.digest);
    let head = Request::new("HEAD", url(reference, &path));
    match self.send(reference, &head, true)?.status {
      200 => return Ok(()),
      404 => {}
      status => return Err(unexpected(&head, status, None)),
    }

    let post = Request::new("POST", url(reference, "blobs/uploads/"));
    let started = self.send(reference, &post, true)?;
    let location = started
      .header("location")
      .filter(|_| started.status == 202)
      .ok_or_else(|| unexpected(&post, started.status, None))?;
    let mut upload = url::Url::parse(&post.url)
      .and_then(|base| base.join(location))
      .map_err(|error| {
        Error::Guest(format!(
          "{} gave the upload location {location:?}: {error}",
          reference.domain
        ))
      })?;
    upload
      .query_pairs_mut()
      .append_pair("digest", &descriptor.digest);

    let blob = store.path(&descriptor.digest)?;
    let mut put = Request::new("PUT", upload.to_string());
    put.content_type = Some("application/octet-stream");
    put.upload = Some(&blob);
    // Credentials go only to the registry, not to an upload location on
    // another origin such as a storage service.
    let response = if same_origin(&post.url, &put.url) {
      self.send(reference, &put, true)?
    } else {
      curl::send(&put, &Auth::None)?
    };
    match response.status {
      201 => Ok(()),
      status => Err(unexpected(&put, status, None)),
    }
  }

  /// Uploads the manifest or index `descriptor` under `target`, a tag or its
  /// digest.
  pub fn push_manifest(
    &self,
    reference: &Reference,
    target: &str,
    descriptor: &Descriptor,
    store: &ContentStore,
  ) -> Result<()> {
    let document = store.path(&descriptor.digest)?;
    let response_body = store.partial();
    let mut put = Request::new("PUT", url(reference, &format!("manifests/{target}")));
    put.content_type = Some(&descriptor.media_type);
    put.upload = Some(&document);
    put.output = Some(&response_body);

    let result = self
      .send(reference, &put, true)
      .and_then(|response| match response.status {
        201 => Ok(()),
        status => Err(unexpected(&put, status, Some(&response_body))),
      });
    let _ = std::fs::remove_file(&response_body);
    result
  }

  /// GETs `path` under the repository into the file `body`, failing on any
  /// status but 200.
  fn get(&self, reference: &Reference, path: &str, accept: Option<&str>, body: &Path) -> Result<Response> {
    let mut get = Request::new("GET", url(reference, path));
    get.accept = accept;
    get.output = Some(body);
    let response = self.send(reference, &get, false)?;

    match response.status {
      200 => Ok(response),
      status => Err(unexpected(&get, status, Some(body))),
    }
  }

  /// Sends `request` with any cached token. On a 401, authenticates as the
  /// WWW-Authenticate challenge asks and retries once. The token's scope is
  /// pull, plus push if `push` is set.
  fn send(&self, reference: &Reference, request: &Request, push: bool) -> Result<Response> {
    let key = (format!("{}/{}", reference.api_host(), reference.repository), push);
    let cached = self
      .tokens
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .get(&key)
      .cloned();
    let auth = cached.map_or(Auth::None, Auth::Bearer);

    let response = curl::send(request, &auth)?;
    if response.status != 401 {
      return Ok(response);
    }
    let challenge = response
      .header("www-authenticate")
      .ok_or_else(|| unexpected(request, 401, request.output))?;
    let auth = self.authorize(reference, &key, challenge)?;
    curl::send(request, &auth)
  }

  /// The authorization a WWW-Authenticate challenge asks for: a bearer token
  /// from its realm, or basic auth with the credentials.
  fn authorize(&self, reference: &Reference, key: &(String, bool), challenge: &str) -> Result<Auth> {
    let (scheme, parameters) = parse_challenge(challenge);

    match scheme.to_ascii_lowercase().as_str() {
      "basic" => self
        .credentials
        .clone()
        .map(Auth::Basic)
        .ok_or_else(|| Error::Invalid(format!("{} wants an account", reference.domain))),
      "bearer" => {
        let url = token_url(reference, key.1, challenge, &parameters)?;
        self.fetch_token(reference, key, &url).map(Auth::Bearer)
      }
      _ => Err(Error::Invalid(format!(
        "{} asks for {scheme} authentication, which isn't supported",
        reference.domain
      ))),
    }
  }

  /// Fetches a bearer token from `url`, with basic auth if there are
  /// credentials, and caches it under `key`.
  fn fetch_token(&self, reference: &Reference, key: &(String, bool), url: &url::Url) -> Result<Secret> {
    let auth = self.credentials.clone().map_or(Auth::None, Auth::Basic);
    let body = curl::tempfile_path();
    let mut get = Request::new("GET", url.to_string());
    get.output = Some(&body);
    let response = curl::send(&get, &auth);
    let bytes = std::fs::read(&body).unwrap_or_default();
    let _ = std::fs::remove_file(&body);
    let response = response?;
    if response.status != 200 {
      return Err(Error::Command {
        command: format!("GET {url}"),
        failure: format!("HTTP {}: {}", response.status, snippet(&bytes)),
      });
    }

    let token: TokenResponse = super::parse(&bytes, "the registry's token")?;
    let token: Secret = token
      .token
      .or(token.access_token)
      .ok_or_else(|| Error::Guest(format!("{} sent no token", reference.domain)))?
      .into();
    self
      .tokens
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .insert(key.clone(), token.clone());
    Ok(token)
  }
}

/// The token request URL: a bearer challenge's `realm`, with its `service`
/// and `scope` as query parameters. Without a challenge scope, the scope is
/// `reference`'s repository with pull, plus push if `push` is set.
fn token_url(
  reference: &Reference,
  push: bool,
  challenge: &str,
  parameters: &HashMap<String, String>,
) -> Result<url::Url> {
  let realm = parameters
    .get("realm")
    .ok_or_else(|| Error::Guest(format!("{} named no token realm: {challenge}", reference.domain)))?;
  let actions = if push { "pull,push" } else { "pull" };
  let scope = format!("repository:{}:{actions}", reference.repository);
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

#[derive(serde::Deserialize)]
struct TokenResponse {
  token: Option<String>,
  access_token: Option<String>,
}

/// The `/v2/<repository>/<path>` URL.
fn url(reference: &Reference, path: &str) -> String {
  let scheme = if reference.is_loopback() { "http" } else { "https" };

  format!("{scheme}://{}/v2/{}/{path}", reference.api_host(), reference.repository)
}

fn same_origin(one: &str, other: &str) -> bool {
  match (url::Url::parse(one), url::Url::parse(other)) {
    (Ok(one), Ok(other)) => one.origin() == other.origin(),
    _ => false,
  }
}

/// The error for an unexpected `status`, quoting the start of `body`.
fn unexpected(request: &Request, status: u16, body: Option<&Path>) -> Error {
  let bytes = body
    .and_then(|body| std::fs::read(body).ok())
    .unwrap_or_default();

  Error::Command {
    command: format!("{} {}", request.method, request.url),
    failure: format!("HTTP {status}: {}", snippet(&bytes)),
  }
}

fn snippet(bytes: &[u8]) -> String {
  let text = String::from_utf8_lossy(&bytes[..bytes.len().min(400)]);

  text.trim().to_string()
}

/// Splits a WWW-Authenticate challenge, such as
/// `Bearer realm="https://ghcr.io/token",service="ghcr.io"`, into its scheme
/// and parameters, with the parameter names lowercased.
fn parse_challenge(challenge: &str) -> (String, HashMap<String, String>) {
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

/// A fetched manifest's media type: the Content-Type if it is a known type,
/// else the document's `mediaType`, else an index if it has `manifests` and
/// a manifest if not.
fn media_type_of(content_type: Option<&str>, bytes: &[u8]) -> String {
  let known = [
    media_type::INDEX,
    media_type::MANIFEST,
    media_type::DOCKER_MANIFEST_LIST,
    media_type::DOCKER_MANIFEST,
  ];
  let header = content_type.map(|value| value.split(';').next().unwrap_or_default().trim());
  if let Some(header) = header.filter(|header| known.contains(header)) {
    return header.to_string();
  }

  #[derive(serde::Deserialize)]
  #[serde(rename_all = "camelCase")]
  struct Peek {
    media_type: Option<String>,
    manifests: Option<serde::de::IgnoredAny>,
  }
  match serde_json::from_slice::<Peek>(bytes) {
    Ok(Peek {
      media_type: Some(media_type),
      ..
    }) => media_type,
    Ok(Peek { manifests: Some(_), .. }) => media_type::INDEX.to_string(),
    _ => media_type::MANIFEST.to_string(),
  }
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
  fn debugs_without_its_secrets() {
    let client = RegistryClient::new(Some(Credentials {
      username: "someone".into(),
      password: "hunter2".into(),
    }));
    client
      .tokens
      .lock()
      .unwrap()
      .insert(("ghcr.io/a/b".into(), true), "a-token".into());

    let debugged = format!("{client:?}");

    assert!(
      debugged.contains("someone") && debugged.contains("ghcr.io/a/b"),
      "{debugged}"
    );
    assert!(
      !debugged.contains("hunter2") && !debugged.contains("a-token"),
      "{debugged}"
    );
    assert_eq!(Secret::from("hunter2").to_string(), "********");
  }

  #[test]
  fn asks_for_a_token_to_the_repository() {
    let reference = Reference::parse("ghcr.io/a/b").unwrap();
    let (_, parameters) = parse_challenge(r#"Bearer realm="https://ghcr.io/token",service="ghcr.io""#);

    assert_eq!(
      token_url(&reference, true, "", &parameters)
        .unwrap()
        .as_str(),
      "https://ghcr.io/token?service=ghcr.io&scope=repository%3Aa%2Fb%3Apull%2Cpush"
    );
  }

  #[test]
  fn tells_an_index_from_a_manifest() {
    assert_eq!(
      media_type_of(Some("application/vnd.oci.image.index.v1+json; charset=utf-8"), b"{}"),
      media_type::INDEX
    );
    assert_eq!(
      media_type_of(Some("application/json"), br#"{"manifests":[]}"#),
      media_type::INDEX
    );
    assert_eq!(
      media_type_of(
        None,
        br#"{"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}"#
      ),
      media_type::DOCKER_MANIFEST
    );
    assert_eq!(media_type_of(None, br#"{"layers":[]}"#), media_type::MANIFEST);
  }
}
