use super::{ContentStore, Descriptor, Reference, media_type, sha256_file, sha256_hex};
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

/// Manifests and indexes are small; anything bigger is refused.
const MAX_MANIFEST: u64 = 4 << 20;
const ACCEPT_MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, \
                                application/vnd.oci.image.manifest.v1+json, \
                                application/vnd.docker.distribution.manifest.list.v2+json, \
                                application/vnd.docker.distribution.manifest.v2+json";

/// A password or token, which prints as asterisks, whether displayed or
/// debugged; `expose` gives its text.
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

/// A registry account, for the registries that want one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
  pub username: String,
  pub password: Secret,
}

/// Pulls from and pushes to registries over the OCI distribution API,
/// through curl(1). Tokens and passwords reach curl on its stdin, never its
/// arguments.
#[derive(Debug, Default)]
pub struct RegistryClient {
  credentials: Option<Credentials>,
  /// The bearer token for each registry and repository, to pull or to
  /// push.
  tokens: Mutex<HashMap<(String, bool), Secret>>,
}

#[derive(Clone, Debug)]
enum Auth {
  None,
  Bearer(Secret),
  Basic(Credentials),
}

/// What curl is to send.
struct Request<'a> {
  method: &'a str,
  url: String,
  accept: Option<&'a str>,
  content_type: Option<&'a str>,
  /// A file to send as the body.
  upload: Option<&'a Path>,
  /// Where the response's body goes.
  output: Option<&'a Path>,
}

impl<'a> Request<'a> {
  fn new(method: &'a str, url: String) -> Self {
    Self {
      method,
      url,
      accept: None,
      content_type: None,
      upload: None,
      output: None,
    }
  }
}

struct Response {
  status: u16,
  /// The last response's, after redirects; names lowercase.
  headers: Vec<(String, String)>,
}

impl Response {
  fn header(&self, name: &str) -> Option<&str> {
    self
      .headers
      .iter()
      .find(|(key, _)| key == name)
      .map(|(_, value)| value.as_str())
  }
}

impl RegistryClient {
  pub fn new(credentials: Option<Credentials>) -> Self {
    Self {
      credentials,
      tokens: Mutex::default(),
    }
  }

  /// Fetches the manifest or index `target`, a tag or digest, of
  /// `reference`'s repository into `store`.
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

  /// Fetches `descriptor`'s blob from `reference`'s repository into `store`.
  pub fn fetch_blob(&self, reference: &Reference, descriptor: &Descriptor, store: &ContentStore) -> Result<()> {
    let partial = store.partial();
    let result = self
      .get(reference, &format!("blobs/{}", descriptor.digest), None, &partial)
      .and_then(|_| store.ingest_file(&partial, descriptor));

    let _ = std::fs::remove_file(&partial);
    result
  }

  /// Uploads `descriptor`'s blob from `store` to `reference`'s repository,
  /// unless the repository has it: in one PUT, after a POST starts the
  /// upload.
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
    // A location elsewhere, such as storage, gets no credentials.
    let response = if same_origin(&post.url, &put.url) {
      self.send(reference, &put, true)?
    } else {
      curl(&put, &Auth::None)?
    };
    match response.status {
      201 => Ok(()),
      status => Err(unexpected(&put, status, None)),
    }
  }

  /// Uploads the manifest or index `descriptor` from `store` to
  /// `reference`'s repository as `target`, a tag or its digest.
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

  /// GETs `path` under the repository into `body`; fails unless it answers
  /// 200.
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

  /// Sends `request` to `reference`'s registry, authenticating as it asks,
  /// to pull from its repository or, with `push`, to push to it too.
  fn send(&self, reference: &Reference, request: &Request, push: bool) -> Result<Response> {
    let key = (format!("{}/{}", reference.registry(), reference.repository), push);
    let cached = self
      .tokens
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .get(&key)
      .cloned();
    let auth = cached.map_or(Auth::None, Auth::Bearer);

    let response = curl(request, &auth)?;
    if response.status != 401 {
      return Ok(response);
    }
    let challenge = response
      .header("www-authenticate")
      .ok_or_else(|| unexpected(request, 401, request.output))?;
    let auth = self.authorize(reference, &key, challenge)?;
    curl(request, &auth)
  }

  /// What the registry's challenge asks for: a bearer token from its realm,
  /// or the account itself.
  fn authorize(&self, reference: &Reference, key: &(String, bool), challenge: &str) -> Result<Auth> {
    let (scheme, parameters) = parse_challenge(challenge);

    match scheme.to_ascii_lowercase().as_str() {
      "basic" => self
        .credentials
        .clone()
        .map(Auth::Basic)
        .ok_or_else(|| Error::Invalid(format!("{} wants an account", reference.domain))),
      "bearer" => {
        let realm = parameters
          .get("realm")
          .ok_or_else(|| Error::Guest(format!("{} named no token realm: {challenge}", reference.domain)))?;
        let actions = if key.1 { "pull,push" } else { "pull" };
        let scope = format!("repository:{}:{actions}", reference.repository);
        let mut url = url::Url::parse(realm)
          .map_err(|error| Error::Invalid(format!("{}'s token realm {realm:?}: {error}", reference.domain)))?;
        {
          let mut query = url.query_pairs_mut();
          if let Some(service) = parameters.get("service") {
            query.append_pair("service", service);
          }
          query.append_pair("scope", parameters.get("scope").unwrap_or(&scope));
        }

        let auth = self.credentials.clone().map_or(Auth::None, Auth::Basic);
        let body = tempfile_path();
        let mut get = Request::new("GET", url.to_string());
        get.output = Some(&body);
        let response = curl(&get, &auth);
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
        Ok(Auth::Bearer(token))
      }
      _ => Err(Error::Invalid(format!(
        "{} asks for {scheme} authentication, which isn't supported",
        reference.domain
      ))),
    }
  }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
  token: Option<String>,
  access_token: Option<String>,
}

/// The URL of `path` under `reference`'s repository.
fn url(reference: &Reference, path: &str) -> String {
  let scheme = if reference.local() { "http" } else { "https" };

  format!("{scheme}://{}/v2/{}/{path}", reference.registry(), reference.repository)
}

fn same_origin(one: &str, other: &str) -> bool {
  match (url::Url::parse(one), url::Url::parse(other)) {
    (Ok(one), Ok(other)) => one.origin() == other.origin(),
    _ => false,
  }
}

/// Runs curl, following redirects.
fn curl(request: &Request, auth: &Auth) -> Result<Response> {
  let url = &request.url;
  let headers = tempfile_path();
  let mut config = format!(
    "url = {}\ndump-header = {}\nlocation\nsilent\nshow-error\nretry = 3\nwrite-out = \"%{{http_code}}\"\n",
    quote(url),
    quote(&headers.to_string_lossy())
  );
  match (request.method, request.upload) {
    ("HEAD", _) => config.push_str("head\n"),
    // Without waiting for a 100 Continue.
    (_, Some(upload)) => config.push_str(&format!(
      "upload-file = {}\nrequest = {}\nheader = \"Expect:\"\n",
      quote(&upload.to_string_lossy()),
      quote(request.method)
    )),
    ("GET", None) => {}
    (method, None) => config.push_str(&format!("request = {}\ndata-binary = \"\"\n", quote(method))),
  }
  // Stdout carries only the status.
  let output = request.output.unwrap_or(Path::new("/dev/null"));
  config.push_str(&format!("output = {}\n", quote(&output.to_string_lossy())));
  if let Some(accept) = request.accept {
    config.push_str(&format!("header = {}\n", quote(&format!("Accept: {accept}"))));
  }
  if let Some(content_type) = request.content_type {
    config.push_str(&format!(
      "header = {}\n",
      quote(&format!("Content-Type: {content_type}"))
    ));
  }
  match auth {
    Auth::None => {}
    Auth::Bearer(token) => config.push_str(&format!(
      "header = {}\n",
      quote(&format!("Authorization: Bearer {}", token.expose()))
    )),
    Auth::Basic(credentials) => config.push_str(&format!(
      "user = {}\n",
      quote(&format!("{}:{}", credentials.username, credentials.password.expose()))
    )),
  }

  let command = || format!("curl {} {url}", request.method);
  let failed = |failure: String| Error::Command {
    command: command(),
    failure,
  };
  let result = (|| {
    let mut child = Command::new("curl")
      .args(["--config", "-"])
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .map_err(|error| failed(error.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
      stdin
        .write_all(config.as_bytes())
        .map_err(|error| failed(error.to_string()))?;
    }
    let output = child
      .wait_with_output()
      .map_err(|error| failed(error.to_string()))?;
    if !output.status.success() {
      return Err(failed(format!(
        "exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
      )));
    }

    let status = String::from_utf8_lossy(&output.stdout)
      .trim()
      .parse()
      .map_err(|_| failed("wrote no HTTP status".to_string()))?;
    let dumped = std::fs::read_to_string(&headers).unwrap_or_default();
    Ok(Response {
      status,
      headers: last_headers(&dumped),
    })
  })();

  let _ = std::fs::remove_file(&headers);
  result
}

/// The error for `request` answering `status`, with a snippet of `body`.
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

/// A path in the temporary directory for one curl run's scratch file.
fn tempfile_path() -> std::path::PathBuf {
  use std::sync::atomic::{AtomicU64, Ordering};
  static NEXT: AtomicU64 = AtomicU64::new(0);

  std::env::temp_dir().join(format!(
    "containerization-freebsd-curl-{}-{}",
    std::process::id(),
    NEXT.fetch_add(1, Ordering::Relaxed)
  ))
}

/// A string as curl's config file quotes it.
fn quote(value: &str) -> String {
  let mut quoted = String::from("\"");

  for character in value.chars() {
    match character {
      '"' => quoted.push_str("\\\""),
      '\\' => quoted.push_str("\\\\"),
      '\n' => quoted.push_str("\\n"),
      '\r' => quoted.push_str("\\r"),
      '\t' => quoted.push_str("\\t"),
      character => quoted.push(character),
    }
  }
  quoted.push('"');
  quoted
}

/// The headers of the last response curl dumped: after any redirects.
fn last_headers(dumped: &str) -> Vec<(String, String)> {
  let block = dumped
    .split("\r\n\r\n")
    .filter(|block| block.trim_start().starts_with("HTTP/"))
    .last()
    .unwrap_or_default();

  block
    .lines()
    .skip(1)
    .filter_map(|line| line.split_once(':'))
    .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
    .collect()
}

/// A WWW-Authenticate challenge's scheme and parameters, such as
/// `Bearer realm="https://ghcr.io/token",service="ghcr.io"`.
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

/// A manifest's media type: the registry's Content-Type, or failing that the
/// document's own `mediaType`, or failing that whether it lists manifests.
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
  fn quotes_for_curls_config() {
    assert_eq!(quote(r#"pa"ss\word"#), r#""pa\"ss\\word""#);
  }

  #[test]
  fn reads_the_headers_after_redirects() {
    let dumped = "HTTP/1.1 307 Temporary Redirect\r\nLocation: /elsewhere\r\n\r\n\
                  HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Thing: a:b\r\n\r\n";

    assert_eq!(
      last_headers(dumped),
      [
        ("content-type".to_string(), "application/octet-stream".to_string()),
        ("x-thing".to_string(), "a:b".to_string())
      ]
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
