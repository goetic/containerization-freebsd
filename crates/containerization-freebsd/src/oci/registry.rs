use super::auth::{Access, Auth, Credentials, Secret, TokenResponse, parse_challenge, token_url};
use super::curl::{self, Request, Response};
use super::{ContentStore, Descriptor, Digest, Reference, media_type};
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

/// 4 MiB: the distribution spec says registries should accept manifests at
/// least this large.
const MAX_MANIFEST: u64 = 4 << 20;

/// A distribution API client over curl(1), which gets tokens and passwords
/// on stdin rather than in its arguments.
#[derive(Debug, Default)]
pub struct RegistryClient {
  credentials: Option<Credentials>,
  /// Bearer tokens, keyed by `<API host>/<repository>` and the access they
  /// grant.
  tokens: Mutex<HashMap<(String, Access), Secret>>,
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
  /// digest. A manifest over `MAX_MANIFEST` bytes is refused.
  pub fn fetch_manifest(&self, reference: &Reference, target: &str, store: &ContentStore) -> Result<Descriptor> {
    let partial = store.partial();
    let result = (|| {
      let response = self.get(
        reference,
        &format!("manifests/{target}"),
        Some(&media_type::MANIFESTS.join(", ")),
        &partial,
        Some(MAX_MANIFEST),
      )?;
      // curl before 8.4 can't stop a download whose size the registry
      // didn't send up front.
      let size = std::fs::metadata(&partial)
        .map_err(Error::io("reading a manifest"))?
        .len();
      if size > MAX_MANIFEST {
        return Err(Error::Guest(format!(
          "{reference}'s manifest {target} is {size} bytes, over the {MAX_MANIFEST}-byte limit"
        )));
      }
      let bytes = std::fs::read(&partial).map_err(Error::io("reading a manifest"))?;
      let digest = Digest::of(&bytes);
      if let Ok(expected) = target.parse::<Digest>()
        && digest != expected
      {
        return Err(Error::Checksum {
          path: partial.clone(),
          actual: digest.to_string(),
          expected: target.to_string(),
        });
      }

      let descriptor = Descriptor {
        media_type: media_type_of(response.header("content-type"), &bytes),
        digest,
        size,
        platform: None,
        annotations: Default::default(),
      };
      store.commit(&partial, &descriptor.digest)?;
      Ok(descriptor)
    })();

    let _ = std::fs::remove_file(&partial);
    result
  }

  pub fn fetch_blob(&self, reference: &Reference, descriptor: &Descriptor, store: &ContentStore) -> Result<()> {
    let partial = store.partial();
    let result = self
      .get(reference, &format!("blobs/{}", descriptor.digest), None, &partial, None)
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
    match self.send(reference, &head, Access::Push)?.status {
      200 => return Ok(()),
      404 => {}
      status => return Err(unexpected(&head, status, None)),
    }

    let post = Request::new("POST", url(reference, "blobs/uploads/"));
    let started = self.send(reference, &post, Access::Push)?;
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
      .append_pair("digest", descriptor.digest.as_str());

    let blob = store.path(&descriptor.digest)?;
    let mut put = Request::new("PUT", upload.to_string());
    put.content_type = Some("application/octet-stream");
    put.upload = Some(&blob);
    // Credentials go only to the registry, not to an upload location on
    // another origin such as a storage service.
    let response = if same_origin(&post.url, &put.url) {
      self.send(reference, &put, Access::Push)?
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
      .send(reference, &put, Access::Push)
      .and_then(|response| match response.status {
        201 => Ok(()),
        status => Err(unexpected(&put, status, Some(&response_body))),
      });
    let _ = std::fs::remove_file(&response_body);
    result
  }

  /// GETs `path` under the repository into the file `body`, failing on any
  /// status but 200. A body over `max_size` bytes is refused.
  fn get(
    &self,
    reference: &Reference,
    path: &str,
    accept: Option<&str>,
    body: &Path,
    max_size: Option<u64>,
  ) -> Result<Response> {
    let mut get = Request::new("GET", url(reference, path));
    get.accept = accept;
    get.output = Some(body);
    get.max_size = max_size;
    let response = self.send(reference, &get, Access::Pull)?;

    match response.status {
      200 => Ok(response),
      status => Err(unexpected(&get, status, Some(body))),
    }
  }

  /// Sends `request` with any cached token. On a 401, authenticates as the
  /// WWW-Authenticate challenge asks and retries once. The token's scope
  /// grants `access`.
  fn send(&self, reference: &Reference, request: &Request, access: Access) -> Result<Response> {
    let key = (format!("{}/{}", reference.api_host(), reference.repository), access);
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
  fn authorize(&self, reference: &Reference, key: &(String, Access), challenge: &str) -> Result<Auth> {
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
  fn fetch_token(&self, reference: &Reference, key: &(String, Access), url: &url::Url) -> Result<Secret> {
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

/// A fetched manifest's media type: the Content-Type if it is a known type,
/// else the document's `mediaType`, else an index if it has `manifests` and
/// a manifest if not.
fn media_type_of(content_type: Option<&str>, bytes: &[u8]) -> String {
  let header = content_type.map(|value| value.split(';').next().unwrap_or_default().trim());
  if let Some(header) = header.filter(|header| media_type::MANIFESTS.contains(header)) {
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
  use crate::oci::testing::FakeRegistry;

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
      .insert(("ghcr.io/a/b".into(), Access::Push), "a-token".into());

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

  #[test]
  fn refuses_a_manifest_over_the_limit() {
    let root = tempfile::tempdir().unwrap();
    let store = ContentStore::new(root.path()).unwrap();
    let huge = vec![b' '; MAX_MANIFEST as usize + 1];
    let registry = FakeRegistry::default()
      .manifest("test/image", "1", media_type::MANIFEST, &huge)
      .serve();
    let reference = Reference::parse(&format!("{registry}/test/image:1")).unwrap();

    let error = RegistryClient::default()
      .fetch_manifest(&reference, "1", &store)
      .unwrap_err();

    assert!(
      matches!(&error, Error::Guest(message) if message.ends_with("the response body is over the 4194304-byte limit")),
      "{error}"
    );
    assert!(store.digests().unwrap().is_empty());
    assert_eq!(
      std::fs::read_dir(root.path().join("ingest"))
        .unwrap()
        .count(),
      0
    );
  }

  #[test]
  fn fetches_a_manifest_once_and_names_its_type() {
    let root = tempfile::tempdir().unwrap();
    let store = ContentStore::new(root.path()).unwrap();
    let index = br#"{"schemaVersion":2,"manifests":[]}"#;
    let wrong = Digest::of(b"something else").to_string();
    let registry = FakeRegistry::default()
      .manifest("test/image", "1", media_type::INDEX, index)
      .manifest("test/image", &wrong, media_type::INDEX, index)
      .serve();
    let reference = Reference::parse(&format!("{registry}/test/image:1")).unwrap();
    let client = RegistryClient::default();

    let descriptor = client.fetch_manifest(&reference, "1", &store).unwrap();
    assert_eq!(
      (descriptor.media_type.as_str(), descriptor.size),
      (media_type::INDEX, index.len() as u64)
    );
    assert_eq!(store.read(&descriptor.digest).unwrap(), index);
    // Fetched by digest, a manifest must have that digest.
    let error = client
      .fetch_manifest(&reference, &wrong, &store)
      .unwrap_err();
    assert!(matches!(error, Error::Checksum { .. }), "{error}");
  }
}
