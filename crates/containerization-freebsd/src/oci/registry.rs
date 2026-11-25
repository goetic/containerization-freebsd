use super::{auth, content, media_type, reference};
use crate::{digest, error, http};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, PoisonError};
use url::Url;

/// 4 MiB: the distribution spec says registries should accept manifests at
/// least this large.
const MAX_MANIFEST: u64 = 4 << 20;
/// The most of a token response that is read.
const MAX_TOKEN: u64 = 1 << 20;

/// A distribution API client. It keeps its connections open for later
/// requests, and caches the bearer tokens that registries grant it.
pub struct RegistryClient {
  credentials: Option<auth::Credentials>,
  /// Bearer tokens, keyed by `<API host>/<repository>` and the access they
  /// grant.
  tokens: Mutex<HashMap<(String, auth::Access), auth::Secret>>,
  agent: ureq::Agent,
}

/// Shows the credentials and tokens, which redact their secrets, but not the
/// agent, whose proxy settings may hold a password.
impl fmt::Debug for RegistryClient {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RegistryClient")
      .field("credentials", &self.credentials)
      .field("tokens", &self.tokens)
      .finish_non_exhaustive()
  }
}

impl Default for RegistryClient {
  fn default() -> Self {
    Self::new(None)
  }
}

impl RegistryClient {
  pub fn new(credentials: Option<auth::Credentials>) -> Self {
    Self {
      credentials,
      tokens: Mutex::default(),
      agent: http::agent(),
    }
  }

  /// Fetches the manifest or index `target`, a tag or digest, from
  /// `reference`'s repository into `store`, verifying it if `target` is a
  /// digest. A manifest over `MAX_MANIFEST` bytes is refused.
  pub fn fetch_manifest(
    &self,
    reference: &reference::Reference,
    target: &str,
    store: &content::ContentStore,
  ) -> error::Result<super::Descriptor> {
    let accept = media_type::MANIFESTS.join(", ");
    let mut get = http::Request::new(http::Method::Get, url(reference, &format!("manifests/{target}"))?);
    get.accept = Some(&accept);
    let what = get.to_string();
    let partial = store.partial();
    let mut content_type = None;
    let downloaded = http::download(partial.path(), Some(MAX_MANIFEST), &what, |from| {
      get.from = from;
      let response = self.get(reference, &get)?;
      content_type = response.header("content-type").map(str::to_string);
      Ok(response)
    })?;

    let digest = digest::Digest::from_sha256(&downloaded.sha256);
    if let Ok(expected) = target.parse::<digest::Digest>()
      && digest != expected
    {
      return Err(error::Error::Checksum {
        path: partial.path().to_path_buf(),
        actual: digest.to_string(),
        expected: target.to_string(),
      });
    }
    let bytes = std::fs::read(partial.path()).map_err(error::Error::io("reading a manifest"))?;
    let descriptor = super::Descriptor::new(media_type_of(content_type.as_deref(), &bytes), digest, downloaded.size);
    store.commit(partial, &descriptor.digest)?;
    Ok(descriptor)
  }

  /// Fetches `descriptor`'s blob into `store`, hashing it as it arrives. A
  /// blob longer than the descriptor's size is refused once it passes it.
  pub fn fetch_blob(
    &self,
    reference: &reference::Reference,
    descriptor: &super::Descriptor,
    store: &content::ContentStore,
  ) -> error::Result<()> {
    let mut get = http::Request::new(
      http::Method::Get,
      url(reference, &format!("blobs/{}", descriptor.digest))?,
    );
    let what = get.to_string();
    let partial = store.partial();
    let downloaded = http::download(partial.path(), Some(descriptor.size), &what, |from| {
      get.from = from;
      self.get(reference, &get)
    })?;

    store.ingest_hashed(partial, descriptor, &downloaded.sha256, downloaded.size)
  }

  /// Uploads `descriptor`'s blob unless a HEAD finds it in the repository,
  /// as a monolithic upload: a POST opens the session and one PUT sends the
  /// blob.
  pub fn push_blob(
    &self,
    reference: &reference::Reference,
    descriptor: &super::Descriptor,
    store: &content::ContentStore,
  ) -> error::Result<()> {
    let head = http::Request::new(
      http::Method::Head,
      url(reference, &format!("blobs/{}", descriptor.digest))?,
    );
    let found = self.send(reference, &head, auth::Access::Push)?;
    match found.status() {
      200 => return Ok(()),
      404 => {}
      _ => return Err(found.unexpected(&head)),
    }

    let post = http::Request::new(http::Method::Post, url(reference, "blobs/uploads/")?);
    let started = self.send(reference, &post, auth::Access::Push)?;
    let location = match (started.status(), started.header("location")) {
      (202, Some(location)) => location.to_string(),
      _ => return Err(started.unexpected(&post)),
    };
    let mut upload = post.url.join(&location).map_err(|error| {
      error::Error::Guest(format!(
        "{} gave the upload location {location:?}: {error}",
        reference.domain()
      ))
    })?;
    upload
      .query_pairs_mut()
      .append_pair("digest", descriptor.digest.as_str());

    let blob = store.path(&descriptor.digest)?;
    let mut put = http::Request::new(http::Method::Put, upload);
    put.content_type = Some("application/octet-stream");
    put.upload = Some(&blob);
    // Credentials go only to the registry, not to an upload location on
    // another origin such as a storage service.
    let response = if post.url.origin() == put.url.origin() {
      self.send(reference, &put, auth::Access::Push)?
    } else {
      http::send(&self.agent, &put, None)?
    };
    match response.status() {
      201 => Ok(()),
      _ => Err(response.unexpected(&put)),
    }
  }

  /// Uploads the manifest or index `descriptor` under `target`, a tag or its
  /// digest.
  pub fn push_manifest(
    &self,
    reference: &reference::Reference,
    target: &str,
    descriptor: &super::Descriptor,
    store: &content::ContentStore,
  ) -> error::Result<()> {
    let document = store.path(&descriptor.digest)?;
    let mut put = http::Request::new(http::Method::Put, url(reference, &format!("manifests/{target}"))?);
    put.content_type = Some(&descriptor.media_type);
    put.upload = Some(&document);

    let response = self.send(reference, &put, auth::Access::Push)?;
    match response.status() {
      201 => Ok(()),
      _ => Err(response.unexpected(&put)),
    }
  }

  /// GETs `request` from the repository, failing unless the response
  /// carries what it asks for.
  fn get(&self, reference: &reference::Reference, request: &http::Request) -> error::Result<http::Response> {
    self
      .send(reference, request, auth::Access::Pull)?
      .content(request)
  }

  /// Sends `request` with any cached token. On a 401, authenticates as the
  /// WWW-Authenticate challenge asks and retries once. The token's scope
  /// grants `access`.
  fn send(
    &self,
    reference: &reference::Reference,
    request: &http::Request,
    access: auth::Access,
  ) -> error::Result<http::Response> {
    let key = (format!("{}/{}", reference.api_host(), reference.repository()), access);
    let cached = self
      .tokens
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .get(&key)
      .cloned();
    let auth = cached.map_or(auth::Auth::None, auth::Auth::Bearer);

    let response = http::send(&self.agent, request, auth.header().as_deref())?;
    if response.status() != 401 {
      return Ok(response);
    }
    let Some(challenge) = response.header("www-authenticate").map(str::to_string) else {
      return Err(response.unexpected(request));
    };
    let auth = self.authorize(reference, &key, &challenge)?;
    http::send(&self.agent, request, auth.header().as_deref())
  }

  /// The authorization a WWW-Authenticate challenge asks for: a bearer token
  /// from its realm, or basic auth with the credentials.
  fn authorize(
    &self,
    reference: &reference::Reference,
    key: &(String, auth::Access),
    challenge: &str,
  ) -> error::Result<auth::Auth> {
    let (scheme, parameters) = auth::parse_challenge(challenge);

    match scheme.to_ascii_lowercase().as_str() {
      "basic" => self
        .credentials
        .clone()
        .map(auth::Auth::Basic)
        .ok_or_else(|| error::Error::Invalid(format!("{} wants an account", reference.domain()))),
      "bearer" => {
        let url = auth::token_url(reference, key.1, challenge, &parameters)?;
        self
          .fetch_token(reference, key, url)
          .map(auth::Auth::Bearer)
      }
      _ => Err(error::Error::Invalid(format!(
        "{} asks for {scheme} authentication, which isn't supported",
        reference.domain()
      ))),
    }
  }

  /// Fetches a bearer token from `url`, with basic auth if there are
  /// credentials, and caches it under `key`.
  fn fetch_token(
    &self,
    reference: &reference::Reference,
    key: &(String, auth::Access),
    url: Url,
  ) -> error::Result<auth::Secret> {
    let auth = self
      .credentials
      .clone()
      .map_or(auth::Auth::None, auth::Auth::Basic);
    let get = http::Request::new(http::Method::Get, url);
    let response = http::send(&self.agent, &get, auth.header().as_deref())?;
    if response.status() != 200 {
      return Err(response.unexpected(&get));
    }
    let bytes = response.body(&get, MAX_TOKEN)?;

    let token: auth::TokenResponse = super::parse(&bytes, "the registry's token")?;
    let token: auth::Secret = token
      .token
      .or(token.access_token)
      .ok_or_else(|| error::Error::Guest(format!("{} sent no token", reference.domain())))?
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
fn url(reference: &reference::Reference, path: &str) -> error::Result<Url> {
  let scheme = if reference.is_loopback() { "http" } else { "https" };
  let url = format!(
    "{scheme}://{}/v2/{}/{path}",
    reference.api_host(),
    reference.repository()
  );

  Url::parse(&url).map_err(|error| error::Error::Invalid(format!("{url:?} is not a URL: {error}")))
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
  use crate::{oci, testing};

  #[test]
  fn debugs_without_its_secrets() {
    let client = RegistryClient::new(Some(auth::Credentials {
      username: "someone".into(),
      password: "hunter2".into(),
    }));
    client
      .tokens
      .lock()
      .unwrap()
      .insert(("ghcr.io/a/b".into(), auth::Access::Push), "a-token".into());

    let debugged = format!("{client:?}");

    assert!(
      debugged.contains("someone") && debugged.contains("ghcr.io/a/b"),
      "{debugged}"
    );
    assert!(
      !debugged.contains("hunter2") && !debugged.contains("a-token"),
      "{debugged}"
    );
    assert_eq!(auth::Secret::from("hunter2").to_string(), "********");
  }

  #[test]
  fn refuses_a_registry_that_makes_no_url() {
    let reference = reference::Reference::parse("localhost:abc/a").unwrap();

    let error = url(&reference, "tags/list").unwrap_err();

    assert!(
      matches!(&error, error::Error::Invalid(message) if message.contains("localhost:abc")),
      "{error}"
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

  #[test]
  fn refuses_a_manifest_over_the_limit() {
    let root = tempfile::tempdir().unwrap();
    let store = content::ContentStore::new(root.path()).unwrap();
    let huge = vec![b' '; MAX_MANIFEST as usize + 1];
    let registry = testing::FakeRegistry::default()
      .manifest("test/image", "1", media_type::MANIFEST, &huge)
      .serve();
    let reference = reference::Reference::parse(&format!("{registry}/test/image:1")).unwrap();

    let error = RegistryClient::default()
      .fetch_manifest(&reference, "1", &store)
      .unwrap_err();

    assert!(
      matches!(&error, error::Error::Guest(message) if message.ends_with("the response body is over the 4194304-byte limit")),
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
    let store = content::ContentStore::new(root.path()).unwrap();
    let index = br#"{"schemaVersion":2,"manifests":[]}"#;
    let wrong = digest::Digest::of(b"something else").to_string();
    let registry = testing::FakeRegistry::default()
      .manifest("test/image", "1", media_type::INDEX, index)
      .manifest("test/image", &wrong, media_type::INDEX, index)
      .serve();
    let reference = reference::Reference::parse(&format!("{registry}/test/image:1")).unwrap();
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
    assert!(matches!(error, error::Error::Checksum { .. }), "{error}");
  }

  #[test]
  fn refuses_a_blob_longer_than_its_descriptor_says() {
    let root = tempfile::tempdir().unwrap();
    let store = content::ContentStore::new(root.path()).unwrap();
    let blob = b"a blob longer than four bytes";
    let registry = testing::FakeRegistry::default().blob(blob).serve();
    let reference = reference::Reference::parse(&format!("{registry}/test/image:1")).unwrap();
    let descriptor = oci::Descriptor::new(media_type::LAYER, digest::Digest::of(blob), 4);

    let error = RegistryClient::default()
      .fetch_blob(&reference, &descriptor, &store)
      .unwrap_err();

    assert!(
      matches!(&error, error::Error::Guest(message) if message.ends_with("over the 4-byte limit")),
      "{error}"
    );
    assert!(!store.has(&descriptor.digest));
  }
}
