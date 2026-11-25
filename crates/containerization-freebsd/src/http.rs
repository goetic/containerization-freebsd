//! HTTP for registries and release downloads, over ureq. A request is retried
//! after a failure to resolve or connect, and after a 408, 429, 500, 502, 503,
//! or 504 response, as curl's `--retry` does. A download hashes its body as it
//! writes it, and resumes with a Range request if the body breaks off.

use crate::{digest, error};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;
use ureq::config::RedirectAuthHeaders;
use ureq::tls::{RootCerts, TlsConfig};
use ureq::typestate::WithBody;
use ureq::{Agent, Body, RequestBuilder};
use url::Url;

/// How many times a request is retried, and how many times in a row a
/// download resumes without getting any further.
const RETRIES: u32 = 3;
/// The wait before the first retry, doubled before each one after it.
#[cfg(not(test))]
const BACKOFF: Duration = Duration::from_secs(1);
#[cfg(test)]
const BACKOFF: Duration = Duration::from_millis(10);
/// The longest wait for a retry that a server's Retry-After may ask for.
const LONGEST_WAIT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a server may take to send a response's headers. The body has no
/// limit, because ureq can bound only its whole transfer, not a pause in it.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
/// The statuses that a retry may clear, as curl's `--retry` takes them.
const TRANSIENT: [u16; 6] = [408, 429, 500, 502, 503, 504];
/// The most of an error response's body that its error quotes.
const SNIPPET: u64 = 400;
/// The most bytes a download reads at once.
const CHUNK: usize = 64 << 10;

/// An agent that verifies certificates as macOS does, sends credentials
/// only to the same host when it follows a redirect, and returns responses
/// whatever their status.
pub(crate) fn agent() -> Agent {
  Agent::config_builder()
    .http_status_as_error(false)
    .redirect_auth_headers(RedirectAuthHeaders::SameHost)
    .timeout_connect(Some(CONNECT_TIMEOUT))
    .timeout_recv_response(Some(RESPONSE_TIMEOUT))
    .tls_config(
      TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build(),
    )
    .build()
    .into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
  Get,
  Head,
  Post,
  Put,
}

impl fmt::Display for Method {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::Get => "GET",
      Self::Head => "HEAD",
      Self::Post => "POST",
      Self::Put => "PUT",
    })
  }
}

pub(crate) struct Request<'a> {
  pub(crate) method: Method,
  pub(crate) url: Url,
  pub(crate) accept: Option<&'a str>,
  pub(crate) content_type: Option<&'a str>,
  /// The file sent as the request's body.
  pub(crate) upload: Option<&'a Path>,
  /// The byte a resumed download asks for the body from, with a Range header
  /// unless it is 0.
  pub(crate) from: u64,
}

impl<'a> Request<'a> {
  pub(crate) fn new(method: Method, url: Url) -> Self {
    Self {
      method,
      url,
      accept: None,
      content_type: None,
      upload: None,
      from: 0,
    }
  }
}

/// The method and URL, as errors name a request.
impl fmt::Display for Request<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{} {}", self.method, self.url)
  }
}

/// A response whose body has yet to be read.
pub(crate) struct Response(ureq::http::Response<Body>);

impl Response {
  pub(crate) fn status(&self) -> u16 {
    self.0.status().as_u16()
  }

  pub(crate) fn header(&self, name: &str) -> Option<&str> {
    self.0.headers().get(name)?.to_str().ok()
  }

  /// The response, if it carries the content `request` asks for: a 200, or a
  /// 206 to a request that resumes. Otherwise, the error for it.
  pub(crate) fn content(self, request: &Request) -> error::Result<Self> {
    match (self.status(), request.from) {
      (200, _) | (206, 1..) => Ok(self),
      _ => Err(self.unexpected(request)),
    }
  }

  /// Reads the whole body, failing if it is over `limit` bytes.
  pub(crate) fn body(self, request: &Request, limit: u64) -> error::Result<Vec<u8>> {
    self
      .0
      .into_body()
      .into_with_config()
      .limit(limit)
      .read_to_vec()
      .map_err(|error| failed(request, &error))
  }

  /// The error for a response to `request` with a status it didn't expect,
  /// quoting the start of the body.
  pub(crate) fn unexpected(self, request: &Request) -> error::Error {
    let status = self.status();
    let mut start = Vec::new();
    let _ = self
      .0
      .into_body()
      .into_reader()
      .take(SNIPPET)
      .read_to_end(&mut start);

    error::Error::Command {
      command: request.to_string(),
      failure: format!("HTTP {status}: {}", String::from_utf8_lossy(&start).trim()),
    }
  }

  fn length(&self) -> Option<u64> {
    self.header("content-length")?.parse().ok()
  }

  /// How long the server's Retry-After, in seconds, asks a retry to wait.
  fn retry_after(&self) -> Option<Duration> {
    let seconds = self.header("retry-after")?.trim().parse().ok()?;

    Some(Duration::from_secs(seconds).min(LONGEST_WAIT))
  }
}

/// Sends `request` with `authorization` as its Authorization header,
/// retrying failures to resolve or connect and transient statuses. Once the
/// retries run out, a transient status is returned like any other.
pub(crate) fn send(agent: &Agent, request: &Request, authorization: Option<&str>) -> error::Result<Response> {
  let mut retries = 0;

  loop {
    // Each attempt sends the file from its start.
    let upload = request
      .upload
      .map(File::open)
      .transpose()
      .map_err(|error| error::Error::Io {
        action: format!("reading the body of {request}"),
        error,
      })?;
    let wait = match exchange(agent, request, authorization, upload) {
      Ok(response) if retries < RETRIES && TRANSIENT.contains(&response.status()) => {
        response.retry_after().unwrap_or_else(|| backoff(retries))
      }
      Err(error) if retries < RETRIES && transient(&error) => backoff(retries),
      Ok(response) => return Ok(response),
      Err(error) => return Err(failed(request, &error)),
    };
    std::thread::sleep(wait);
    retries += 1;
  }
}

fn exchange(
  agent: &Agent,
  request: &Request,
  authorization: Option<&str>,
  upload: Option<File>,
) -> std::result::Result<Response, ureq::Error> {
  let url = request.url.as_str();
  let response = match request.method {
    Method::Get => headers(agent.get(url), request, authorization).call(),
    Method::Head => headers(agent.head(url), request, authorization).call(),
    Method::Post => with_body(headers(agent.post(url), request, authorization), upload),
    Method::Put => with_body(headers(agent.put(url), request, authorization), upload),
  }?;
  Ok(Response(response))
}

fn headers<B>(mut builder: RequestBuilder<B>, request: &Request, authorization: Option<&str>) -> RequestBuilder<B> {
  if let Some(accept) = request.accept {
    builder = builder.header("Accept", accept);
  }
  if let Some(content_type) = request.content_type {
    builder = builder.header("Content-Type", content_type);
  }
  if let Some(authorization) = authorization {
    builder = builder.header("Authorization", authorization);
  }
  if request.from > 0 {
    builder = builder.header("Range", format!("bytes={}-", request.from));
  }
  builder
}

/// Sends `upload` as the body, with its length as the Content-Length, or an
/// empty body.
fn with_body(
  builder: RequestBuilder<WithBody>,
  upload: Option<File>,
) -> std::result::Result<ureq::http::Response<Body>, ureq::Error> {
  match upload {
    Some(file) => builder.send(file),
    None => builder.send_empty(),
  }
}

/// Whether a retry may clear `error`, a failure beneath HTTP.
fn transient(error: &ureq::Error) -> bool {
  matches!(
    error,
    ureq::Error::Io(_) | ureq::Error::Timeout(_) | ureq::Error::HostNotFound | ureq::Error::ConnectionFailed
  )
}

fn backoff(retries: u32) -> Duration {
  BACKOFF * 2u32.pow(retries)
}

fn failed(request: &Request, error: &dyn fmt::Display) -> error::Error {
  error::Error::Command {
    command: request.to_string(),
    failure: error.to_string(),
  }
}

/// The sha256 and length of a download.
pub(crate) struct Downloaded {
  pub(crate) sha256: String,
  pub(crate) size: u64,
}

/// Downloads the body of the response that `get` returns into `path`,
/// hashing it as it writes it, and fails if the body is over `limit` bytes.
/// `get` is given the byte to ask for the body from, 0 at first, and returns
/// a response that carries it, as `Response::content` checks. If the body
/// breaks off, the download resumes where it stopped, or starts over if the
/// server sends the whole body again. `what` names the download in errors.
pub(crate) fn download(
  path: &Path,
  limit: Option<u64>,
  what: &str,
  mut get: impl FnMut(u64) -> error::Result<Response>,
) -> error::Result<Downloaded> {
  let writing = || format!("writing {}", path.display());
  let create = || {
    File::create(path)
      .map(digest::Hashing::new)
      .map_err(error::Error::io(writing()))
  };
  let mut file = create()?;
  let mut size = 0;
  let mut stalls = 0;

  loop {
    let response = get(size)?;
    if size > 0 && response.status() != 206 {
      file = create()?;
      size = 0;
    }
    let before = size;

    match append(response, &mut file, &mut size, limit) {
      Ok(()) => {
        return Ok(Downloaded {
          sha256: file.finish(),
          size,
        });
      }
      Err(Append::Read(error)) => {
        stalls = if size > before { 0 } else { stalls + 1 };
        if stalls > RETRIES {
          return Err(error::Error::Command {
            command: what.to_string(),
            failure: error.to_string(),
          });
        }
        std::thread::sleep(backoff(stalls));
      }
      Err(Append::Write(error)) => return Err(error::Error::io(writing())(error)),
      Err(Append::OverLimit(limit)) => {
        return Err(error::Error::Guest(format!(
          "{what}: the response body is over the {limit}-byte limit"
        )));
      }
    }
  }
}

/// Why `append` stopped before the body's end.
enum Append {
  Read(io::Error),
  Write(io::Error),
  OverLimit(u64),
}

/// Appends `response`'s body to `file`, counting what it appends in `size`.
fn append(
  response: Response,
  file: &mut digest::Hashing<File>,
  size: &mut u64,
  limit: Option<u64>,
) -> std::result::Result<(), Append> {
  let over = |size: u64| limit.filter(|limit| size > *limit);
  if let Some(limit) = response.length().and_then(|length| over(*size + length)) {
    return Err(Append::OverLimit(limit));
  }
  let mut body = response.0.into_body().into_reader();
  let mut buffer = vec![0; CHUNK];

  loop {
    let read = match body.read(&mut buffer) {
      Ok(0) => return Ok(()),
      Ok(read) => read,
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      Err(error) => return Err(Append::Read(error)),
    };
    if let Some(limit) = over(*size + read as u64) {
      return Err(Append::OverLimit(limit));
    }
    file.write_all(&buffer[..read]).map_err(Append::Write)?;
    *size += read as u64;
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::testing;

  fn get(url: &str) -> Request<'static> {
    Request::new(Method::Get, Url::parse(url).unwrap())
  }

  /// Downloads `url` into `path` as a registry or release download does.
  fn download_from(url: &str, path: &Path, limit: Option<u64>) -> error::Result<Downloaded> {
    let agent = agent();
    let mut request = get(url);

    download(path, limit, "the test download", |from| {
      request.from = from;
      send(&agent, &request, None)?.content(&request)
    })
  }

  fn range(request: &testing::Request) -> Option<&str> {
    request.headers.get("range").map(String::as_str)
  }

  #[test]
  fn retries_a_transient_status_until_it_clears() {
    let (url, requests) = testing::serve_in_order(vec![
      testing::Response::status("503 Service Unavailable").header("Retry-After", "0".into()),
      testing::Response::status("502 Bad Gateway"),
      testing::Response::ok(b"done".to_vec()),
    ]);
    let request = get(&url);

    let response = send(&agent(), &request, None).unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(&request, 100).unwrap(), b"done");
    assert_eq!(requests.lock().unwrap().len(), 3);
  }

  #[test]
  fn returns_a_transient_status_once_its_retries_run_out() {
    let unavailable = || testing::Response::status("503 Service Unavailable");
    let (url, requests) = testing::serve_in_order((0..=RETRIES).map(|_| unavailable()).collect());

    let response = send(&agent(), &get(&url), None).unwrap();

    assert_eq!(response.status(), 503);
    assert_eq!(requests.lock().unwrap().len(), RETRIES as usize + 1);
  }

  #[test]
  fn resumes_a_download_that_breaks_off() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("download");
    let (url, requests) = testing::serve_in_order(vec![
      testing::Response::ok(b"hello, world".to_vec()).cut(5),
      testing::Response::status("206 Partial Content").body(b", world".to_vec()),
    ]);

    let downloaded = download_from(&url, &path, None).unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"hello, world");
    assert_eq!(
      digest::Digest::from_sha256(&downloaded.sha256),
      digest::Digest::of(b"hello, world")
    );
    assert_eq!(downloaded.size, 12);
    let requests = requests.lock().unwrap();
    assert_eq!(range(&requests[0]), None);
    assert_eq!(range(&requests[1]), Some("bytes=5-"));
  }

  #[test]
  fn starts_over_when_the_server_sends_the_whole_body_again() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("download");
    let (url, _) = testing::serve_in_order(vec![
      testing::Response::ok(b"hello, world".to_vec()).cut(5),
      testing::Response::ok(b"hello, world".to_vec()),
    ]);

    let downloaded = download_from(&url, &path, None).unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"hello, world");
    assert_eq!(downloaded.size, 12);
  }

  #[test]
  fn refuses_a_body_over_its_limit() {
    let directory = tempfile::tempdir().unwrap();
    let (url, _) = testing::serve_in_order(vec![testing::Response::ok(b"too long".to_vec())]);

    let error = download_from(&url, &directory.path().join("download"), Some(4))
      .err()
      .unwrap();

    assert!(
      matches!(&error, error::Error::Guest(message) if message.ends_with("over the 4-byte limit")),
      "{error}"
    );
  }

  #[test]
  fn fails_on_a_status_that_carries_no_content() {
    let directory = tempfile::tempdir().unwrap();
    let (url, _) = testing::serve_in_order(vec![
      testing::Response::status("404 Not Found").header("Content-Type", "text/plain".into()),
    ]);

    let error = download_from(&url, &directory.path().join("download"), None)
      .err()
      .unwrap();

    assert!(
      matches!(&error, error::Error::Command { failure, .. } if failure.starts_with("HTTP 404")),
      "{error}"
    );
  }
}
