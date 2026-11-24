//! Loopback HTTP servers for tests: a registry, the files in a directory, and
//! canned responses in order.
//!
//! The registry serves pulls and pushes for any repository. Like ghcr.io, it
//! requires a bearer token scoped to the repository: GET and HEAD accept pull
//! or push, POST and PUT need push. Blob GETs and HEADs redirect to
//! unauthenticated storage outside the API, as real registries often do.

use crate::oci::Digest;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use url::Url;

/// Serves on a thread, answering each request with what `respond` returns
/// for it and the server's `host:port`, and returns the `host:port`.
fn serve(mut respond: impl FnMut(&Request, &str) -> Response + Send + 'static) -> String {
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let address = listener.local_addr().unwrap().to_string();
  let host = address.clone();

  std::thread::spawn(move || {
    for mut stream in listener.incoming().flatten() {
      let Ok(request) = Request::read(&stream, &host) else {
        continue;
      };
      let response = respond(&request, &host);
      let _ = response.write(&mut stream, request.method == "HEAD");
    }
  });
  address
}

/// Serves the files in `root`, and returns the server's URL.
pub(crate) fn serve_files(root: PathBuf) -> String {
  let address = serve(
    move |request, _| match std::fs::read(root.join(request.url.path().trim_start_matches('/'))) {
      Ok(bytes) => Response::ok(bytes),
      Err(_) => Response::status("404 Not Found"),
    },
  );
  format!("http://{address}")
}

/// Answers each request with the next of `responses`, and returns the
/// server's URL and the requests it has received. Once the responses run
/// out, it answers 400.
pub(crate) fn serve_in_order(responses: Vec<Response>) -> (String, Arc<Mutex<Vec<Request>>>) {
  let requests = Arc::new(Mutex::new(Vec::new()));
  let received = requests.clone();
  let mut responses = responses.into_iter();
  let address = serve(move |request, _| {
    received.lock().unwrap().push(request.clone());
    responses
      .next()
      .unwrap_or_else(|| Response::status("400 Bad Request"))
  });
  (format!("http://{address}"), requests)
}

#[derive(Default)]
pub(crate) struct FakeRegistry {
  /// Media type and bytes by `<repository>/<tag or digest>`.
  manifests: HashMap<String, (String, Vec<u8>)>,
  /// By digest, shared by every repository.
  blobs: HashMap<String, Vec<u8>>,
  uploads: u32,
}

impl FakeRegistry {
  /// Adds the manifest or index `bytes` under both `target` and its digest,
  /// as a push would.
  pub(crate) fn manifest(mut self, repository: &str, target: &str, media_type: &str, bytes: &[u8]) -> Self {
    self.put_manifest(repository, target, media_type, bytes.to_vec());
    self
  }

  pub(crate) fn blob(mut self, bytes: &[u8]) -> Self {
    self
      .blobs
      .insert(Digest::of(bytes).to_string(), bytes.to_vec());
    self
  }

  /// Serves on a thread and returns the `host:port`.
  pub(crate) fn serve(mut self) -> String {
    serve(move |request, host| self.respond(request, host))
  }

  fn respond(&mut self, request: &Request, host: &str) -> Response {
    let route = Route::parse(request.url.path());
    if let Some(repository) = route.repository()
      && !request.allowed(repository)
    {
      return Response::status("401 Unauthorized").header(
        "WWW-Authenticate",
        format!("Bearer realm=\"http://{host}/token\",service=\"test\""),
      );
    }

    match (request.method.as_str(), route) {
      ("GET", Route::Token) => token(request),
      ("GET" | "HEAD", Route::Storage { digest }) => found(
        self
          .blobs
          .get(&digest)
          .map(|blob| ("application/octet-stream", blob)),
      ),
      ("GET" | "HEAD", Route::Manifest { repository, target }) => found(
        self
          .manifests
          .get(&format!("{repository}/{target}"))
          .map(|(kind, bytes)| (kind.as_str(), bytes)),
      ),
      ("PUT", Route::Manifest { repository, target }) => {
        let kind = request
          .headers
          .get("content-type")
          .cloned()
          .unwrap_or_default();
        self.put_manifest(&repository, &target, &kind, request.body.clone());
        Response::status("201 Created")
      }
      ("POST", Route::Uploads { repository }) => {
        self.uploads += 1;
        Response::status("202 Accepted").header("Location", format!("/v2/{repository}/blobs/uploads/{}", self.uploads))
      }
      ("PUT", Route::Upload { .. }) => match request.query("digest") {
        Some(digest) if digest == Digest::of(&request.body).as_str() => {
          self.blobs.insert(digest, request.body.clone());
          Response::status("201 Created")
        }
        _ => Response::status("400 Bad Request"),
      },
      ("GET" | "HEAD", Route::Blob { digest, .. }) => {
        Response::status("307 Temporary Redirect").header("Location", format!("/storage/{digest}"))
      }
      _ => Response::status("404 Not Found"),
    }
  }

  fn put_manifest(&mut self, repository: &str, target: &str, media_type: &str, bytes: Vec<u8>) {
    let entry = (media_type.to_string(), bytes);
    self
      .manifests
      .insert(format!("{repository}/{}", Digest::of(&entry.1)), entry.clone());
    self
      .manifests
      .insert(format!("{repository}/{target}"), entry);
  }
}

/// Grants a token `<push|pull>:<repository>` for the scope
/// `repository:<repository>:<actions>`.
fn token(request: &Request) -> Response {
  let scope = request.query("scope").unwrap_or_default();
  let Some((repository, actions)) = scope
    .strip_prefix("repository:")
    .and_then(|scope| scope.rsplit_once(':'))
  else {
    return Response::status("400 Bad Request");
  };
  let action = if actions.split(',').any(|action| action == "push") {
    "push"
  } else {
    "pull"
  };

  Response::ok(format!(r#"{{"token":"{action}:{repository}"}}"#).into_bytes())
}

fn found(found: Option<(&str, &Vec<u8>)>) -> Response {
  match found {
    Some((kind, bytes)) => Response::ok(bytes.clone()).header("Content-Type", kind.to_string()),
    None => Response::status("404 Not Found"),
  }
}

enum Route {
  Token,
  Storage {
    digest: String,
  },
  Manifest {
    repository: String,
    target: String,
  },
  /// Where a POST opens an upload session.
  Uploads {
    repository: String,
  },
  Upload {
    repository: String,
  },
  Blob {
    repository: String,
    digest: String,
  },
  Unknown,
}

impl Route {
  fn parse(path: &str) -> Self {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match segments.as_slice() {
      ["token"] => Self::Token,
      ["storage", digest] => Self::Storage {
        digest: digest.to_string(),
      },
      ["v2", repository @ .., "manifests", target] => Self::Manifest {
        repository: repository.join("/"),
        target: target.to_string(),
      },
      ["v2", repository @ .., "blobs", "uploads", ""] => Self::Uploads {
        repository: repository.join("/"),
      },
      ["v2", repository @ .., "blobs", "uploads", _] => Self::Upload {
        repository: repository.join("/"),
      },
      ["v2", repository @ .., "blobs", digest] => Self::Blob {
        repository: repository.join("/"),
        digest: digest.to_string(),
      },
      _ => Self::Unknown,
    }
  }

  /// The repository whose token the route needs, if it needs one.
  fn repository(&self) -> Option<&str> {
    match self {
      Self::Manifest { repository, .. }
      | Self::Uploads { repository }
      | Self::Upload { repository }
      | Self::Blob { repository, .. } => Some(repository),
      Self::Token | Self::Storage { .. } | Self::Unknown => None,
    }
  }
}

#[derive(Clone)]
pub(crate) struct Request {
  method: String,
  url: Url,
  /// Headers by lowercase name.
  pub(crate) headers: HashMap<String, String>,
  body: Vec<u8>,
}

impl Request {
  fn read(stream: &TcpStream, host: &str) -> io::Result<Self> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let url = Url::parse(&format!("http://{host}{}", parts.next().unwrap_or_default())).map_err(io::Error::other)?;

    let mut headers = HashMap::new();
    loop {
      line.clear();
      reader.read_line(&mut line)?;
      let Some((name, value)) = line.trim_end().split_once(':') else {
        break;
      };
      headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
    }
    let length = headers
      .get("content-length")
      .and_then(|length| length.parse().ok())
      .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;

    Ok(Self {
      method,
      url,
      headers,
      body,
    })
  }

  fn query(&self, name: &str) -> Option<String> {
    self
      .url
      .query_pairs()
      .find(|(key, _)| key == name)
      .map(|(_, value)| value.into_owned())
  }

  /// Whether the bearer token's scope covers this method on `repository`.
  fn allowed(&self, repository: &str) -> bool {
    let Some((action, granted)) = self
      .headers
      .get("authorization")
      .and_then(|value| value.strip_prefix("Bearer "))
      .and_then(|token| token.split_once(':'))
    else {
      return false;
    };

    granted == repository && (action == "push" || !matches!(self.method.as_str(), "POST" | "PUT"))
  }
}

pub(crate) struct Response {
  status: &'static str,
  headers: Vec<(&'static str, String)>,
  body: Vec<u8>,
  /// How many of the body's bytes are sent, if not all of them.
  cut: Option<usize>,
}

impl Response {
  pub(crate) fn status(status: &'static str) -> Self {
    Self {
      status,
      headers: Vec::new(),
      body: Vec::new(),
      cut: None,
    }
  }

  pub(crate) fn ok(body: Vec<u8>) -> Self {
    Self::status("200 OK").body(body)
  }

  pub(crate) fn body(mut self, body: Vec<u8>) -> Self {
    self.body = body;
    self
  }

  pub(crate) fn header(mut self, name: &'static str, value: String) -> Self {
    self.headers.push((name, value));
    self
  }

  /// Sends only the first `at` bytes of the body before closing the
  /// connection, though the Content-Length promises them all.
  pub(crate) fn cut(mut self, at: usize) -> Self {
    self.cut = Some(at);
    self
  }

  /// Omits the body if `head`.
  fn write(&self, stream: &mut TcpStream, head: bool) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {}\r\n", self.status)?;
    for (name, value) in &self.headers {
      write!(stream, "{name}: {value}\r\n")?;
    }
    write!(
      stream,
      "Content-Length: {}\r\nConnection: close\r\n\r\n",
      self.body.len()
    )?;
    if !head {
      stream.write_all(&self.body[..self.cut.unwrap_or(self.body.len())])?;
    }
    Ok(())
  }
}
