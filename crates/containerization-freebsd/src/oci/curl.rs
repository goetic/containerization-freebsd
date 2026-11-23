//! HTTP over curl(1). Options, credentials included, go to curl as a config
//! file on stdin, so they never appear in the process's arguments.

use super::auth::Auth;
use crate::error::{Error, Result};
use crate::scratch::Scratch;
use std::fmt;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use url::Url;

/// curl's exit status when a response body is over `max-filesize`.
const TOO_LARGE: i32 = 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Method {
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

pub(super) struct Request<'a> {
  pub(super) method: Method,
  pub(super) url: Url,
  pub(super) accept: Option<&'a str>,
  pub(super) content_type: Option<&'a str>,
  /// The file sent as the request body.
  pub(super) upload: Option<&'a Path>,
  /// The file the response body is written to.
  pub(super) output: Option<&'a Path>,
  /// The most bytes the response body may have. curl refuses a larger body
  /// or stops downloading it.
  pub(super) max_size: Option<u64>,
}

pub(super) struct Response {
  pub(super) status: u16,
  /// The final response's headers, after redirects, with lowercase names.
  headers: Vec<(String, String)>,
}

impl<'a> Request<'a> {
  pub(super) fn new(method: Method, url: Url) -> Self {
    Self {
      method,
      url,
      accept: None,
      content_type: None,
      upload: None,
      output: None,
      max_size: None,
    }
  }

  /// The curl config for this request with `auth`: follow redirects, dump
  /// headers to `headers`, write the body to `output`, and print only the
  /// status code.
  fn config(&self, auth: &Auth, headers: &Path) -> String {
    let mut config = Config::default();

    config.option("url", self.url.as_str());
    config.option("dump-header", &headers.to_string_lossy());
    config.flag("location");
    config.flag("silent");
    config.flag("show-error");
    config.option("retry", "3");
    config.option("write-out", "%{http_code}");
    match (self.method, self.upload) {
      (Method::Head, _) => config.flag("head"),
      (method, Some(upload)) => {
        config.option("upload-file", &upload.to_string_lossy());
        config.option("request", &method.to_string());
        // An empty Expect header stops curl waiting for 100 Continue.
        config.option("header", "Expect:");
      }
      (Method::Get, None) => {}
      (method, None) => {
        config.option("request", &method.to_string());
        config.option("data-binary", "");
      }
    }
    // The body goes to a file so stdout carries only the status code.
    let output = self.output.unwrap_or(Path::new("/dev/null"));
    config.option("output", &output.to_string_lossy());
    if let Some(max_size) = self.max_size {
      config.option("max-filesize", &max_size.to_string());
    }
    if let Some(accept) = self.accept {
      config.option("header", &format!("Accept: {accept}"));
    }
    if let Some(content_type) = self.content_type {
      config.option("header", &format!("Content-Type: {content_type}"));
    }
    match auth {
      Auth::None => {}
      Auth::Bearer(token) => config.option("header", &format!("Authorization: Bearer {}", token.expose())),
      Auth::Basic(credentials) => config.option(
        "user",
        &format!("{}:{}", credentials.username, credentials.password.expose()),
      ),
    }
    config.0
  }
}

impl Response {
  pub(super) fn header(&self, name: &str) -> Option<&str> {
    self
      .headers
      .iter()
      .find(|(key, _)| key == name)
      .map(|(_, value)| value.as_str())
  }
}

pub(super) fn send(request: &Request, auth: &Auth) -> Result<Response> {
  let headers = Scratch::temporary();
  let config = request.config(auth, headers.path());
  let command = format!("curl {} {}", request.method, request.url);
  let status = run(&config, &command, request.max_size)?;

  Ok(Response {
    status,
    headers: last_headers(&std::fs::read_to_string(headers.path()).unwrap_or_default()),
  })
}

/// A curl config file (`--config`), one option per line.
#[derive(Default)]
struct Config(String);

impl Config {
  fn flag(&mut self, name: &str) {
    self.0.push_str(name);
    self.0.push('\n');
  }

  fn option(&mut self, name: &str, value: &str) {
    self.0.push_str(&format!("{name} = {}\n", quote(value)));
  }
}

/// Runs curl with `config` on stdin and returns the HTTP status it printed.
/// Errors name the request as `command`, and say when the response body was
/// over `max_size` bytes.
fn run(config: &str, command: &str, max_size: Option<u64>) -> Result<u16> {
  let failed = |failure: String| Error::Command {
    command: command.to_string(),
    failure,
  };
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
  if let (Some(max_size), Some(TOO_LARGE)) = (max_size, output.status.code()) {
    return Err(Error::Guest(format!(
      "{command}: the response body is over the {max_size}-byte limit"
    )));
  }
  if !output.status.success() {
    return Err(failed(format!(
      "exited {}: {}",
      output.status,
      String::from_utf8_lossy(&output.stderr).trim()
    )));
  }

  String::from_utf8_lossy(&output.stdout)
    .trim()
    .parse()
    .map_err(|_| failed("wrote no HTTP status".to_string()))
}

/// `value` as a double-quoted string in curl's config syntax.
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

/// The last response's headers from curl's `dump-header` output, which has a
/// block for each response, redirects included.
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn quotes_for_curls_config() {
    assert_eq!(quote(r#"pa"ss\word"#), r#""pa\"ss\\word""#);
  }

  #[test]
  fn writes_curls_config_for_an_upload() {
    let mut put = Request::new(
      Method::Put,
      Url::parse("https://ghcr.io/v2/a/b/blobs/uploads/1").unwrap(),
    );
    put.content_type = Some("application/octet-stream");
    put.upload = Some(Path::new("/blob"));

    assert_eq!(
      put.config(&Auth::Bearer("a-token".into()), Path::new("/headers")),
      "url = \"https://ghcr.io/v2/a/b/blobs/uploads/1\"\n\
       dump-header = \"/headers\"\n\
       location\n\
       silent\n\
       show-error\n\
       retry = \"3\"\n\
       write-out = \"%{http_code}\"\n\
       upload-file = \"/blob\"\n\
       request = \"PUT\"\n\
       header = \"Expect:\"\n\
       output = \"/dev/null\"\n\
       header = \"Content-Type: application/octet-stream\"\n\
       header = \"Authorization: Bearer a-token\"\n"
    );
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
}
