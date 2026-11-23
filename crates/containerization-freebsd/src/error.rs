use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
  /// A host tool (`curl`, `hdiutil`, `diskutil`, `cp`, `tar`)
  /// failed, or a registry answered with an HTTP error.
  Command {
    command: String,
    failure: String,
  },
  /// A download's sha256 differs from the published one.
  Checksum {
    path: PathBuf,
    actual: String,
    expected: String,
  },
  /// `error`, raised during the part of a larger operation that `context`
  /// names, such as a build's step. `innermost` returns the error beneath
  /// any contexts, for matching.
  Context {
    context: String,
    error: Box<Error>,
  },
  /// The guest, Virtualization, a host tool or a registry returned something
  /// unexpected.
  Guest(String),
  /// An invalid request, such as an id jail(8) rejects, or starting a
  /// container twice.
  Invalid(String),
  Io {
    action: String,
    error: std::io::Error,
  },
  /// The protocol refused a message the host tried to send for `what`, such
  /// as with `NoSession` when there is no session with the guest agent.
  Protocol {
    what: String,
    error: containerization_freebsd_protocol::Error,
  },
  /// The guest agent's session ended, as on a guest reboot, while the named
  /// operation waited on it.
  SessionEnded(String),
  Timeout(String),
  Virtualization {
    action: String,
    error: virtualization::Error,
  },
}

impl Error {
  /// The error beneath any `Context`s, such as the `Timeout` of a build's
  /// step.
  pub fn innermost(&self) -> &Self {
    match self {
      Self::Context { error, .. } => error.innermost(),
      other => other,
    }
  }

  /// Wraps the error in a `Context` naming the part of an operation that
  /// raised it.
  pub(crate) fn context(self, context: impl Into<String>) -> Self {
    Self::Context {
      context: context.into(),
      error: Box::new(self),
    }
  }

  pub(crate) fn io(action: impl Into<String>) -> impl FnOnce(std::io::Error) -> Self {
    let action = action.into();

    move |error| Self::Io { action, error }
  }

  pub(crate) fn protocol(what: impl Into<String>) -> impl FnOnce(containerization_freebsd_protocol::Error) -> Self {
    let what = what.into();

    move |error| Self::Protocol { what, error }
  }

  pub(crate) fn virtualization(action: &str) -> impl Fn(virtualization::Error) -> Self + '_ {
    move |error| Self::Virtualization {
      action: action.to_string(),
      error,
    }
  }
}

impl fmt::Display for Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Command { command, failure } => write!(formatter, "{command}: {failure}"),
      Self::Checksum { path, actual, expected } => {
        write!(formatter, "{} has sha256 {actual}, expected {expected}", path.display())
      }
      Self::Context { context, error } => write!(formatter, "{context}: {error}"),
      Self::Guest(message) | Self::Invalid(message) | Self::Timeout(message) => formatter.write_str(message),
      Self::Io { action, error } => write!(formatter, "{action}: {error}"),
      Self::Protocol { what, error } => write!(formatter, "{what}: {error}"),
      Self::SessionEnded(what) => write!(formatter, "the guest agent's session ended while {what}"),
      Self::Virtualization { action, error } => write!(formatter, "{action}: {error}"),
    }
  }
}

impl std::error::Error for Error {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Context { error, .. } => Some(error.as_ref()),
      Self::Io { error, .. } => Some(error),
      Self::Protocol { error, .. } => Some(error),
      Self::Virtualization { error, .. } => Some(error),
      Self::Command { .. }
      | Self::Checksum { .. }
      | Self::Guest(_)
      | Self::Invalid(_)
      | Self::SessionEnded(_)
      | Self::Timeout(_) => None,
    }
  }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn keeps_the_error_beneath_a_context() {
    let error = Error::Timeout("tar did not finish within 600s".into())
      .context("layer 2 of 3")
      .context("unpacking ghcr.io/test/image:1");

    assert_eq!(
      error.to_string(),
      "unpacking ghcr.io/test/image:1: layer 2 of 3: tar did not finish within 600s"
    );
    assert!(matches!(error.innermost(), Error::Timeout(_)), "{error:?}");
    let source = std::error::Error::source(&error).expect("a source");
    assert_eq!(source.to_string(), "layer 2 of 3: tar did not finish within 600s");
  }
}
