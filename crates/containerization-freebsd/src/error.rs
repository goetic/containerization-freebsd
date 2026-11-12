use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
  /// A host tool (`curl`, `hdiutil`, `diskutil`, `cp`) failed.
  Command {
    command: String,
    failure: String,
  },
  /// A download's sha256 differs from the one published for it.
  Checksum {
    path: PathBuf,
    actual: String,
    expected: String,
  },
  /// The guest did something other than what it was expected to.
  Guest(String),
  Io {
    action: String,
    error: std::io::Error,
  },
  Timeout(String),
  Virtualization {
    action: String,
    error: virtualization::Error,
  },
}

impl Error {
  pub(crate) fn io(action: impl Into<String>) -> impl FnOnce(std::io::Error) -> Self {
    let action = action.into();

    move |error| Self::Io { action, error }
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
      Self::Guest(message) | Self::Timeout(message) => formatter.write_str(message),
      Self::Io { action, error } => write!(formatter, "{action}: {error}"),
      Self::Virtualization { action, error } => write!(formatter, "{action}: {error}"),
    }
  }
}

impl std::error::Error for Error {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Io { error, .. } => Some(error),
      Self::Virtualization { error, .. } => Some(error),
      Self::Command { .. } | Self::Checksum { .. } | Self::Guest(_) | Self::Timeout(_) => None,
    }
  }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
