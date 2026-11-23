//! Tools the library runs on the host, such as curl(1).

use crate::error::{Error, Result};
use std::process::Command;

/// Runs `command` and returns its stdout, failing with its stderr unless it
/// exits 0.
pub(crate) fn run(command: &mut Command) -> Result<String> {
  let description = format!("{command:?}");
  let failed = |failure: String| Error::Command {
    command: description.clone(),
    failure,
  };
  let output = command
    .output()
    .map_err(|error| failed(error.to_string()))?;

  if !output.status.success() {
    return Err(failed(format!(
      "exited {}: {}",
      output.status,
      String::from_utf8_lossy(&output.stderr)
    )));
  }

  Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
