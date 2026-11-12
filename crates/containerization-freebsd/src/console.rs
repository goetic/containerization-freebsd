//! The host's end of the shell `guest/first-boot.sh` leaves on the guest's
//! console port, `/dev/ttyV0.0`, until the agent replaces it.

use crate::error::{Error, Result};
use std::io::{BufRead, BufReader, PipeReader, PipeWriter, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The line the guest's shell prints when it starts, then its seconds since
/// the kernel booted.
pub const READY: &str = "console-ready";

pub struct Console {
  echo: Arc<AtomicBool>,
  lines: Receiver<String>,
  input: PipeWriter,
  commands: u32,
}

pub struct Ran {
  pub code: i32,
  pub output: Vec<String>,
  pub seconds: f64,
}

impl Ran {
  pub fn text(&self) -> String {
    self.output.join("\n")
  }
}

impl Console {
  pub(crate) fn new(output: PipeReader, input: PipeWriter) -> Self {
    let (sender, lines) = std::sync::mpsc::channel();
    let echo = Arc::new(AtomicBool::new(false));
    let echoing = echo.clone();

    std::thread::spawn(move || {
      for line in BufReader::new(output).lines().map_while(Result::ok) {
        let line = line.trim_end_matches('\r').to_string();

        if echoing.load(Ordering::Relaxed) {
          eprintln!("guest| {line}");
        }
        if sender.send(line).is_err() {
          break;
        }
      }
    });

    Self {
      echo,
      lines,
      input,
      commands: 0,
    }
  }

  /// Copies every line the guest prints to stderr, for watching a boot.
  pub fn set_echo(&self, echo: bool) {
    self.echo.store(echo, Ordering::Relaxed);
  }

  /// The first line starting with `prefix`, or `None` if none came within `timeout`.
  pub fn wait_for(&self, prefix: &str, timeout: Duration) -> Option<String> {
    self.wait_for_any(&[prefix], timeout)
  }

  /// The first line starting with any of `prefixes`, or `None` if none came within `timeout`.
  pub fn wait_for_any(&self, prefixes: &[&str], timeout: Duration) -> Option<String> {
    let started = Instant::now();

    loop {
      let left = timeout.checked_sub(started.elapsed())?;

      match self.lines.recv_timeout(left) {
        Ok(line) if prefixes.iter().any(|prefix| line.starts_with(prefix)) => return Some(line),
        Ok(_) => {}
        Err(RecvTimeoutError::Timeout) => return None,
        // As good as silence: a machine without the port closes it at once.
        Err(RecvTimeoutError::Disconnected) => {
          std::thread::sleep(left);
          return None;
        }
      }
    }
  }

  /// Sends a line without waiting for it to finish.
  pub fn send(&mut self, line: &str) -> Result<()> {
    writeln!(self.input, "{line}").map_err(Error::io("writing to the guest"))
  }

  /// Runs `script` in the guest's shell, and collects what it printed.
  pub fn run(&mut self, script: &str, timeout: Duration) -> Result<Ran> {
    self.commands += 1;
    let marker = format!("console-done-{}", self.commands);
    let started = Instant::now();
    let timed_out = || Error::Timeout(format!("{script:?} did not finish within {}s", timeout.as_secs()));

    // The marker starts a line of its own even after output without a newline;
    // the empty line that leaves otherwise is dropped below.
    write!(
      self.input,
      "{script}\nstatus=$?; printf '\\n{marker} %s\\n' \"$status\"\n"
    )
    .map_err(Error::io("writing to the guest"))?;

    let mut output = Vec::new();
    loop {
      let left = timeout
        .checked_sub(started.elapsed())
        .ok_or_else(timed_out)?;

      match self.lines.recv_timeout(left) {
        Ok(line) => match line.strip_prefix(&marker) {
          Some(code) => {
            if output.last().is_some_and(String::is_empty) {
              output.pop();
            }
            return Ok(Ran {
              code: code.trim().parse().unwrap_or(-1),
              output,
              seconds: started.elapsed().as_secs_f64(),
            });
          }
          None => output.push(line),
        },
        Err(RecvTimeoutError::Timeout) => return Err(timed_out()),
        Err(RecvTimeoutError::Disconnected) => {
          return Err(Error::Guest(format!("the console closed during {script:?}")));
        }
      }
    }
  }

  /// As `run`, failing unless the script exits 0.
  pub fn check(&mut self, script: &str, timeout: Duration) -> Result<Ran> {
    let ran = self.run(script, timeout)?;

    if ran.code == 0 {
      Ok(ran)
    } else {
      let tail = ran.output[ran.output.len().saturating_sub(20)..].join("\n");

      Err(Error::Guest(format!(
        "{script:?} exited {} after {:.1}s: {tail}",
        ran.code, ran.seconds
      )))
    }
  }
}
