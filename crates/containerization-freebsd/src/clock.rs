//! Keeps the guest's clock in step with the host's. Like Containerization's
//! TimeSyncer, it syncs every 30 seconds while the machine is not paused.

use crate::agent::Agent;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

const INTERVAL: Duration = Duration::from_secs(30);

/// Syncs the clock from a background thread, which stops when this is dropped.
pub(crate) struct ClockSync {
  paused: Arc<AtomicBool>,
  _stop: mpsc::Sender<()>,
}

impl ClockSync {
  pub(crate) fn start(agent: Agent) -> Self {
    let paused = Arc::new(AtomicBool::new(false));
    let (stop, stopped) = mpsc::channel::<()>();
    let syncing = paused.clone();

    std::thread::spawn(move || {
      while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(INTERVAL) {
        if !syncing.load(Ordering::Relaxed) {
          let _ = agent.sync_clock();
        }
      }
    });
    Self { paused, _stop: stop }
  }

  pub(crate) fn set_paused(&self, paused: bool) {
    self.paused.store(paused, Ordering::Relaxed);
  }
}
