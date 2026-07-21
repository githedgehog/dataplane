// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Utils for task lifecycle management

use super::Subsystem;
use tracing::error;

/// Drop-guard so panic-unwind, early-`?`, and unexpected normal return
/// all reach [`Subsystem::report_fatal`]. The guard can be disarmed by calling
/// `Self::disarm`  on graceful shutdown paths.
pub struct ExitGuard {
    subsystem: Subsystem,
    id: String,
    armed: bool,
}

impl Subsystem {
    /// Get an [`ExitGuard`] bound to a [`Subsystem`]
    #[must_use]
    pub fn new_exit_guard(&self, id: String, armed: bool) -> ExitGuard {
        ExitGuard::new(self.clone(), id, armed)
    }
}

impl ExitGuard {
    /// Create an [`ExitGuard`]
    #[must_use]
    fn new(subsystem: Subsystem, id: String, armed: bool) -> Self {
        Self {
            subsystem,
            id,
            armed,
        }
    }
    /// Disarm an [`ExitGuard`], which inhibits the report
    /// of a fatal error if the guard is dropped.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for ExitGuard {
    fn drop(&mut self) {
        if !self.armed || self.subsystem.is_cancelled() {
            return;
        }
        let reason = if std::thread::panicking() {
            format!("{} ({}) panicked", self.id, self.subsystem.name)
        } else {
            format!("{} ({}) exited unexpectedly", self.id, self.subsystem.name)
        };
        error!("{reason}. Reporting...");
        self.subsystem.report_fatal(&reason);
    }
}
