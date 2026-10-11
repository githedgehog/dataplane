// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Captures written as files in a directory.

use crate::controller::{
    CaptureController, CaptureReport, CaptureRequest, CaptureStartError, CaptureStatus,
};
use crate::names::CaptureNames;
use chrono::{DateTime, Utc};
use concurrency::sync::{Arc, Mutex};
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

/// Errors from [`CaptureDirectory::start`].
#[derive(Debug, thiserror::Error)]
pub enum CaptureFileError {
    /// The directory or the file could not be created.
    #[error("failed to create {path}: {source}")]
    Create {
        /// What could not be created.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The capture could not start.
    #[error(transparent)]
    Start(#[from] CaptureStartError),
}

/// Runs captures into files in one directory, each named by its start time.
pub struct CaptureDirectory {
    controller: CaptureController,
    dir: PathBuf,
    /// The file of the most recent capture, for status and stop reports.
    last: Mutex<Option<PathBuf>>,
}

impl CaptureDirectory {
    /// Write the captures `controller` runs into `dir`, creating it when the first capture starts.
    #[must_use]
    pub fn new(controller: CaptureController, dir: impl Into<PathBuf>) -> Self {
        CaptureDirectory {
            controller,
            dir: dir.into(),
            last: Mutex::new(None),
        }
    }

    /// Start a capture into a new file, returning its path.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be created or the capture cannot start (for example because one is already
    /// running), in which case no file is left behind.
    pub fn start(
        &self,
        request: CaptureRequest,
        names: CaptureNames,
    ) -> Result<PathBuf, CaptureFileError> {
        // Checked before a file exists, so that the usual refusal neither creates one nor is mistaken for
        // a name collision. The controller checks again, which covers a race with another caller.
        if matches!(self.controller.status(), CaptureStatus::Running { .. }) {
            return Err(CaptureStartError::AlreadyRunning.into());
        }
        std::fs::create_dir_all(&self.dir).map_err(|source| CaptureFileError::Create {
            path: self.dir.clone(),
            source,
        })?;
        let path = self.dir.join(file_name(clock::system_now().into()));
        // `create_new` so that a capture never overwrites another.
        let file = File::create_new(&path).map_err(|source| CaptureFileError::Create {
            path: path.clone(),
            source,
        })?;
        if let Err(error) = self.controller.start(request, BufWriter::new(file), names) {
            // Best effort: the error being reported matters more than a failure to tidy up after it.
            let _ = std::fs::remove_file(&path);
            return Err(error.into());
        }
        *self.last.lock() = Some(path.clone());
        Ok(path)
    }

    /// Stop the running capture, returning its report and file, or `None` if none was running.
    #[must_use]
    pub fn stop(&self) -> Option<(Arc<CaptureReport>, PathBuf)> {
        let report = self.controller.stop()?;
        Some((report, self.last_file()?))
    }

    /// What the controller is doing, and the file of the running or most recent capture.
    #[must_use]
    pub fn status(&self) -> (CaptureStatus, Option<PathBuf>) {
        (self.controller.status(), self.last_file())
    }

    /// The directory captures are written to.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn last_file(&self) -> Option<PathBuf> {
        self.last.lock().clone()
    }
}

/// `capture-<UTC start time>.pcapng`, sortable and free of characters that need quoting in a shell.
fn file_name(start: DateTime<Utc>) -> String {
    format!("capture-{}.pcapng", start.format("%Y%m%dT%H%M%S%.3fZ"))
}

#[cfg(test)]
mod tests {
    use super::file_name;
    use chrono::{TimeZone, Utc};

    #[test]
    fn file_names_sort_by_start_time() {
        let start = Utc.with_ymd_and_hms(2026, 10, 11, 15, 30, 12).unwrap();
        assert_eq!(file_name(start), "capture-20261011T153012.000Z.pcapng");
    }
}
