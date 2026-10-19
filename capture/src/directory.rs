// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Captures written as files.

use crate::controller::{
    CaptureController, CaptureReport, CaptureRequest, CaptureStartError, CaptureStatus,
};
use crate::names::CaptureNames;
use chrono::{DateTime, Utc};
use concurrency::sync::{Arc, Mutex};
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use tracing::warn;

/// The capture file's write buffer: large enough that writing is a syscall every few dozen packets
/// rather than every few. The writer also flushes it on its idle tick.
const WRITE_BUFFER: usize = 64 * 1024;

/// Where a capture is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureTarget {
    /// A file named by its start time, in the configured default directory.
    Default,
    /// A file named by its start time, in this directory.
    Dir(PathBuf),
    /// This file, which must not exist yet.
    File(PathBuf),
}

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
    /// No location was given and no default directory is configured.
    #[error(
        "no capture location: give file=PATH or dir=PATH, or start the dataplane with --capture-dir"
    )]
    NoLocation,
}

/// Runs captures into files, by default in one directory and named by their start time.
pub struct CaptureDirectory {
    controller: CaptureController,
    default_dir: Option<PathBuf>,
    /// The file of the most recent capture, for status and stop reports.
    last: Mutex<Option<PathBuf>>,
}

impl CaptureDirectory {
    /// Run the captures `controller` runs into files, by default in `default_dir`.
    ///
    /// With no default directory, a capture must be told where to go. There is deliberately no
    /// built-in default: the obvious places on a gateway (its runtime directory) are tmpfs, so a large
    /// capture there would eat the node's memory.
    #[must_use]
    pub fn new(controller: CaptureController, default_dir: Option<PathBuf>) -> Self {
        CaptureDirectory {
            controller,
            default_dir,
            last: Mutex::new(None),
        }
    }

    /// Start a capture into a new file at `target`, returning its path.
    ///
    /// # Errors
    ///
    /// Fails if there is nowhere to write, the file cannot be created, or the capture cannot start (for
    /// example because one is already running), in which case no file is left behind.
    pub fn start(
        &self,
        request: CaptureRequest,
        names: CaptureNames,
        target: CaptureTarget,
    ) -> Result<PathBuf, CaptureFileError> {
        // Checked before a file exists, so that the usual refusal neither creates one nor is mistaken for
        // a name collision. The controller checks again, which covers a race with another caller.
        if matches!(self.controller.status(), CaptureStatus::Running { .. }) {
            return Err(CaptureStartError::AlreadyRunning.into());
        }
        let (dir, path) = match target {
            CaptureTarget::File(path) => {
                let dir = path
                    .parent()
                    .filter(|dir| !dir.as_os_str().is_empty())
                    .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
                (dir, path)
            }
            CaptureTarget::Dir(dir) => {
                let path = dir.join(file_name(clock::system_now().into()));
                (dir, path)
            }
            CaptureTarget::Default => {
                let dir = self
                    .default_dir
                    .clone()
                    .ok_or(CaptureFileError::NoLocation)?;
                let path = dir.join(file_name(clock::system_now().into()));
                (dir, path)
            }
        };
        std::fs::create_dir_all(&dir).map_err(|source| CaptureFileError::Create {
            path: dir.clone(),
            source,
        })?;
        warn_if_memory_backed(&dir);
        // `create_new` so that a capture never overwrites another file.
        let file = File::create_new(&path).map_err(|source| CaptureFileError::Create {
            path: path.clone(),
            source,
        })?;
        let out = BufWriter::with_capacity(WRITE_BUFFER, file);
        if let Err(error) = self.controller.start(request, out, names) {
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

    /// The directory captures are written to when not told otherwise, if one is configured.
    #[must_use]
    pub fn default_dir(&self) -> Option<&Path> {
        self.default_dir.as_deref()
    }

    fn last_file(&self) -> Option<PathBuf> {
        self.last.lock().clone()
    }
}

/// Warn when `dir` is on tmpfs: a capture there grows in memory nothing accounts for, and on a node
/// that memory is shared with everything else using `/run`.
fn warn_if_memory_backed(dir: &Path) {
    // Only a warning, and statfs is not something miri can run.
    if cfg!(miri) {
        return;
    }
    if let Ok(fs) = nix::sys::statfs::statfs(dir)
        && fs.filesystem_type() == nix::sys::statfs::TMPFS_MAGIC
    {
        warn!(
            "capturing into {}, which is tmpfs: the capture is held in memory until deleted",
            dir.display()
        );
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
