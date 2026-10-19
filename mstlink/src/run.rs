// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Running `mstlink` as a child process.
//!
//! A child inherits the capabilities of the thread that forks it, so run this from a thread that
//! keeps `CAP_SYS_ADMIN` even if others in the process give theirs up.

use std::ffi::OsString;
use std::time::Duration;

use tokio::process::Command;

use crate::{FecHistogram, ParseError, Pcie, PortReport, Query};

/// Why running `mstlink` gave no answer.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// It could not be started; [`std::io::ErrorKind::NotFound`] means it is not installed.
    #[error("could not run mstlink")]
    Spawn(#[source] std::io::Error),
    /// It did not finish in time, and was killed.
    #[error("mstlink took longer than {0:?}")]
    Timeout(Duration),
    /// It answered with something other than a report.
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// How to run `mstlink`.
#[derive(Debug, Clone)]
pub struct Runner {
    program: OsString,
    timeout: Duration,
}

impl Default for Runner {
    /// `mstlink` from `PATH`, given 10 s: a run takes 0.1 to 0.4 s, unless firmware is busy.
    fn default() -> Self {
        Runner {
            program: "mstlink".into(),
            timeout: Duration::from_secs(10),
        }
    }
}

impl Runner {
    /// Run `program` instead of `mstlink` from `PATH`.
    #[must_use]
    pub fn program(mut self, program: impl Into<OsString>) -> Self {
        self.program = program.into();
        self
    }

    /// Kill a run that takes longer than `timeout`.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Ask `query` of the PCI function at `pci_address`, returning `mstlink`'s raw output.
    ///
    /// The exit status is ignored: `mstlink` exits non-zero for failures it also explains in its
    /// JSON, which the parsers report.
    ///
    /// # Errors
    ///
    /// Fails if `mstlink` cannot be started or overruns the timeout.
    pub async fn run(&self, query: Query, pci_address: &str) -> Result<String, RunError> {
        let child = Command::new(&self.program)
            .args(query.args(pci_address))
            .kill_on_drop(true)
            .output();
        let output = tokio::time::timeout(self.timeout, child)
            .await
            .map_err(|_| RunError::Timeout(self.timeout))?
            .map_err(RunError::Spawn)?;
        // Some failures arrive on stdout as text, others on stderr; JSON is always on stdout.
        let text = if output.stdout.iter().all(u8::is_ascii_whitespace) {
            output.stderr
        } else {
            output.stdout
        };
        Ok(String::from_utf8_lossy(&text).into_owned())
    }

    /// What `mstlink` says about the port of the PCI function at `pci_address`.
    ///
    /// # Errors
    ///
    /// Fails if `mstlink` cannot run, overruns, or answers with a failure.
    pub async fn port(&self, pci_address: &str) -> Result<PortReport, RunError> {
        Ok(PortReport::parse(
            &self.run(Query::Port, pci_address).await?,
        )?)
    }

    /// The port's FEC histogram.
    ///
    /// # Errors
    ///
    /// Fails as [`Runner::port`] does, and while the link runs without FEC.
    pub async fn fec_histogram(&self, pci_address: &str) -> Result<FecHistogram, RunError> {
        Ok(FecHistogram::parse(
            &self.run(Query::FecHistogram, pci_address).await?,
        )?)
    }

    /// The function's PCIe link.
    ///
    /// # Errors
    ///
    /// Fails as [`Runner::port`] does.
    pub async fn pcie(&self, pci_address: &str) -> Result<Pcie, RunError> {
        Ok(Pcie::parse(&self.run(Query::Pcie, pci_address).await?)?)
    }
}
