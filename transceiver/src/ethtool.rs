// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reading module memory through the kernel's ethtool netlink interface ([`ethtool2`]), which
//! addresses memory by page and bank as CMIS needs.
//!
//! The kernel requires `CAP_NET_ADMIN` for these reads, and services each one inside the sending
//! syscall, usually as a firmware transaction on the module's two-wire bus: an async socket does not
//! keep the thread that drives it from waiting. Drive reads from a runtime on a thread that may
//! block.

use ethtool2::{EepromWindow, Handle, WindowError};

use crate::capture::{Capture, ReadError};
use crate::memory::{Block, Image, Region};
use crate::module::Module;

/// Why a read through ethtool netlink failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The kernel refused the read or the exchange failed. Of note: [`ethtool2::Error::Unsupported`]
    /// (the driver cannot read modules), [`ethtool2::Error::PermissionDenied`] (no
    /// `CAP_NET_ADMIN`), and [`ethtool2::Error::Kernel`] with `EIO` (no module plugged in).
    #[error(transparent)]
    Ethtool(#[from] ethtool2::Error),
    /// The kernel answered with something other than half a page.
    #[error("expected half a page of module memory, got {0} bytes")]
    WrongLength(usize),
    /// The region does not map to a request the kernel accepts; a bug in this crate.
    #[error("region {0:?} is not a valid ethtool request")]
    Window(Region, #[source] WindowError),
}

/// The memory of the module plugged into one network device.
#[derive(Clone)]
pub struct EthtoolEeprom {
    handle: Handle,
    ifindex: u32,
}

impl EthtoolEeprom {
    /// Read the module of the device with index `ifindex` over `handle`, whose socket must be in the
    /// device's network namespace.
    #[must_use]
    pub fn new(handle: Handle, ifindex: u32) -> Self {
        Self { handle, ifindex }
    }

    /// Read one region.
    ///
    /// # Errors
    ///
    /// Fails if the kernel refuses or the exchange fails; see [`Error`].
    pub async fn read(&self, region: Region) -> Result<Block, Error> {
        let window = match region {
            Region::Lower(address) => EepromWindow::lower(address.seven_bit()),
            Region::Upper {
                address,
                bank,
                page,
            } => EepromWindow::upper(address.seven_bit(), page, bank),
        }
        .map_err(|error| Error::Window(region, error))?;
        let data = self.handle.module_eeprom(self.ifindex, window).await?;
        Block::try_from(data.as_slice()).map_err(|_| Error::WrongLength(data.len()))
    }

    /// Drive `capture` to completion; see [`Capture::supply`].
    ///
    /// # Errors
    ///
    /// Fails if the module's identity could not be read or the result could not be decoded.
    pub async fn capture(&self, mut capture: Capture) -> Result<(Module, Image), ReadError<Error>> {
        while let Some(region) = capture.next_region() {
            let read = self.read(region).await;
            capture.supply(region, read)?;
        }
        Ok(capture.finish()?)
    }
}
