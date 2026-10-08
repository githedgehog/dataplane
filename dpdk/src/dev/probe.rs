// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Explicit PCI device attachment.

use crate::eal::Eal;
use errno::ErrorCode;
use hardware::pci::address::PciAddress;

/// Failure to attach a PCI device to DPDK.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// The EAL was initialized with PCI disabled.
    #[error("cannot probe PCI device {address}: PCI is disabled")]
    PciDisabled { address: PciAddress },
    /// The device could not be found or attached by a driver.
    #[error("failed to probe PCI device {address}: {source}")]
    Driver {
        address: PciAddress,
        #[source]
        source: ErrorCode,
    },
}

impl Eal {
    /// Attach one PCI device using its current kernel-driver binding.
    ///
    /// Initialize with `--no-auto-probing` and no allowlist to defer attachment to this call.
    /// Exclusive EAL access keeps probing on its owner thread, before resources are borrowed.
    /// A successful probe may expose multiple ports; enumerate and claim them separately.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError`] if PCI is disabled or the device cannot be attached.
    ///
    /// ```compile_fail,E0502
    /// # use dataplane_dpdk::{eal::Eal, mem::{PoolConfig, PoolParams}};
    /// # use hardware::pci::address::PciAddress;
    /// fn probe_with_live_resources(eal: &mut Eal, address: PciAddress) {
    ///     let pool = eal.mem.new_pkt_pool(PoolConfig::new("rx", PoolParams::default()).unwrap()).unwrap();
    ///     eal.probe_pci(address).unwrap();
    ///     let _batch = pool.alloc_bulk(1);
    /// }
    /// ```
    pub fn probe_pci(&mut self, address: PciAddress) -> Result<(), ProbeError> {
        if !self.has_pci() {
            return Err(ProbeError::PciDisabled { address });
        }

        // PciAddress formats numeric components only, so this has exactly one trailing NUL.
        let args = format!("pci:{address}\0");
        // SAFETY: EAL is live and exclusively borrowed; args is a valid C string for this call.
        let ret = unsafe { dpdk_sys::rte_dev_probe(args.as_ptr().cast()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ProbeError::Driver {
                address,
                source: ErrorCode::parse_i32(ret),
            })
        }
    }
}
