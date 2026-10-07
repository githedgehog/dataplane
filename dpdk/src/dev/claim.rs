// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Exclusive ownership of ethernet ports.
//!
//! [`DevConfig::apply`](super::DevConfig::apply) requires a [`PortClaim`] to prevent duplicate
//! configuration and reject ports owned by another DPDK component.
//! DPDK's owner API is advisory; this crate enforces it through the claim type.

use super::{DevIndex, DevInfo, DevInfoError, Manager};
use alloc::string::String;
use core::ffi::{CStr, c_char};
use core::fmt::{Display, Formatter};
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use errno::Errno;
use tracing::{debug, warn};

/// The prefix of the owner name this crate registers. The rest is `/<pid>/<tid>`.
const OWNER_PREFIX: &str = "dataplane";

/// The DPDK owner id under which this EAL claims ports.
///
/// DPDK allocates one ID per [`Eal`](crate::eal::Eal).
/// The owner name identifies the claiming process and thread.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct OwnerId(u64);

impl OwnerId {
    /// Allocate a fresh owner id.
    pub(crate) fn new() -> Result<OwnerId, Errno> {
        let mut id = 0u64;
        // SAFETY: `id` is a valid out-pointer for the duration of the call.
        let ret = unsafe { dpdk_sys::rte_eth_dev_owner_new(&raw mut id) };
        if ret == 0 {
            Ok(OwnerId(id))
        } else {
            Err(Errno::from(-ret))
        }
    }

    /// Delete this owner ID and release any remaining claims at EAL teardown.
    pub(crate) fn release_all(self) {
        // SAFETY: plain FFI call on an id from `rte_eth_dev_owner_new`.
        let ret = unsafe { dpdk_sys::rte_eth_dev_owner_delete(self.0) };
        if ret != 0 {
            warn!("failed to release port ownership at EAL teardown: {ret}");
        }
    }
}

/// Who holds a port, decoded from the name its owner registered with DPDK.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PortOwner {
    /// Claimed through this crate.
    Dataplane {
        /// The claiming process.
        pid: u32,
        /// The claiming thread.
        tid: u32,
    },
    /// Claimed by something else, such as a bonding or failsafe PMD or another DPDK application.
    Foreign(ForeignOwner),
}

/// An owner this crate did not register, identified only by what it told DPDK.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForeignOwner {
    id: u64,
    name: String,
}

impl ForeignOwner {
    /// The owner's DPDK id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The name the owner registered.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl PortOwner {
    /// The calling process and thread.
    fn current() -> PortOwner {
        // SAFETY: `rte_sys_gettid` is a plain syscall wrapper.
        let tid = unsafe { dpdk_sys::rte_sys_gettid() };
        PortOwner::Dataplane {
            pid: std::process::id(),
            tid: tid.cast_unsigned(),
        }
    }

    /// Decode a DPDK owner record.
    fn decode(id: u64, name: &str) -> PortOwner {
        let parsed = name
            .strip_prefix(OWNER_PREFIX)
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.split_once('/'))
            .and_then(|(pid, tid)| Some((pid.parse().ok()?, tid.parse().ok()?)));
        match parsed {
            Some((pid, tid)) => PortOwner::Dataplane { pid, tid },
            None => PortOwner::Foreign(ForeignOwner {
                id,
                name: String::from(name),
            }),
        }
    }

    /// Encode as a DPDK owner record for `id`.
    fn encode(&self, id: OwnerId) -> dpdk_sys::rte_eth_dev_owner {
        // SAFETY: an all-zero `rte_eth_dev_owner` is valid: id 0 and an empty name.
        let mut owner: dpdk_sys::rte_eth_dev_owner = unsafe { core::mem::zeroed() };
        owner.id = id.0;
        let name = self.to_string();
        // Reserve space for the NUL terminator.
        let len = name.len().min(owner.name.len() - 1);
        for (dst, src) in owner.name.iter_mut().zip(&name.as_bytes()[..len]) {
            *dst = *src as c_char;
        }
        owner
    }
}

impl Display for PortOwner {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PortOwner::Dataplane { pid, tid } => write!(f, "{OWNER_PREFIX}/{pid}/{tid}"),
            PortOwner::Foreign(foreign) => {
                write!(f, "\"{}\" (owner id {})", foreign.name, foreign.id)
            }
        }
    }
}

/// Failure to claim a port.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// Another owner holds the port.
    #[error("port {port} is already owned by {owner}")]
    AlreadyOwned {
        /// The contested port.
        port: DevIndex,
        /// Its current owner.
        owner: PortOwner,
    },
    /// No such port.
    #[error("port {port} does not exist")]
    NoSuchPort {
        /// The requested port.
        port: DevIndex,
    },
    /// The port's device information could not be read, so nothing was claimed.
    #[error("port {port}: {source}")]
    Info {
        /// The port.
        port: DevIndex,
        /// Why the information was unavailable.
        source: DevInfoError,
    },
    /// DPDK reported an error it does not document for this call.
    #[error("failed to claim port {port}: {code:?}")]
    Unexpected {
        /// The port.
        port: DevIndex,
        /// The error DPDK returned.
        code: Errno,
    },
}

/// The exclusive right to configure one port.
///
/// Obtained from [`Eal::claim`](crate::eal::Eal::claim) and consumed by
/// [`DevConfig::apply`](super::DevConfig::apply).
/// A claimed port rejects further claims and is excluded from [`Manager::iter`](super::Manager::iter).
/// Dropping an unused claim releases ownership; closing its device releases the port.
///
/// `!Send` and `!Sync`: a port is claimed and configured on the thread that owns the EAL.
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::dev::PortClaim;
/// fn assert_send<T: Send>() {}
/// assert_send::<PortClaim>();
/// ```
#[derive(Debug)]
#[must_use = "dropping a claim releases the port"]
pub struct PortClaim<'eal> {
    info: DevInfo<'eal>,
    owner: OwnerId,
    _thread: PhantomData<*const ()>,
}

impl<'eal> PortClaim<'eal> {
    /// Read the port information, then claim it; a failed lookup leaves ownership unchanged.
    /// Lookup, claim, and close all run on the EAL thread, preventing port reuse between calls.
    /// Hotplug is not supported.
    pub(crate) fn claim(
        owner: OwnerId,
        dev: &'eal Manager,
        index: DevIndex,
    ) -> Result<PortClaim<'eal>, ClaimError> {
        let info = dev.info(index).map_err(|source| match source {
            // `rte_eth_dev_info_get` reports a port that does not exist as ENODEV.
            DevInfoError::NotAvailable => ClaimError::NoSuchPort { port: index },
            source => ClaimError::Info {
                port: index,
                source,
            },
        })?;
        PortClaim::new(owner, info)
    }

    /// Claim `info`'s port for `owner`.
    pub(crate) fn new(owner: OwnerId, info: DevInfo<'eal>) -> Result<PortClaim<'eal>, ClaimError> {
        let port = info.index();
        let record = PortOwner::current().encode(owner);
        // SAFETY: `record` is a valid owner struct for the duration of the call.
        let ret = unsafe { dpdk_sys::rte_eth_dev_owner_set(port.as_u16(), &raw const record) };
        match ret {
            0 => {
                debug!("claimed port {port} as {}", PortOwner::current());
                Ok(PortClaim {
                    info,
                    owner,
                    _thread: PhantomData,
                })
            }
            errno::NEG_EPERM => Err(ClaimError::AlreadyOwned {
                port,
                owner: current_owner(port),
            }),
            errno::NEG_ENODEV => Err(ClaimError::NoSuchPort { port }),
            _ => Err(ClaimError::Unexpected {
                port,
                code: Errno::from(-ret),
            }),
        }
    }

    /// The claimed device.
    #[must_use]
    pub fn info(&self) -> &DevInfo<'eal> {
        &self.info
    }

    /// Hand the claim to a device, which releases it by closing the port.
    pub(crate) fn into_info(self) -> DevInfo<'eal> {
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is never used or dropped again, so `info` is moved out exactly once.
        unsafe { core::ptr::read(&raw const this.info) }
    }
}

impl Drop for PortClaim<'_> {
    fn drop(&mut self) {
        let port = self.info.index();
        // SAFETY: plain FFI call; the port and id are both ours.
        let ret = unsafe { dpdk_sys::rte_eth_dev_owner_unset(port.as_u16(), self.owner.0) };
        if ret != 0 {
            warn!("failed to release port {port}: {ret}");
        }
    }
}

/// Read who currently owns `port`.
fn current_owner(port: DevIndex) -> PortOwner {
    // SAFETY: an all-zero `rte_eth_dev_owner` is a valid out-parameter.
    let mut record: dpdk_sys::rte_eth_dev_owner = unsafe { core::mem::zeroed() };
    // SAFETY: `record` is a valid out-pointer for the duration of the call.
    let ret = unsafe { dpdk_sys::rte_eth_dev_owner_get(port.as_u16(), &raw mut record) };
    if ret != 0 {
        return PortOwner::Foreign(ForeignOwner {
            id: 0,
            name: String::from("<unknown>"),
        });
    }
    // SAFETY: DPDK NUL-terminates the name (`strlcpy` into a fixed buffer).
    let name = unsafe { CStr::from_ptr(record.name.as_ptr()) }.to_string_lossy();
    PortOwner::decode(record.id, &name)
}

#[cfg(test)]
mod tests {
    use super::{ClaimError, ForeignOwner, OwnerId, PortClaim, PortOwner};
    use crate::dev::{DevConfig, DevIndex, RssConf, RxOffload, TxOffloadConfig};
    use crate::test_support::{RingPort, start_eal};
    use core::ffi::CStr;

    #[test]
    fn a_port_has_one_claim_at_a_time() {
        let shared = start_eal();
        let ring = RingPort::new();
        let info = || shared.dev().info(ring.index).unwrap();
        let owner = OwnerId::new().unwrap();

        let first = PortClaim::new(owner, info()).unwrap();
        assert!(
            shared.dev().iter().all(|dev| dev.index() != ring.index),
            "a claimed port must drop out of iteration"
        );
        match PortClaim::new(owner, info()) {
            Err(ClaimError::AlreadyOwned { port, owner }) => {
                assert_eq!(port, ring.index);
                assert_eq!(owner, PortOwner::current());
            }
            other => panic!("expected AlreadyOwned, got {other:?}"),
        }

        drop(first);
        drop(PortClaim::new(owner, info()).expect("dropping a claim releases the port"));
    }

    #[test]
    fn iteration_skips_a_claimed_port_before_an_available_port() {
        let shared = start_eal();
        let first = RingPort::new();
        let second = first.another();
        assert!(first.index < second.index);
        let owner = OwnerId::new().unwrap();
        let _claim = PortClaim::new(owner, shared.dev().info(first.index).unwrap()).unwrap();

        let available: Vec<_> = shared.dev().iter().map(|dev| dev.index()).collect();
        assert_eq!(available, [second.index]);
    }

    #[test]
    fn a_close_error_does_not_close_a_reused_port() {
        let shared = start_eal();
        let ring = RingPort::new();
        let owner = OwnerId::new().unwrap();
        let config = DevConfig {
            num_rx_queues: 0,
            num_tx_queues: 0,
            num_hairpin_queues: 0,
            tx_offloads: TxOffloadConfig::none(),
            rx_offloads: RxOffload::NONE,
            mtu: None,
            rss: None,
        };
        let claim = PortClaim::new(owner, shared.dev().info(ring.index).unwrap()).unwrap();
        let dev = config.apply(claim).unwrap();
        // SAFETY: no queues exist. Remove the native port to provoke ENODEV on close.
        assert_eq!(unsafe { dpdk_sys::rte_eth_dev_close(ring.index.0) }, 0);

        let replacement = {
            let error = dev.close().unwrap_err();
            assert_eq!(error.error, errno::ErrorCode::parse_i32(errno::NEG_ENODEV));
            let replacement = ring.another();
            assert_eq!(replacement.index, ring.index);
            replacement
            // The close error is dropped here, after the port ID has been reused.
        };
        // SAFETY: plain port-table query, serialized by the fixture.
        assert_eq!(
            unsafe { dpdk_sys::rte_eth_dev_is_valid_port(replacement.index.0) },
            1
        );
    }

    #[test]
    fn claiming_a_missing_port_reports_no_such_port() {
        let shared = start_eal();
        let owner = OwnerId::new().unwrap();
        // The test EAL runs with `--no-pci` and creates ring ports from the bottom of the port
        // table, so the last slot is never in use.
        let missing = DevIndex(DevIndex::MAX - 1);
        match PortClaim::claim(owner, shared.dev(), missing) {
            Err(ClaimError::NoSuchPort { port }) => assert_eq!(port, missing),
            other => panic!("expected NoSuchPort, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_apply_keeps_the_claim() {
        let shared = start_eal();
        let ring = RingPort::new();
        let info = || shared.dev().info(ring.index).unwrap();
        let owner = OwnerId::new().unwrap();
        // The ring PMD supports no RSS, so this configuration is rejected before DPDK sees it.
        let config = DevConfig {
            num_rx_queues: 1,
            num_tx_queues: 1,
            num_hairpin_queues: 0,
            tx_offloads: TxOffloadConfig::none(),
            rx_offloads: RxOffload::NONE,
            mtu: None,
            rss: Some(RssConf {
                key: None,
                hf: u64::from(dpdk_sys::RTE_ETH_RSS_IP),
            }),
        };

        let failure = config
            .apply(PortClaim::new(owner, info()).unwrap())
            .unwrap_err();
        assert!(
            PortClaim::new(owner, info()).is_err(),
            "the claim must still hold"
        );
        drop(failure);
        drop(PortClaim::new(owner, info()).expect("dropping the failure releases the port"));
    }

    #[test]
    fn dataplane_owners_round_trip_through_the_dpdk_name() {
        let owner = PortOwner::Dataplane {
            pid: 4321,
            tid: 8765,
        };
        let record = owner.encode(OwnerId(7));
        assert_eq!(record.id, 7);
        // SAFETY: `encode` NUL-terminates.
        let name = unsafe { CStr::from_ptr(record.name.as_ptr()) }
            .to_str()
            .unwrap();
        assert_eq!(name, "dataplane/4321/8765");
        assert_eq!(PortOwner::decode(7, name), owner);
    }

    #[test]
    fn other_owners_are_foreign() {
        for name in [
            "net_bonding0",
            "dataplane",
            "dataplane/1",
            "dataplane/x/2",
            "",
        ] {
            assert_eq!(
                PortOwner::decode(3, name),
                PortOwner::Foreign(ForeignOwner {
                    id: 3,
                    name: name.into()
                })
            );
        }
    }
}
