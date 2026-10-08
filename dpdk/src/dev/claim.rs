// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Exclusive ownership of ethernet ports.
//!
//! [`DevConfig::apply`](super::DevConfig::apply) requires a [`PortClaim`] to prevent duplicate
//! configuration and reject ports owned by another DPDK component.
//! DPDK's owner API is advisory; this crate enforces it through the claim type.

use super::{DevIndex, DevInfo, DevInfoError, Manager};
use alloc::string::String;
use concurrency::sync::atomic::{AtomicBool, Ordering};
use core::ffi::{CStr, c_char};
use core::fmt::{Display, Formatter};
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use errno::Errno;
use tracing::{debug, error, warn};

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
}

/// The EAL's port owner ID and persistent teardown-failure record.
///
/// `rte_eth_dev_close` removes the owner record even when the driver fails to close.
/// Remember failures here so EAL teardown retains mempools the driver may still reference.
#[derive(Debug)]
pub(crate) struct Ownership {
    id: OwnerId,
    /// Set when a close fails or an abandoned port cannot be closed; never cleared. A failed stop
    /// leaves the port owned, so `close_abandoned` still sees it.
    teardown_failed: AtomicBool,
}

impl Ownership {
    /// Allocate a fresh owner id with a clean teardown record.
    pub(crate) fn new() -> Result<Ownership, Errno> {
        Ok(Ownership {
            id: OwnerId::new()?,
            teardown_failed: AtomicBool::new(false),
        })
    }

    /// An unregistered owner for tests that make no port calls.
    #[cfg(test)]
    pub(crate) fn unregistered() -> Ownership {
        Ownership {
            id: OwnerId(0),
            teardown_failed: AtomicBool::new(false),
        }
    }

    /// Record that a port may still reference its mempools after a failed teardown.
    pub(crate) fn record_teardown_failure(&self) {
        self.teardown_failed.store(true, Ordering::Relaxed);
    }

    /// Whether any port's teardown failed, so its driver may still reference the mempools.
    pub(crate) fn teardown_failed(&self) -> bool {
        self.teardown_failed.load(Ordering::Relaxed)
    }

    /// Close owned ports abandoned by leaked handles or failed teardown.
    /// Called before pool release, after all queue users have finished.
    #[cold]
    pub(crate) fn close_abandoned(&self) -> AbandonedPorts {
        let mut report = AbandonedPorts::default();
        let mut cursor = 0u16;
        loop {
            // SAFETY: plain FFI query on an id from `rte_eth_dev_owner_new`.
            let next = unsafe { dpdk_sys::rte_eth_find_next_owned_by(cursor, self.id.0) };
            let Ok(port) = u16::try_from(next) else {
                break;
            };
            if port >= DevIndex::MAX {
                break;
            }
            warn!("port {port} was never closed; closing it at EAL teardown");
            // SAFETY: `port` is a valid port id owned by this EAL, and no queue handle for it
            // can still exist (see above).
            let stopped = unsafe { dpdk_sys::rte_eth_dev_stop(port) };
            // Closing a port that failed to stop is not valid.
            let closed = if stopped == 0 {
                // SAFETY: as above, and the port is stopped.
                unsafe { dpdk_sys::rte_eth_dev_close(port) }
            } else {
                stopped
            };
            if closed == 0 {
                report.closed += 1;
            } else {
                error!("could not close abandoned port {port}: {closed}");
                self.record_teardown_failure();
                report.stuck += 1;
            }
            let Some(after) = port.checked_add(1) else {
                break;
            };
            cursor = after;
        }
        report
    }

    /// Delete this owner ID and release any remaining claims at EAL teardown.
    pub(crate) fn release_all(&self) {
        // SAFETY: plain FFI call on an id from `rte_eth_dev_owner_new`.
        let ret = unsafe { dpdk_sys::rte_eth_dev_owner_delete(self.id.0) };
        if ret != 0 {
            warn!("failed to release port ownership at EAL teardown: {ret}");
        }
    }
}

/// Results of closing abandoned ports during EAL teardown.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub(crate) struct AbandonedPorts {
    /// Ports that were still open and have now been closed.
    pub(crate) closed: u16,
    /// Ports that could not be stopped or closed, and so may still reference their mempools.
    pub(crate) stuck: u16,
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
    owner: &'eal Ownership,
    _thread: PhantomData<*const ()>,
}

impl<'eal> PortClaim<'eal> {
    /// Read the port information, then claim it; a failed lookup leaves ownership unchanged.
    /// Lookup, claim, and close all run on the EAL thread, preventing port reuse between calls.
    /// Hotplug is not supported.
    pub(crate) fn claim(
        owner: &'eal Ownership,
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
    pub(crate) fn new(
        owner: &'eal Ownership,
        info: DevInfo<'eal>,
    ) -> Result<PortClaim<'eal>, ClaimError> {
        let port = info.index();
        let record = PortOwner::current().encode(owner.id);
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

    /// Hand the claim to a device, which releases it by closing the port and reports a failed
    /// teardown to the returned [`Ownership`].
    pub(crate) fn into_parts(self) -> (DevInfo<'eal>, &'eal Ownership) {
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is never used or dropped again, so `info` is moved out exactly once.
        let info = unsafe { core::ptr::read(&raw const this.info) };
        (info, this.owner)
    }
}

impl Drop for PortClaim<'_> {
    fn drop(&mut self) {
        let port = self.info.index();
        // SAFETY: plain FFI call; the port and id are both ours.
        let ret = unsafe { dpdk_sys::rte_eth_dev_owner_unset(port.as_u16(), self.owner.id.0) };
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
    use super::{
        AbandonedPorts, ClaimError, ForeignOwner, OwnerId, Ownership, PortClaim, PortOwner,
    };
    use crate::dev::{DevConfig, DevIndex, RssConf, RxOffload, TxOffloadConfig};
    use crate::queue::rx::{RxQueueConfig, RxQueueIndex};
    use crate::queue::tx::{TxQueueConfig, TxQueueIndex};
    use crate::socket::{Preference, SocketId};
    use crate::test_support::{RingPort, packet_pool, start_eal};
    use core::ffi::CStr;

    #[test]
    fn a_port_has_one_claim_at_a_time() {
        let shared = start_eal();
        let ring = RingPort::new();
        let info = || shared.dev().info(ring.index).unwrap();
        let owner = Ownership::new().unwrap();

        let first = PortClaim::new(&owner, info()).unwrap();
        assert!(
            shared.dev().iter().all(|dev| dev.index() != ring.index),
            "a claimed port must drop out of iteration"
        );
        match PortClaim::new(&owner, info()) {
            Err(ClaimError::AlreadyOwned { port, owner }) => {
                assert_eq!(port, ring.index);
                assert_eq!(owner, PortOwner::current());
            }
            other => panic!("expected AlreadyOwned, got {other:?}"),
        }

        drop(first);
        drop(PortClaim::new(&owner, info()).expect("dropping a claim releases the port"));
    }

    #[test]
    fn iteration_skips_a_claimed_port_before_an_available_port() {
        let shared = start_eal();
        let first = RingPort::new();
        let second = first.another();
        assert!(first.index < second.index);
        let owner = Ownership::new().unwrap();
        let _claim = PortClaim::new(&owner, shared.dev().info(first.index).unwrap()).unwrap();

        let available: Vec<_> = shared.dev().iter().map(|dev| dev.index()).collect();
        assert_eq!(available, [second.index]);
    }

    #[test]
    fn a_close_error_does_not_close_a_reused_port() {
        let shared = start_eal();
        let ring = RingPort::new();
        let owner = Ownership::new().unwrap();
        let config = DevConfig {
            num_rx_queues: 0,
            num_tx_queues: 0,
            num_hairpin_queues: 0,
            tx_offloads: TxOffloadConfig::none(),
            rx_offloads: RxOffload::NONE,
            mtu: None,
            rss: None,
        };
        let claim = PortClaim::new(&owner, shared.dev().info(ring.index).unwrap()).unwrap();
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
        let owner = Ownership::new().unwrap();
        // The test EAL runs with `--no-pci` and creates ring ports from the bottom of the port
        // table, so the last slot is never in use.
        let missing = DevIndex(DevIndex::MAX - 1);
        match PortClaim::claim(&owner, shared.dev(), missing) {
            Err(ClaimError::NoSuchPort { port }) => assert_eq!(port, missing),
            other => panic!("expected NoSuchPort, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_apply_keeps_the_claim() {
        let shared = start_eal();
        let ring = RingPort::new();
        let info = || shared.dev().info(ring.index).unwrap();
        let owner = Ownership::new().unwrap();
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
            .apply(PortClaim::new(&owner, info()).unwrap())
            .unwrap_err();
        assert!(
            PortClaim::new(&owner, info()).is_err(),
            "the claim must still hold"
        );
        drop(failure);
        drop(PortClaim::new(&owner, info()).expect("dropping the failure releases the port"));
    }

    #[test]
    fn a_leaked_device_is_closed_at_teardown() {
        let shared = start_eal();
        let ring = RingPort::new();
        let owner = Ownership::new().unwrap();
        let config = DevConfig {
            num_rx_queues: 1,
            num_tx_queues: 1,
            num_hairpin_queues: 0,
            tx_offloads: TxOffloadConfig::none(),
            rx_offloads: RxOffload::NONE,
            mtu: None,
            rss: None,
        };
        let claim = PortClaim::new(&owner, shared.dev().info(ring.index).unwrap()).unwrap();
        let mut dev = config.apply(claim).unwrap();
        dev.new_rx_queue(RxQueueConfig {
            queue_index: RxQueueIndex(0),
            num_descriptors: 8,
            socket_preference: Preference::Id(SocketId::ANY),
            offloads: RxOffload::NONE,
            pool: packet_pool(63),
        })
        .unwrap();
        dev.new_tx_queue(TxQueueConfig {
            queue_index: TxQueueIndex(0),
            num_descriptors: 8,
            socket_preference: Preference::Id(SocketId::ANY),
            config: (),
        })
        .unwrap();
        let started = dev.start().unwrap();

        core::mem::forget(started);
        assert_eq!(
            owner.close_abandoned(),
            AbandonedPorts {
                closed: 1,
                stuck: 0
            }
        );
        // SAFETY: plain FFI query.
        let valid = unsafe { dpdk_sys::rte_eth_dev_is_valid_port(ring.index.as_u16()) };
        assert_eq!(valid, 0, "closing releases the port");
        assert_eq!(
            owner.close_abandoned(),
            AbandonedPorts::default(),
            "a closed port is not closed twice"
        );
        assert!(
            !owner.teardown_failed(),
            "closing an abandoned port cleanly lets the pools go"
        );
    }

    #[test]
    fn a_dropped_device_leaves_nothing_abandoned() {
        let shared = start_eal();
        let ring = RingPort::new();
        let owner = Ownership::new().unwrap();
        let config = DevConfig {
            num_rx_queues: 0,
            num_tx_queues: 0,
            num_hairpin_queues: 0,
            tx_offloads: TxOffloadConfig::none(),
            rx_offloads: RxOffload::NONE,
            mtu: None,
            rss: None,
        };
        let claim = PortClaim::new(&owner, shared.dev().info(ring.index).unwrap()).unwrap();
        drop(config.apply(claim).unwrap());
        assert_eq!(owner.close_abandoned(), AbandonedPorts::default());
        assert!(
            !owner.teardown_failed(),
            "a clean close leaves the pools free to release"
        );
    }

    /// A failed close must retain mempools even after the port disappears from the owner scan.
    #[test]
    fn a_failed_close_is_remembered_after_dpdk_forgets_the_port() {
        let shared = start_eal();
        let ring = RingPort::new();
        let owner = Ownership::new().unwrap();
        let config = DevConfig {
            num_rx_queues: 0,
            num_tx_queues: 0,
            num_hairpin_queues: 0,
            tx_offloads: TxOffloadConfig::none(),
            rx_offloads: RxOffload::NONE,
            mtu: None,
            rss: None,
        };
        let claim = PortClaim::new(&owner, shared.dev().info(ring.index).unwrap()).unwrap();
        let dev = config.apply(claim).unwrap();
        // SAFETY: no queues exist. Release the port behind the device's back, so its own close
        // fails on a port DPDK no longer lists -- the state a failed driver close leaves.
        assert_eq!(unsafe { dpdk_sys::rte_eth_dev_close(ring.index.0) }, 0);

        dev.close().unwrap_err();
        assert_eq!(
            owner.close_abandoned(),
            AbandonedPorts::default(),
            "DPDK no longer reports the port as owned"
        );
        assert!(
            owner.teardown_failed(),
            "the failed close must still keep the pools allocated"
        );
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
