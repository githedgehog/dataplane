// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Exclusive ownership of ethernet ports.
//!
//! DPDK lets any code configure any port; its owner API (`rte_eth_dev_owner_*`) is advisory. This
//! module makes claiming a port the only way to obtain the [`PortClaim`] that
//! [`DevConfig::apply`](super::DevConfig::apply) requires, so two configurations of one port, or a
//! port a bonding PMD or another process already owns, cannot be expressed.

use super::{DevIndex, DevInfo, DevInfoError};
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
/// One per [`Eal`](crate::eal::Eal), allocated at init. DPDK accepts only ids it handed out, so the
/// id itself carries no meaning; who claimed a port is recorded in the owner name instead.
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

    /// Release every port still owned by this id. A backstop for EAL teardown: closing a port
    /// already releases it.
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
        // Leave room for the NUL; the name is far shorter than RTE_ETH_MAX_OWNER_NAME_LEN anyway.
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
    /// The port was claimed but its device information could not be read; the claim was released.
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
/// [`DevConfig::apply`](super::DevConfig::apply). While a claim or the device built from it exists,
/// no other claim on the port can succeed, and the port no longer appears in
/// [`Manager::iter`](super::Manager::iter). Dropping an unused claim releases the port; closing the
/// device releases it too.
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
    use crate::dev::{DevConfig, RssConf, RxOffload, TxOffloadConfig};
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
