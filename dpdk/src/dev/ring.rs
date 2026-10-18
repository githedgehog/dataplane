// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A virtual cable: two Ethernet devices joined by rings, for tests.
//!
//! Each end is an ordinary ring-PMD port, so code that drives a NIC drives a cable end unchanged.
//! Queue `q` of one end transmits into the ring queue `q` of the other end receives from. Nothing
//! steers or hashes: a frame arrives on the queue it was sent on, so a test chooses which receive
//! queue every frame lands on.
//!
//! The PMD offers no RSS, no `rte_flow` and no offloads, so the code under test takes whatever
//! software paths it has for their absence. It also reports the all-zero MAC address for both
//! ends and cannot be given another, so code that needs one has to be told it.

use core::ffi::{c_char, c_int, c_uint};
use core::ptr::NonNull;
use std::ffi::CString;

use errno::ErrorCode;

use super::DevIndex;
use crate::eal::Eal;

#[link(name = "rte_net_ring", kind = "static")]
unsafe extern "C" {
    // From rte_eth_ring.h, which the bindings do not cover.
    fn rte_eth_from_rings(
        name: *const c_char,
        rx_queues: *const *mut dpdk_sys::rte_ring,
        nb_rx_queues: c_uint,
        tx_queues: *const *mut dpdk_sys::rte_ring,
        nb_tx_queues: c_uint,
        numa_node: c_uint,
    ) -> c_int;
}

/// The longest name `rte_ring_create` accepts, terminator excluded.
const MAX_RING_NAME: usize = dpdk_sys::RTE_RING_NAMESIZE as usize - 1;

/// The longest suffix a cable adds to its name to name a ring: direction and queue number.
const LONGEST_RING_SUFFIX: &str = "_ab65535";

/// Failure to make a [`RingCable`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RingCableError {
    /// The cable's name is empty, too long, or not made of letters, digits, `_` and `-`.
    #[error("invalid ring cable name {0:?}")]
    InvalidName(String),
    /// A cable needs at least one queue.
    #[error("a ring cable needs at least one queue")]
    NoQueues,
    /// Ring sizes must be powers of two of at least 2.
    #[error("ring size {0} is not a power of two of at least 2")]
    InvalidRingSize(u32),
    /// A ring could not be created.
    #[error("failed to create ring {name}: {source}")]
    Ring {
        name: String,
        #[source]
        source: ErrorCode,
    },
    /// A ring-PMD port could not be created over the rings.
    #[error("failed to create ring port {name}: {source}")]
    Port {
        name: String,
        #[source]
        source: ErrorCode,
    },
}

/// Two Ethernet devices joined by rings: what [`RingCable::a`] transmits on queue `q`,
/// [`RingCable::b`] receives on queue `q`, and the other way round.
///
/// The devices are unclaimed and unconfigured; claim and set each up like any other port, with up
/// to [`RingCable::queues`] receive and transmit queues.
///
/// A cable is never taken apart. Its rings back two devices that may be started by anyone holding
/// their indices, and freeing a ring under a device still polling it would be a use after free;
/// a few rings per test process is a small price for not having to reason about that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingCable {
    /// One end.
    pub a: DevIndex,
    /// The other end.
    pub b: DevIndex,
    /// How many queue pairs each end has.
    pub queues: u16,
}

impl Eal {
    /// Make a [`RingCable`] named `name` with `queues` queue pairs, each direction of each a ring of
    /// `ring_size` slots (one fewer usable).
    ///
    /// The ends' device names are `<name>_a` and `<name>_b`; the rings are named after them.
    /// `name` must be unique in the process and short enough to leave room in DPDK's ring names
    /// for a direction and queue suffix: 20 characters.
    ///
    /// # Errors
    ///
    /// Returns [`RingCableError`] for a bad name, queue count or ring size, or if DPDK cannot make
    /// a ring or a port. Rings made before a failure are not freed.
    pub fn attach_ring_cable(
        &mut self,
        name: &str,
        queues: u16,
        ring_size: u32,
    ) -> Result<RingCable, RingCableError> {
        if name.is_empty()
            || name.len() > MAX_RING_NAME - LONGEST_RING_SUFFIX.len()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(RingCableError::InvalidName(name.to_string()));
        }
        if queues == 0 {
            return Err(RingCableError::NoQueues);
        }
        if ring_size < 2 || !ring_size.is_power_of_two() {
            return Err(RingCableError::InvalidRingSize(ring_size));
        }

        // Ring `<name>_ab<q>` carries queue `q` from a to b, `<name>_ba<q>` from b to a.
        let a_to_b = rings(&format!("{name}_ab"), queues, ring_size)?;
        let b_to_a = rings(&format!("{name}_ba"), queues, ring_size)?;
        let a = ring_port(&format!("{name}_a"), &b_to_a, &a_to_b, queues)?;
        let b = ring_port(&format!("{name}_b"), &a_to_b, &b_to_a, queues)?;
        Ok(RingCable { a, b, queues })
    }
}

/// `count` rings named `<prefix><q>`.
fn rings(
    prefix: &str,
    count: u16,
    size: u32,
) -> Result<Vec<NonNull<dpdk_sys::rte_ring>>, RingCableError> {
    (0..count)
        .map(|q| {
            let name = format!("{prefix}{q}");
            let c_name = CString::new(name.as_str())
                .map_err(|_| RingCableError::InvalidName(name.clone()))?;
            // SAFETY: the EAL is initialized (`Eal` exists) and `c_name` is a valid C string.
            // SOCKET_ID_ANY is -1; flags 0 is multi-producer, multi-consumer, which is always safe.
            let ring = unsafe { dpdk_sys::rte_ring_create(c_name.as_ptr(), size, -1, 0) };
            NonNull::new(ring).ok_or_else(|| RingCableError::Ring {
                name,
                // SAFETY: reads this thread's rte_errno, which the failed call just set.
                source: ErrorCode::parse_i32(unsafe { dpdk_sys::rte_errno_get() }),
            })
        })
        .collect()
}

/// A ring-PMD port named `name`, receiving queue `q` from `rx[q]` and transmitting it to `tx[q]`,
/// for each of its `queues` queues.
fn ring_port(
    name: &str,
    rx: &[NonNull<dpdk_sys::rte_ring>],
    tx: &[NonNull<dpdk_sys::rte_ring>],
    queues: u16,
) -> Result<DevIndex, RingCableError> {
    debug_assert!(rx.len() == usize::from(queues) && tx.len() == usize::from(queues));
    let c_name = CString::new(name).map_err(|_| RingCableError::InvalidName(name.to_string()))?;
    let rx: Vec<*mut dpdk_sys::rte_ring> = rx.iter().map(|r| r.as_ptr()).collect();
    let tx: Vec<*mut dpdk_sys::rte_ring> = tx.iter().map(|r| r.as_ptr()).collect();
    // SAFETY: the EAL is initialized, the name is a valid C string and both arrays hold live rings
    // that are never freed (see `RingCable`). DPDK copies the arrays.
    let port = unsafe {
        rte_eth_from_rings(
            c_name.as_ptr(),
            rx.as_ptr(),
            c_uint::from(queues),
            tx.as_ptr(),
            c_uint::from(queues),
            dpdk_sys::rte_socket_id(),
        )
    };
    u16::try_from(port)
        .map(DevIndex)
        .map_err(|_| RingCableError::Port {
            name: name.to_string(),
            // SAFETY: reads this thread's rte_errno, which the failed call just set.
            source: ErrorCode::parse_i32(unsafe { dpdk_sys::rte_errno_get() }),
        })
}
