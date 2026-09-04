// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Transmit queue configuration and management.

use crate::dev::DevIndex;
use crate::mem::{MBUF_BURST, MbufArray};
use crate::socket::SocketId;
use crate::{dev, socket};
use core::marker::PhantomData;
use core::ptr::null_mut;
use errno::ErrorCode;
use std::cmp::min;
use tracing::trace;

/// A DPDK transmit queue index.
///
/// This is a newtype around `u16` to provide type safety and prevent accidental misuse.
// #[non_exhaustive] // TODO: make non_exhaustive again
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxQueueIndex(pub u16);

impl TxQueueIndex {
    /// The index of the tx queue represented as a `u16`.
    ///
    /// This function is mostly useful for interfacing with `dpdk_sys`.
    #[must_use]
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl From<TxQueueIndex> for u16 {
    fn from(value: TxQueueIndex) -> u16 {
        value.as_u16()
    }
}

impl From<u16> for TxQueueIndex {
    fn from(value: u16) -> TxQueueIndex {
        TxQueueIndex(value)
    }
}

/// Configuration for a DPDK transmit queue.
#[derive(Debug, Clone)]
pub struct TxQueueConfig {
    /// The index of the tx queue.
    pub queue_index: TxQueueIndex,
    /// The number of descriptors in the tx queue.
    pub num_descriptors: u16,
    /// The socket preference for the tx queue.
    pub socket_preference: socket::Preference,
    /// The low-level configuration of the tx queue.
    pub config: (), // TODO
}

/// Error type for transmit queue configuration failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigFailure {
    #[error("Memory allocation failed: {0}")]
    NoMemory(ErrorCode),
    #[error("An unexpected error occurred {0}")]
    Unexpected(ErrorCode),
    #[error("The socket preference setting did not resolve a known socket: {0}")]
    InvalidSocket(ErrorCode),
}

impl TxQueue<'_> {
    /// Configure a new [`TxQueueStopped`].
    ///
    /// This method is crate internal.
    /// The library end user should call this by way of the
    /// [`Dev::configure_tx_queue`] method.
    ///
    /// This design ensures that the hairpin queue is correctly tracked in the list of queues
    /// associated with the device.
    pub(crate) fn setup(dev: &dev::Dev, config: TxQueueConfig) -> Result<Self, ConfigFailure> {
        let socket_id: SocketId = config
            .socket_preference
            .try_into()
            .map_err(ConfigFailure::InvalidSocket)?;

        // Clamp the requested ring size to the driver's min/max/alignment limits rather than
        // passing a possibly-illegal raw value.  DPDK adjusts both the rx and tx counts in a single
        // call; we only consume the tx result here (`nb_rx_desc` is required by the API but unused).
        let mut nb_rx_desc = config.num_descriptors;
        let mut nb_tx_desc = config.num_descriptors;
        let adjust = unsafe {
            dpdk_sys::rte_eth_dev_adjust_nb_rx_tx_desc(
                dev.info.index().as_u16(),
                &mut nb_rx_desc,
                &mut nb_tx_desc,
            )
        };
        match adjust {
            errno::SUCCESS => {}
            errno::NEG_ENOMEM => return Err(ConfigFailure::NoMemory(ErrorCode::parse(adjust))),
            _ => return Err(ConfigFailure::Unexpected(ErrorCode::parse(adjust))),
        }

        let tx_conf = dpdk_sys::rte_eth_txconf {
            offloads: dev.info.inner.tx_queue_offload_capa,
            // The remaining fields (threshold registers, `tx_free_thresh`, `tx_rs_thresh`) are left
            // zeroed on purpose: DPDK reads zero here as "use the PMD's per-driver defaults".
            ..Default::default()
        };
        let ret = unsafe {
            dpdk_sys::rte_eth_tx_queue_setup(
                dev.info.index().as_u16(),
                config.queue_index.as_u16(),
                nb_tx_desc,
                socket_id.as_c_uint(),
                &tx_conf,
            )
        };

        match ret {
            errno::SUCCESS => Ok(TxQueue {
                dev: dev.info.index(),
                config,
                _dev: PhantomData,
            }),
            errno::NEG_ENOMEM => Err(ConfigFailure::NoMemory(ErrorCode::parse(ret))),
            _ => Err(ConfigFailure::Unexpected(ErrorCode::parse(ret))),
        }
    }

    /// Start the transmit queue.
    pub(crate) fn start(&mut self) -> Result<(), TxQueueStartError> {
        match unsafe {
            dpdk_sys::rte_eth_dev_tx_queue_start(
                self.dev.as_u16(),
                self.config.queue_index.as_u16(),
            )
        } {
            errno::SUCCESS => Ok(()),
            errno::NEG_ENODEV => Err(TxQueueStartError::DeviceRemoved),
            errno::NEG_EINVAL => Err(TxQueueStartError::InvalidArgument),
            errno::NEG_EIO => Err(TxQueueStartError::DeviceRemoved),
            errno::NEG_ENOTSUP => Err(TxQueueStartError::NotSupported),
            unexpected => Err(TxQueueStartError::Unknown(ErrorCode::parse(unexpected))),
        }
    }

    /// Stop the transmit queue.
    #[allow(unused)]
    pub(crate) fn stop(&mut self) -> Result<(), TxQueueStopError> {
        let ret = unsafe {
            dpdk_sys::rte_eth_dev_tx_queue_stop(self.dev.as_u16(), self.config.queue_index.as_u16())
        };

        match ret {
            errno::SUCCESS => Ok(()),
            errno::NEG_ENODEV => Err(TxQueueStopError::DeviceRemoved),
            errno::NEG_EINVAL => Err(TxQueueStopError::InvalidArgument),
            errno::NEG_EIO => Err(TxQueueStopError::DeviceRemoved),
            errno::NEG_ENOTSUP => Err(TxQueueStopError::NotSupported),
            val => Err(TxQueueStopError::Unknown(errno::Errno(val))),
        }
    }

    pub(crate) const PKT_BURST_SIZE: usize = 64;

    /// Transmit a batch of packets on this queue, returning the packets that could not be sent.
    ///
    /// Ownership of every successfully transmitted mbuf passes to the PMD, which frees it once the
    /// transmit descriptor is reclaimed, so those mbufs must *not* be freed by us.  Any packets the
    /// queue would not accept (because it is full, paused, or the link is down) are returned in the
    /// resulting [`MbufArray`]; the caller may retry them or drop the array to discard them.  This
    /// also bounds the work: the burst loop stops as soon as the queue stops making progress rather
    /// than spinning forever.
    #[must_use = "the returned MbufArray holds packets that were NOT transmitted; retry or drop it"]
    #[tracing::instrument(level = "trace", skip(packets))]
    pub fn transmit(&mut self, packets: MbufArray) -> MbufArray {
        let len = packets.len();
        if len == 0 {
            return MbufArray::new_empty();
        }
        // Copy the mbufs out as raw pointers into an inline array (no heap).  `Mbuf::into_raw`
        // suppresses the per-mbuf `Drop`, so from here on ownership is tracked purely by index:
        // nothing is freed implicitly.  `len <= MBUF_BURST` since that is the input's capacity.
        let mut raw = [null_mut::<dpdk_sys::rte_mbuf>(); MBUF_BURST];
        for (slot, mbuf) in raw.iter_mut().zip(packets) {
            *slot = mbuf.into_raw();
        }
        let mut offset = 0;
        while offset < len {
            trace!(
                "Transmitting packets to tx queue {queue} on dev {dev}",
                queue = self.config.queue_index.as_u16(),
                dev = self.dev.as_u16()
            );
            let nb_tx = unsafe {
                dpdk_sys::rte_eth_tx_burst(
                    self.dev.as_u16(),
                    self.config.queue_index.as_u16(),
                    raw.as_mut_ptr().add(offset),
                    min(Self::PKT_BURST_SIZE, len - offset) as u16,
                )
            } as usize;
            trace!(
                "Transmitted {nb_tx} packets from tx queue {queue} on dev {dev}",
                queue = self.config.queue_index.as_u16(),
                dev = self.dev.as_u16()
            );
            if nb_tx == 0 {
                // The queue is not accepting packets right now.  Stop rather than spin; the
                // unsent tail is returned to the caller below.
                break;
            }
            offset += nb_tx;
        }
        // `[0, offset)` were accepted and are now owned by the PMD (their raw pointers are simply
        // dropped here).  `[offset, len)` are still ours; re-wrap them so the returned `MbufArray`
        // frees them exactly once if the caller drops it.
        //
        // SAFETY: each tail pointer came from a live `Mbuf` via `into_raw` and was not handed to
        // the PMD, so it is still a valid, singly-owned mbuf; `len - offset <= MBUF_BURST`.
        unsafe { MbufArray::from_raw_ptrs(&raw[offset..len]) }
    }
}

/// An exclusively-owned handle to one of a device's transmit queues.
///
/// # Exclusivity
///
/// DPDK's contract is that `rte_eth_tx_burst` must not be called concurrently for the same queue:
/// one queue, one thread. [`transmit`](Self::transmit) therefore takes `&mut self`, and a handle
/// is handed out exactly once by [`Queues::take_tx`](crate::queue::Queues::take_tx) -- so two
/// workers transmitting on the same queue is a borrow error rather than a data race.
///
/// # Lifetime
///
/// See [`RxQueue`](crate::queue::rx::RxQueue); the same branding and the same reason for having
/// no [`Drop`] impl apply here.
#[derive(Debug)]
pub struct TxQueue<'dev> {
    pub(crate) config: TxQueueConfig,
    pub(crate) dev: DevIndex,
    pub(crate) _dev: PhantomData<&'dev ()>,
}

/// TODO
#[derive(thiserror::Error, Debug)]
pub enum TxQueueStartError {
    #[error("Invalid port ID")]
    InvalidPortId,
    #[error("Queue ID out of range")]
    QueueIdOutOfRange,
    #[error("Device removed")]
    DeviceRemoved,
    #[error("Invalid argument")]
    InvalidArgument,
    #[error("Operation not supported")]
    NotSupported,
    #[error("Unknown error: {0}")]
    Unknown(ErrorCode),
}

#[repr(i32)]
#[derive(thiserror::Error, Debug)]
pub enum TxQueueStopError {
    #[error("Invalid port ID")]
    InvalidPortId = errno::NEG_ENODEV,
    #[error("Device removed")]
    DeviceRemoved = errno::NEG_EIO,
    #[error("Invalid argument")]
    InvalidArgument = errno::NEG_EINVAL,
    #[error("Operation not supported")]
    NotSupported = errno::NEG_ENOTSUP,
    #[error("Unknown error")]
    Unknown(errno::Errno),
}
