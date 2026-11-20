// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Transmit queue configuration and management.

use crate::dev::DevIndex;
use crate::mem::MbufArray;
use crate::socket::SocketId;
use crate::{dev, socket};
use core::marker::PhantomData;
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
#[non_exhaustive]
pub enum ConfigFailure {
    #[error("transmit queue {} is already configured on this device", .0.as_u16())]
    AlreadyConfigured(TxQueueIndex),
    #[error(
        "transmit queue {} is beyond the {configured} the device was configured with",
        .index.as_u16()
    )]
    OutOfRange {
        index: TxQueueIndex,
        configured: u16,
    },
    #[error("Memory allocation failed: {0}")]
    NoMemory(ErrorCode),
    #[error("An unexpected error occurred {0}")]
    Unexpected(ErrorCode),
    #[error("The socket preference setting did not resolve a known socket: {0}")]
    InvalidSocket(ErrorCode),
}

impl<'dev> TxQueue<'dev> {
    /// Configure a transmit queue, tracked by its device.
    pub(crate) fn setup(dev: &dev::Dev, config: TxQueueConfig) -> Result<Self, ConfigFailure> {
        let socket_id: SocketId = config
            .socket_preference
            .try_into()
            .map_err(ConfigFailure::InvalidSocket)?;

        // Adjust descriptor counts to the driver limits; use the tx result.
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
            // Inherit port offloads without enabling additional queue offloads.
            offloads: 0,
            // The PMD's defaults: ethdev only substitutes them for a NULL `tx_conf`.
            ..dev.info.inner.default_txconf
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

    /// Transmit a batch, returning unsent packets for retry or disposal.
    ///
    /// The PMD owns accepted packets. Stop when the queue makes no progress. See
    /// [`TxQueue::transmit_from`], which keeps the batch in place.
    #[must_use = "retry or drop the unsent packets"]
    pub fn transmit(&mut self, mut packets: MbufArray<'dev>) -> MbufArray<'dev> {
        self.transmit_from(&mut packets);
        packets
    }

    /// Transmit the packets in `packets`, returning how many the queue accepted.
    ///
    /// The PMD owns accepted packets; they leave `packets` from the front. Refused packets stay
    /// in `packets`, in order, for retry or disposal. Stop when the queue makes no progress.
    ///
    /// The queue reads the batch's own storage, so a caller that keeps its batch (a worker's
    /// per-port transmit batch) moves no mbuf pointers unless the queue refuses some.
    #[tracing::instrument(level = "trace", skip(packets))]
    pub fn transmit_from<const N: usize>(&mut self, packets: &mut MbufArray<'dev, N>) -> usize {
        let dev = self.dev.as_u16();
        let queue = self.config.queue_index.as_u16();
        // SAFETY: `rte_eth_tx_burst` takes ownership of the first `nb_tx` mbufs it is offered and
        // does not write the array; each call is offered only mbufs no earlier call took, and
        // `sent` never exceeds `len`.
        unsafe {
            packets.send_from_front(|mbufs, len| {
                let mut sent = 0;
                while sent < len {
                    trace!("Transmitting packets to tx queue {queue} on dev {dev}");
                    let burst = u16::try_from(min(Self::PKT_BURST_SIZE, len - sent)).unwrap_or(0);
                    let nb_tx = usize::from(dpdk_sys::rte_eth_tx_burst(
                        dev,
                        queue,
                        mbufs.add(sent),
                        burst,
                    ));
                    trace!("Transmitted {nb_tx} packets from tx queue {queue} on dev {dev}");
                    if nb_tx == 0 {
                        break;
                    }
                    sent += nb_tx;
                }
                sent
            })
        }
    }
}

/// An exclusive transmit queue handle borrowed from a started device.
/// Transmission requires mutable access; the handle cannot be used after the device stops.
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
