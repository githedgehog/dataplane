// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Transmit queue configuration and management.

use crate::dev::DevIndex;
use crate::mem::Mbuf;
use crate::socket::SocketId;
use crate::{dev, socket};
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

impl TxQueue {
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

        let tx_conf = dpdk_sys::rte_eth_txconf {
            offloads: dev.info.inner.tx_queue_offload_capa,
            ..Default::default()
        };
        let ret = unsafe {
            dpdk_sys::rte_eth_tx_queue_setup(
                dev.info.index().as_u16(),
                config.queue_index.as_u16(),
                config.num_descriptors,
                socket_id.as_c_uint(),
                &tx_conf,
            )
        };

        match ret {
            errno::SUCCESS => Ok(TxQueue {
                dev: dev.info.index(),
                config,
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

    #[tracing::instrument(level = "trace", skip(packets))]
    pub fn transmit(&self, packets: impl IntoIterator<Item = Mbuf>) {
        let mut packets: Vec<_> = packets.into_iter().collect();
        let mut offset = 0;
        if packets.is_empty() {
            return;
        }
        while offset < packets.len() {
            trace!(
                "Transmitting packets to tx queue {queue} on dev {dev}",
                queue = self.config.queue_index.as_u16(),
                dev = self.dev.as_u16()
            );
            let nb_tx = unsafe {
                dpdk_sys::rte_eth_tx_burst(
                    self.dev.as_u16(),
                    self.config.queue_index.as_u16(),
                    packets.as_mut_ptr().add(offset) as *mut _,
                    min(Self::PKT_BURST_SIZE, packets.len() - offset) as u16,
                )
            };
            offset += nb_tx as usize;
            trace!(
                "Transmitted {nb_tx} packets from tx queue {queue} on dev {dev}",
                queue = self.config.queue_index.as_u16(),
                dev = self.dev.as_u16()
            );
        }
    }
}

/// TODO
#[derive(Debug)]
pub struct TxQueue {
    pub(crate) config: TxQueueConfig,
    pub(crate) dev: DevIndex,
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
