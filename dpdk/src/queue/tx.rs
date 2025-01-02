// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Transmit queue configuration and management.

use crate::dev::DevIndex;
use crate::{dev, socket};
use dpdk_sys::*;
use errno::ErrorCode;

/// A DPDK transmit queue index.
///
/// This is a newtype around `u16` to provide type safety and prevent accidental misuse.
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
#[derive(Debug)]
pub struct ConfigError {
    /// The error code returned by the DPDK library.
    pub code: i32,
    /// The error returned by the OS
    pub err: ErrorCode,
}

/// Error type for transmit queue configuration failures.
#[derive(Debug)]
pub enum ConfigFailure {
    /// Memory allocation failed.
    NoMemory(ConfigError),
    /// An unexpected (i.e. undocumented) error occurred.
    Unexpected(ConfigError),
    /// The socket preference setting did not resolve a known socket.
    InvalidSocket(ConfigError),
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
    pub(crate) fn configure(dev: &dev::Dev, config: TxQueueConfig) -> Result<Self, ConfigFailure> {
        let socket_id = socket::SocketId::try_from(config.socket_preference)
            .map_err(|err| ConfigFailure::InvalidSocket(ConfigError { code: -1, err }))?;

        let tx_conf = rte_eth_txconf {
            offloads: dev.info.inner.tx_queue_offload_capa,
            ..Default::default()
        };
        let ret = unsafe {
            rte_eth_tx_queue_setup(
                dev.info.index().as_u16(),
                config.queue_index.as_u16(),
                config.num_descriptors,
                socket_id.as_c_uint(),
                &tx_conf,
            )
        };

        match ret {
            0 => Ok(TxQueue {
                dev: dev.info.index(),
                config,
            }),
            errno::ENOMEM => Err(ConfigFailure::NoMemory(ConfigError {
                code: ret,
                err: ErrorCode::parse(ret),
            })),
            _ => Err(ConfigFailure::Unexpected(ConfigError {
                code: ret,
                err: ErrorCode::parse(ret),
            })),
        }
    }

    /// Start the transmit queue.
    pub(crate) fn start(&mut self) -> Result<(), TxQueueStartError> {
        let ret = unsafe {
            rte_eth_dev_tx_queue_start(self.dev.as_u16(), self.config.queue_index.as_u16())
        };

        match ret {
            errno::SUCCESS => Ok(()),
            errno::NEG_ENODEV => Err(TxQueueStartError::DeviceRemoved),
            errno::NEG_EINVAL => Err(TxQueueStartError::InvalidArgument),
            errno::NEG_EIO => Err(TxQueueStartError::DeviceRemoved),
            errno::NEG_ENOTSUP => Err(TxQueueStartError::NotSupported),
            val => Err(TxQueueStartError::Unexpected(errno::Errno(val))),
        }
    }

    /// Stop the transmit queue.
    pub(crate) fn stop(&mut self) -> Result<(), TxQueueStopError> {
        let ret = unsafe {
            rte_eth_dev_tx_queue_stop(self.dev.as_u16(), self.config.queue_index.as_u16())
        };

        match ret {
            errno::SUCCESS => Ok(()),
            errno::NEG_ENODEV => Err(TxQueueStopError::DeviceRemoved),
            errno::NEG_EINVAL => Err(TxQueueStopError::InvalidArgument),
            errno::NEG_EIO => Err(TxQueueStopError::DeviceRemoved),
            errno::NEG_ENOTSUP => Err(TxQueueStopError::NotSupported),
            val => Err(TxQueueStopError::Unexpected(errno::Errno(val))),
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
    #[error("Unknown error")]
    Unexpected(errno::Errno),
}

/// TODO
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
    Unexpected(errno::Errno),
}
