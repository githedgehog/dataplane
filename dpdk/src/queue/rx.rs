//! Receive queue configuration and management.

use crate::dev::DevIndex;
use crate::socket::SocketId;
use crate::{dev, mem, socket};
/// Imported for rustdoc
#[allow(unused_imports)]
use dpdk_sys::*;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A DPDK receive queue index.
///
/// This is a newtype around `u16` to provide type safety and prevent accidental misuse.
pub struct Index(pub u16);

impl Index {
    /// The index of the rx queue represented as a `u16`.
    ///
    /// This function is mostly useful for interfacing with [`dpdk_sys`].
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl From<Index> for u16 {
    fn from(value: Index) -> u16 {
        value.as_u16()
    }
}

impl From<u16> for Index {
    fn from(value: u16) -> Index {
        Index(value)
    }
}

#[derive(Debug)]
/// Configuration for a DPDK receive queue.
pub struct RxQueueConfig {
    /// The index of the device this rx queue is associated with
    pub dev: DevIndex,
    /// The index of the rx queue.
    pub queue_index: Index,
    /// The number of descriptors in the rx queue.
    pub num_descriptors: u16,
    /// The socket preference for the rx queue.
    pub socket_preference: socket::Preference,
    /// The low-level configuration of the rx queue.
    pub config: (), // TODO
    /// The memory pool to use for the rx queue.
    pub pool: mem::PoolHandle,
}

/// Error type for receive queue configuration failures.
#[derive(Debug)]
pub struct ConfigError {
    err: errno::Errno,
}

/// Error type for receive queue configuration failures.
#[derive(Debug)]
pub enum ConfigFailure {
    /// The device has been removed.
    DeviceRemoved(errno::Errno),
    /// Invalid arguments were passed to the receive queue configuration.
    InvalidArgument(errno::Errno),
    /// Memory allocation failed.
    NoMemory(errno::Errno),
    /// An unexpected (i.e. undocumented) error occurred.
    Unexpected(errno::Errno),
    /// The socket preference setting did not resolve a known socket.
    InvalidSocket(errno::Errno),
}

#[derive(Debug)]
pub struct RxQueue {
    pub(crate) config: RxQueueConfig,
    pub(crate) dev: DevIndex,
}

impl RxQueue {
    /// Create and configure a new hairpin queue.
    ///
    /// This method is crate internal.
    /// The library end user should call this by way of the
    /// [`dev::Dev::configure_rx_queue`] method.
    ///
    /// This design ensures that the hairpin queue is correctly tracked in the list of queues
    /// associated with the device.
    pub(crate) fn configure(dev: &dev::Dev, config: RxQueueConfig) -> Result<Self, ConfigFailure> {
        let socket_id = SocketId::try_from(config.socket_preference).map_err(|err| {
            ConfigFailure::InvalidSocket(errno::Errno(errno::NEG_EINVAL))
        })?;

        let rx_conf = rte_eth_rxconf {
            offloads: dev.info.inner.rx_queue_offload_capa,
            ..Default::default()
        };
        let ret = unsafe {
            rte_eth_rx_queue_setup(
                dev.info.index().as_u16(),
                config.queue_index.as_u16(),
                config.num_descriptors,
                socket_id.as_c_uint(),
                &rx_conf,
                config.pool.inner().as_ptr(),
            )
        };


        match ret {
            0 => {
                Ok(RxQueue {
                    dev: dev.info.index(),
                    config,
                })
            }
            errno::NEG_ENODEV => Err(ConfigFailure::DeviceRemoved(errno::Errno(ret))),
            errno::NEG_EINVAL => Err(ConfigFailure::InvalidArgument(errno::Errno(ret))),
            errno::NEG_ENOMEM => Err(ConfigFailure::NoMemory(errno::Errno(ret))),
            val => Err(ConfigFailure::Unexpected(errno::Errno(val))),
        }
    }

    /// Start the receive queue.
    pub(crate) fn start(self) -> Result<RxQueue, RxQueueStartError> {
        let ret = unsafe {
            rte_eth_dev_rx_queue_start(self.dev.as_u16(), self.config.queue_index.as_u16())
        };

        match ret {
            0 => Ok(self),
            errno::NEG_ENODEV => Err(RxQueueStartError::InvalidPortId),
            errno::NEG_EINVAL => Err(RxQueueStartError::QueueIdOutOfRange),
            errno::NEG_EIO => Err(RxQueueStartError::DeviceRemoved),
            errno::NEG_ENOTSUP => Err(RxQueueStartError::NotSupported),
            val => Err(RxQueueStartError::Unexpected(errno::Errno(val))),
        }
    }

    /// Start the receive queue.
    pub(crate) fn stop(self) -> Result<RxQueue, RxQueueStopError> {
        let ret = unsafe {
            rte_eth_dev_rx_queue_stop(self.dev.as_u16(), self.config.queue_index.as_u16())
        };

        match ret {
            0 => Ok(self),
            errno::NEG_ENODEV => Err(RxQueueStopError::InvalidPortId),
            errno::NEG_EINVAL => Err(RxQueueStopError::QueueIdOutOfRange),
            errno::NEG_EIO => Err(RxQueueStopError::DeviceRemoved),
            errno::NEG_ENOTSUP => Err(RxQueueStopError::NotSupported),
            val => Err(RxQueueStopError::Unexpected(errno::Errno(val))),
        }
    }
}

/// TODO
#[derive(thiserror::Error, Debug)]
pub enum RxQueueStartError {
    /// TODO
    #[error("Invalid port ID")]
    InvalidPortId,
    /// TODO
    #[error("Queue ID out of range")]
    QueueIdOutOfRange,
    /// TODO
    #[error("Device removed")]
    DeviceRemoved,
    /// TODO
    #[error("Invalid argument")]
    InvalidArgument,
    /// TODO
    #[error("Operation not supported")]
    NotSupported,
    /// TODO
    #[error("Unknown error")]
    Unexpected(errno::Errno),
}

/// TODO
#[derive(thiserror::Error, Debug)]
pub enum RxQueueStopError {
    /// TODO
    #[error("Invalid port ID")]
    InvalidPortId,
    /// TODO
    #[error("Queue ID out of range")]
    QueueIdOutOfRange,
    /// TODO
    #[error("Device removed")]
    DeviceRemoved,
    /// TODO
    #[error("Invalid argument")]
    InvalidArgument,
    /// TODO
    #[error("Operation not supported")]
    NotSupported,
    /// TODO
    #[error("Unexpected error")]
    Unexpected(errno::Errno),
}

/// TODO
#[derive(Debug)]
pub enum RxQueueState {
    /// TODO
    Stopped,
    /// TODO
    Started,
}
