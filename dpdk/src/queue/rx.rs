// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Receive queue configuration and management.

use crate::dev::DevIndex;
use crate::mem::Mbuf;
use crate::socket::SocketId;
use crate::{dev, mem, socket};
use dpdk_sys::*;
use errno::ErrorCode;
use tracing::{trace, warn};

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A DPDK receive queue index.
///
/// This is a newtype around `u16` to provide type safety and prevent accidental misuse.
pub struct RxQueueIndex(pub u16);

impl RxQueueIndex {
    /// The index of the rx queue represented as a `u16`.
    ///
    /// This function is mostly useful for interfacing with [`dpdk_sys`].
    #[must_use]
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl From<RxQueueIndex> for u16 {
    fn from(value: RxQueueIndex) -> u16 {
        value.as_u16()
    }
}

impl From<u16> for RxQueueIndex {
    fn from(value: u16) -> RxQueueIndex {
        RxQueueIndex(value)
    }
}

#[derive(Debug)]
/// Configuration for a DPDK receive queue.
pub struct RxQueueConfig {
    /// The index of the device this rx queue is associated with
    pub dev: DevIndex,
    /// The index of the rx queue.
    pub queue_index: RxQueueIndex,
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
pub enum ConfigFailure {
    /// The device has been removed.
    DeviceRemoved(ErrorCode),
    /// Invalid arguments were passed to the rx queue configuration.
    InvalidArgument(ErrorCode),
    /// Memory allocation failed.
    NoMemory(ErrorCode),
    /// An unexpected (i.e. undocumented) error occurred.
    Unexpected(ErrorCode),
    /// The socket preference setting did not resolve a known socket.
    InvalidSocket(ErrorCode),
}

/// DPDK rx queue
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
    #[tracing::instrument(level = "info")]
    pub(crate) fn configure(dev: &dev::Dev, config: RxQueueConfig) -> Result<Self, ConfigFailure> {
        use ConfigFailure::*;
        let socket_id = SocketId::try_from(config.socket_preference).map_err(InvalidSocket)?;
        // dev.info.index
        // info!("Configuring RX queue on socket {socket_id} for device {dev_info}", d);

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
            0 => Ok(RxQueue {
                dev: dev.info.index(),
                config,
            }),
            errno::NEG_ENODEV => Err(DeviceRemoved(ErrorCode::parse_i32(ret))),
            errno::NEG_EINVAL => Err(InvalidArgument(ErrorCode::parse_i32(ret))),
            errno::NEG_ENOMEM => Err(NoMemory(ErrorCode::parse_i32(ret))),
            _ => Err(Unexpected(ErrorCode::parse_i32(ret))),
        }
    }

    /// Start the rx queue.
    #[tracing::instrument(level = "info")]
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

    /// Start the rx queue.
    #[tracing::instrument(level = "info")]
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

    // TODO: make configurable
    const PKT_BURST_SIZE: usize = 64;

    /// Receive a burst of up to `PKT_BURST_SIZE` packets from the queue
    #[tracing::instrument(level = "trace")]
    pub fn receive(&mut self) -> impl Iterator<Item = Mbuf> {
        let mut pkts: [*mut rte_mbuf; Self::PKT_BURST_SIZE] = unsafe { core::mem::zeroed() };
        trace!(
            "Polling for packets from rx queue {queue} on dev {dev}",
            queue = self.config.queue_index.as_u16(),
            dev = self.dev.as_u16()
        );
        let nb_rx = unsafe {
            wrte_eth_rx_burst(
                self.dev.as_u16(),
                self.config.queue_index.as_u16(),
                pkts.as_mut_ptr(),
                Self::PKT_BURST_SIZE as u16,
            )
        };
        trace!("Received {} packets", nb_rx);
        (0..nb_rx).filter_map(move |i| Mbuf::new_from_raw(pkts[i as usize]))
    }
}

/// Types of errors associated with starting RX queues
#[derive(thiserror::Error, Debug)]
pub enum RxQueueStartError {
    #[error("The port ID associated with this RX queue is invalid")]
    InvalidPortId,
    #[error("The specified queue id is outside the range of known RX queues")]
    QueueIdOutOfRange,
    #[error("The network device associated with this RX queue has been removed")]
    DeviceRemoved,
    #[error("Invalid arguments supplied to RX queue configuration")]
    InvalidArgument,
    #[error("Operation is not supported (check device state and rx queue config)")]
    NotSupported,
    #[error("Unknown error encountered when starting RX queue")]
    Unexpected(errno::Errno),
}

/// Types of errors associated with stopping RX queues
#[derive(thiserror::Error, Debug)]
pub enum RxQueueStopError {
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
    #[error("Unexpected error")]
    Unexpected(errno::Errno),
}

/// States of RX queues
#[derive(Debug)]
pub enum RxQueueState {
    /// Stopped RX queue
    Stopped,
    /// Started RX queue
    Started,
}
