// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Receive queue configuration and management.

use crate::dev::{DevIndex, RxOffload};
use crate::mem::Mbuf;
use crate::socket::SocketId;
use crate::{dev, mem, socket};
use errno::Errno;
use std::ffi::c_int;
use std::ptr::null_mut;
use tracing::{trace, warn};

/// A DPDK receive queue index.
///
/// This is a newtype around `u16` to provide type safety and prevent accidental misuse.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    #[must_use]
    fn from(value: RxQueueIndex) -> u16 {
        value.as_u16()
    }
}

impl From<u16> for RxQueueIndex {
    fn from(value: u16) -> RxQueueIndex {
        RxQueueIndex(value)
    }
}

/// Configuration for a DPDK receive queue.
#[derive(Debug)]
pub struct RxQueueConfig {
    /// The index of the device this rx queue is associated with
    pub dev: DevIndex,
    /// The index of the rx queue.
    pub queue_index: RxQueueIndex,
    /// The number of descriptors in the rx queue.
    pub num_descriptors: u16,
    /// The socket preference for the rx queue.
    pub socket_preference: socket::Preference,
    /// Hardware offloads to use
    pub offloads: RxOffload,
    /// The memory pool to use for the rx queue.
    pub pool: mem::Pool,
}

/// Error type for receive queue configuration failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigFailure {
    #[error("The device has been removed")]
    DeviceRemoved(Errno),
    #[error("Invalid arguments were passed to the receive queue configuration")]
    InvalidArgument(Errno),
    #[error("Memory allocation failed")]
    NoMemory(Errno),
    #[error("The socket preference setting did not resolve a known socket")]
    InvalidSocket(Errno),
    #[error("An unknown error occurred")]
    Unknown(Errno),
}

impl ConfigFailure {
    #[cold]
    fn check(err: c_int) -> Option<ConfigFailure> {
        match err {
            0 => None,
            errno::NEG_ENODEV => Some(ConfigFailure::DeviceRemoved(Errno(err))),
            errno::NEG_EINVAL => Some(ConfigFailure::InvalidArgument(Errno(err))),
            errno::NEG_ENOMEM => Some(ConfigFailure::NoMemory(Errno(err))),
            _ => Some(ConfigFailure::Unknown(Errno(err))),
        }
    }
}

/// DPDK rx queue
#[derive(Debug)]
pub struct RxQueue {
    pub(crate) config: RxQueueConfig,
    pub(crate) dev: DevIndex,
}

impl RxQueue {
    /// Create and configure a new receive queue.
    ///
    /// This method is crate internal.
    /// The library end user should call this by way of the
    /// [`dev::Dev::new_rx_queue`] method.
    ///
    /// This design ensures that the hairpin queue is correctly tracked in the list of queues
    /// associated with the device.
    #[cold]
    #[tracing::instrument(level = "info")]
    pub(crate) fn setup(dev: &dev::Dev, config: RxQueueConfig) -> Result<Self, ConfigFailure> {
        let socket_id = SocketId::try_from(config.socket_preference)
            .map_err(|_| ConfigFailure::InvalidSocket(Errno(errno::NEG_EINVAL)))?;
        let rx_conf = dpdk_sys::rte_eth_rxconf {
            offloads: config.offloads.into(),
            ..Default::default()
        };
        match ConfigFailure::check(unsafe {
            dpdk_sys::rte_eth_rx_queue_setup(
                dev.info.index().as_u16(),
                config.queue_index.as_u16(),
                config.num_descriptors,
                socket_id.as_c_uint(),
                &rx_conf,
                config.pool.inner().as_mut_ptr(),
            )
        }) {
            None => Ok(RxQueue {
                dev: dev.info.index(),
                config,
            }),
            Some(err) => Err(err),
        }
    }

    /// Start the receive queue.
    #[cold]
    #[tracing::instrument(level = "info")]
    pub(crate) fn start(&mut self) -> Result<(), RxQueueStartError> {
        let ret = unsafe {
            dpdk_sys::rte_eth_dev_rx_queue_start(
                self.dev.as_u16(),
                self.config.queue_index.as_u16(),
            )
        };

        match ret {
            0 => Ok(()),
            errno::NEG_ENODEV => Err(RxQueueStartError::InvalidPortId),
            errno::NEG_EINVAL => Err(RxQueueStartError::QueueIdOutOfRange),
            errno::NEG_EIO => Err(RxQueueStartError::DeviceRemoved),
            errno::NEG_ENOTSUP => Err(RxQueueStartError::NotSupported),
            val => Err(RxQueueStartError::Unknown(Errno(val))),
        }
    }

    /// Stop the receive queue.
    #[cold]
    #[tracing::instrument(level = "info")]
    pub(crate) fn stop(&mut self) -> Result<(), RxQueueStopError> {
        let ret = unsafe {
            dpdk_sys::rte_eth_dev_rx_queue_stop(self.dev.as_u16(), self.config.queue_index.as_u16())
        };

        use errno::*;
        match ret {
            0 => Ok(()),
            NEG_ENODEV => Err(RxQueueStopError::InvalidPortId),
            NEG_EINVAL => Err(RxQueueStopError::QueueIdOutOfRange),
            NEG_EIO => Err(RxQueueStopError::DeviceRemoved),
            NEG_ENOTSUP => Err(RxQueueStopError::NotSupported),
            val => Err(RxQueueStopError::Unknown(Errno(val))),
        }
    }

    // TODO: make configurable
    pub(crate) const PKT_BURST_SIZE: usize = 64;

    /// Receive a burst of packets from the queue
    #[tracing::instrument(level = "trace")]
    pub fn receive(&self) -> impl Iterator<Item = Mbuf> {
        let mut pkts: [*mut dpdk_sys::rte_mbuf; RxQueue::PKT_BURST_SIZE] =
            [null_mut(); RxQueue::PKT_BURST_SIZE];
        trace!(
            "Polling for packets from rx queue {queue} on dev {dev}",
            queue = self.config.queue_index.as_u16(),
            dev = self.dev.as_u16()
        );
        let nb_rx = unsafe {
            dpdk_sys::rte_eth_rx_burst(
                self.dev.as_u16(),
                self.config.queue_index.as_u16(),
                pkts.as_mut_ptr(),
                RxQueue::PKT_BURST_SIZE as u16,
            )
        };
        trace!(
            "Received {nb_rx} packets from rx queue {queue} on dev {dev}",
            queue = self.config.queue_index.as_u16(),
            dev = self.dev.as_u16()
        );
        // SAFETY: we should never get a null pointer for anything inside the advertised bounds
        // of the receive buffer
        (0..nb_rx).map(move |i| unsafe { Mbuf::new_from_raw_unchecked(pkts[i as usize]) })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RxQueueStartError {
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
    Unknown(Errno),
}

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
    Unknown(Errno),
}
