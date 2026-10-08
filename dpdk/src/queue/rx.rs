// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Receive queue configuration and management.

use crate::dev::{DevIndex, RxOffload};
use crate::mem::MbufArray;
use crate::socket::SocketId;
use crate::{dev, mem, socket};
use core::marker::PhantomData;
use errno::Errno;
use std::ffi::c_int;
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
pub struct RxQueueConfig<'eal> {
    /// The index of the rx queue.
    pub queue_index: RxQueueIndex,
    /// The number of descriptors in the rx queue.
    pub num_descriptors: u16,
    /// The socket preference for the rx queue.
    pub socket_preference: socket::Preference,
    /// Hardware offloads to use
    pub offloads: RxOffload,
    /// The memory pool to use for the rx queue.
    pub pool: mem::Pool<'eal>,
}

/// Error type for receive queue configuration failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigFailure {
    #[error("receive queue {} is already configured on this device", .0.as_u16())]
    AlreadyConfigured(RxQueueIndex),
    #[error(
        "receive queue {} is beyond the {configured} the device was configured with",
        .index.as_u16()
    )]
    OutOfRange {
        index: RxQueueIndex,
        configured: u16,
    },
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

/// An exclusive receive queue handle borrowed from a started device.
/// Polling requires mutable access; the handle cannot be used after the device stops.
#[derive(Debug)]
pub struct RxQueue<'dev> {
    pub(crate) config: RxQueueConfig<'dev>,
    pub(crate) dev: DevIndex,
    pub(crate) _dev: PhantomData<&'dev ()>,
}

impl<'dev> RxQueue<'dev> {
    /// Configure a receive queue, tracked by its device.
    #[cold]
    #[tracing::instrument(level = "info")]
    pub(crate) fn setup(
        dev: &dev::Dev,
        config: RxQueueConfig<'dev>,
    ) -> Result<Self, ConfigFailure> {
        let socket_id = SocketId::try_from(config.socket_preference)
            .map_err(|_| ConfigFailure::InvalidSocket(Errno(errno::NEG_EINVAL)))?;

        // Adjust descriptor counts to the driver limits; use the rx result.
        let mut nb_rx_desc = config.num_descriptors;
        let mut nb_tx_desc = config.num_descriptors;
        if let Some(err) = ConfigFailure::check(unsafe {
            dpdk_sys::rte_eth_dev_adjust_nb_rx_tx_desc(
                dev.info.index().as_u16(),
                &mut nb_rx_desc,
                &mut nb_tx_desc,
            )
        }) {
            return Err(err);
        }

        let rx_conf = dpdk_sys::rte_eth_rxconf {
            offloads: config.offloads.into(),
            // Zero thresholds select the PMD defaults.
            ..Default::default()
        };
        match ConfigFailure::check(unsafe {
            dpdk_sys::rte_eth_rx_queue_setup(
                dev.info.index().as_u16(),
                config.queue_index.as_u16(),
                nb_rx_desc,
                socket_id.as_c_uint(),
                &rx_conf,
                config.pool.as_mut_ptr(),
            )
        }) {
            None => Ok(RxQueue {
                dev: dev.info.index(),
                config,
                _dev: PhantomData,
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
    #[allow(unused)]
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

    /// Receive up to [`MBUF_BURST`](crate::mem::MBUF_BURST) packets. The returned batch owns them and frees
    /// any remaining packets on drop.
    ///
    /// The batch borrows the device and must be released or transmitted before it stops.
    #[tracing::instrument(level = "trace")]
    pub fn receive(&mut self) -> MbufArray<'dev> {
        let mut burst = MbufArray::new_empty();
        self.receive_into(&mut burst);
        burst
    }

    /// Receive into a reusable array, freeing any packets it still owns first.
    /// Avoids returning a full pointer array by value on every poll.
    pub fn receive_into(&mut self, burst: &mut MbufArray<'dev>) {
        trace!(
            "Polling for packets from rx queue {queue} on dev {dev}",
            queue = self.config.queue_index.as_u16(),
            dev = self.dev.as_u16()
        );
        // SAFETY: `rte_eth_rx_burst` writes exactly as many mbuf pointers as it returns, never
        // more than the capacity it is given, and every one is a live mbuf whose ownership passes
        // to us. That is precisely `refill_with`'s contract.
        unsafe {
            burst.refill_with(|slots, capacity| {
                dpdk_sys::rte_eth_rx_burst(
                    self.dev.as_u16(),
                    self.config.queue_index.as_u16(),
                    slots,
                    capacity,
                ) as usize
            });
        }
        trace!(
            "Received {nb_rx} packets from rx queue {queue} on dev {dev}",
            nb_rx = burst.len(),
            queue = self.config.queue_index.as_u16(),
            dev = self.dev.as_u16()
        );
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
