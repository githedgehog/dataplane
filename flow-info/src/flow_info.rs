// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fmt::Debug;
use std::time::{Duration, Instant};

use concurrency::sync::RwLock;

use crate::{AtomicInstant, FlowInfoItem};

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum FlowInfoError {
    #[error("flow expired")]
    FlowExpired(Instant),
    #[error("no such status")]
    NoSuchStatus(u8),
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FlowStatus {
    Active = 0,
    Expired = 1,
    Removed = 2,
}

impl TryFrom<u8> for FlowStatus {
    type Error = FlowInfoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FlowStatus::Active),
            1 => Ok(FlowStatus::Expired),
            2 => Ok(FlowStatus::Removed),
            v => Err(FlowInfoError::NoSuchStatus(v)),
        }
    }
}

impl From<FlowStatus> for u8 {
    fn from(status: FlowStatus) -> Self {
        status as u8
    }
}

pub struct AtomicFlowStatus(AtomicU8);

impl Debug for AtomicFlowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl AtomicFlowStatus {
    /// Load the flow status.
    ///
    /// # Panics
    ///
    /// Panics if the the stored flow status is invalid, which should never happen.
    ///
    #[must_use]
    pub fn load(&self, ordering: Ordering) -> FlowStatus {
        let value = self.0.load(ordering);
        FlowStatus::try_from(value).expect("Invalid enum state")
    }

    pub fn store(&self, state: FlowStatus, ordering: Ordering) {
        self.0.store(u8::from(state), ordering);
    }

    /// Atomic compare and exchange of the flow status.
    ///
    /// # Errors
    ///
    /// Returns previous `FlowStatus` if the compare and exchange fails.
    ///
    /// # Panics
    ///
    /// Panics if the the stored flow status is invalid, which should never happen.
    ///
    pub fn compare_exchange(
        &self,
        current: FlowStatus,
        new: FlowStatus,
        success: Ordering,
        failure: Ordering,
    ) -> Result<FlowStatus, FlowStatus> {
        match self
            .0
            .compare_exchange(current as u8, new as u8, success, failure)
        {
            Ok(prev) => Ok(FlowStatus::try_from(prev).expect("Invalid enum state")),
            Err(prev) => Err(FlowStatus::try_from(prev).expect("Invalid enum state")),
        }
    }
}

impl From<FlowStatus> for AtomicFlowStatus {
    fn from(status: FlowStatus) -> Self {
        Self(AtomicU8::new(status as u8))
    }
}

#[derive(Debug)]
pub struct FlowInfoLocked {
    // We need this to use downcast because VpcDiscriminant is in net.
    // We could avoid this indirection by moving Packet into its own crate.
    pub dst_vpc_info: Option<Box<dyn FlowInfoItem>>,
}

#[derive(Debug)]
pub struct FlowInfo {
    expires_at: AtomicInstant,
    status: AtomicFlowStatus,
    pub locked: RwLock<FlowInfoLocked>,
}

// TODO: We need a way to stuff an Arc<FlowInfo> into the packet
// meta data.  That means this has to move to net or we need a generic
// meta data extension method.
impl FlowInfo {
    #[must_use]
    pub fn new(expires_at: Instant) -> Self {
        Self {
            expires_at: AtomicInstant::new(expires_at),
            status: AtomicFlowStatus::from(FlowStatus::Active),
            locked: RwLock::new(FlowInfoLocked { dst_vpc_info: None }),
        }
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Extend the expiry of the flow if it is not expired.
    ///
    /// # Errors
    ///
    /// Returns `FlowInfoError::FlowExpired` if the flow is expired with the expiry `Instant`
    ///
    pub fn extend_expiry(&self, duration: Duration) -> Result<(), FlowInfoError> {
        if self.status.load(std::sync::atomic::Ordering::Relaxed) == FlowStatus::Expired {
            return Err(FlowInfoError::FlowExpired(self.expires_at()));
        }
        self.extend_expiry_unchecked(duration);
        Ok(())
    }

    /// Extend the expiry of the flow without checking if it is already expired.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe.
    ///
    pub fn extend_expiry_unchecked(&self, duration: Duration) {
        self.expires_at
            .fetch_add(duration, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn status(&self) -> FlowStatus {
        self.status.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Update the flow status.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe.
    ///
    /// # Errors
    ///
    /// Returns an error if the status transition is invalid.
    ///
    pub fn update_status(&self, status: FlowStatus) -> Result<(), FlowInfoError> {
        self.status
            .store(status, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}
