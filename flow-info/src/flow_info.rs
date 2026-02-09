// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::Arc;
use concurrency::sync::RwLock;
use concurrency::sync::Weak;
use std::fmt::{Debug, Display};
use std::mem::MaybeUninit;
use std::time::{Duration, Instant};

use crate::{AtomicInstant, FlowInfoItem};

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum FlowInfoError {
    #[error("flow expired")]
    FlowExpired(Instant),
    #[error("no such status")]
    NoSuchStatus(u8),
    #[error("Timeout unchanged: would go backwards")]
    TimeoutUnchanged,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FlowStatus {
    Active = 0,
    Expired = 1,
    Removed = 2,
}

impl Display for FlowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Expired => write!(f, "expired"),
            Self::Removed => write!(f, "removed"),
        }
    }
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

#[derive(Debug, Default)]
pub struct FlowInfoLocked {
    // We need this to use downcast to avoid circular dependencies between crates.

    // VpcDiscriminant
    pub dst_vpcd: Option<Box<dyn FlowInfoItem>>,

    // State information for stateful NAT, (see NatFlowState)
    pub nat_state: Option<Box<dyn FlowInfoItem>>,

    // State information for port forwarding
    pub port_fw_state: Option<Box<dyn FlowInfoItem>>,
}

#[derive(Debug)]
pub struct FlowInfo {
    expires_at: AtomicInstant,
    status: AtomicFlowStatus,
    pub locked: RwLock<FlowInfoLocked>,
    pub related: Option<Weak<FlowInfo>>,
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
            locked: RwLock::new(FlowInfoLocked::default()),
            related: None,
        }
    }

    /// We want to create a pair of `FlowInfo`s that are mutually related via a `Weak` references so that no lookup
    /// is needed to find one from the other. This is tricky because the `FlowInfo`s are shared and we
    /// need concurrent access to them. One option to build such relationships is to let those `Weak`
    /// references live inside the `FlowInfoLocked`, which provides interior mutability. That approach is doable
    /// but requires locking the objects to access the data, which we'd like to avoid.
    ///
    /// If such `Weak` references are to live outside the `FlowInfoLocked`, without using any `Mutex` or `RwLock`,
    /// we need to relate the two objects when constructed, before they are inserted in the flow table. But, even
    /// in that case, creating both is tricky because, to get a `Weak` reference to any of them them, we need to
    /// `Arc` them and if we do that, we can't mutate them (unless we use a `Mutex` or the like).
    /// So, there is a chicken-and-egg problem which cannot be solved with safe code.
    ///
    /// This associated function creates a pair of related `FlowInfo`s by construction. The intended usage is
    /// to call this function when a couple of related flow entries are needed and later insert them in the
    /// flow-table.
    #[must_use]
    pub fn related_pair(expires_at: Instant) -> (Arc<FlowInfo>, Arc<FlowInfo>) {
        let mut one: Arc<MaybeUninit<Self>> = Arc::new_uninit();
        let mut two: Arc<MaybeUninit<Self>> = Arc::new_uninit();

        // get mut pointers. Arc::get_mut() will always return Some() since the
        // uninited Arcs have no strong or weak references here.
        let one_p = Arc::get_mut(&mut one).unwrap().as_mut_ptr();
        let two_p = Arc::get_mut(&mut two).unwrap().as_mut_ptr();

        // create the weak refs for the still uninited containers
        let one_weak = Arc::downgrade(&one);
        let two_weak = Arc::downgrade(&two);

        unsafe {
            let one_weak = Weak::from_raw(Weak::into_raw(one_weak) as *const Self);
            let two_weak = Weak::from_raw(Weak::into_raw(two_weak) as *const Self);
            // overwrite the memory locations with the FlowInfo's
            one_p.write(Self {
                expires_at: AtomicInstant::new(expires_at),
                status: AtomicFlowStatus::from(FlowStatus::Active),
                locked: RwLock::new(FlowInfoLocked::default()),
                related: Some(two_weak),
            });
            two_p.write(Self {
                expires_at: AtomicInstant::new(expires_at),
                status: AtomicFlowStatus::from(FlowStatus::Active),
                locked: RwLock::new(FlowInfoLocked::default()),
                related: Some(one_weak),
            });
            // turn back into Arc's
            (one.assume_init(), two.assume_init())
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

    /// Reset the expiry of the flow if it is not expired.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe.
    ///
    /// # Errors
    ///
    /// Returns `FlowInfoError::FlowExpired` if the flow is expired with the expiry `Instant`.
    /// Returns `FlowInfoError::TimeoutUnchanged` if the new timeout is smaller than the current.
    ///
    pub fn reset_expiry(&self, duration: Duration) -> Result<(), FlowInfoError> {
        if self.status.load(std::sync::atomic::Ordering::Relaxed) == FlowStatus::Expired {
            return Err(FlowInfoError::FlowExpired(self.expires_at()));
        }
        self.reset_expiry_unchecked(duration)
    }

    /// Reset the expiry of the flow without checking if it is already expired.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe.
    ///
    /// # Errors
    ///
    /// Returns `FlowInfoError::TimeoutUnchanged` if the new timeout is smaller than the current.
    ///
    pub fn reset_expiry_unchecked(&self, duration: Duration) -> Result<(), FlowInfoError> {
        let current = self.expires_at();
        let new = Instant::now() + duration;
        if new < current {
            return Err(FlowInfoError::TimeoutUnchanged);
        }
        self.expires_at
            .store(new, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub fn status(&self) -> FlowStatus {
        self.status.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Update the flow status.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe.
    pub fn update_status(&self, status: FlowStatus) {
        self.status
            .store(status, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Display for FlowInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let expires_at = self.expires_at.load(Ordering::Relaxed);
        let expires_in = expires_at.saturating_duration_since(Instant::now());
        write!(
            f,
            " status: {:?}, expires in {}s",
            self.status,
            expires_in.as_secs()
        )
        // we can't show the flowinfo yet.
    }
}
