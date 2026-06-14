// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! An installed flow rule: an RAII handle for a live hardware offload.

use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use dpdk_sys::{rte_flow, rte_flow_destroy, rte_flow_error};
use tracing::warn;

use crate::dev::{Dev, DevIndex, Started};
use crate::flow::error::FlowError;

/// A flow rule installed on a device -- a live hardware offload.
///
/// The handle borrows the [`Dev<Started>`] it was created on, so it cannot outlive its device.
/// Dropping it destroys the rule (`rte_flow_destroy`). Because [`Dev::stop`](crate::dev::Dev::stop)
/// consumes the device by value, the borrow forces every rule to be torn down *before* the device
/// stops -- the wrong teardown order simply does not compile.
#[must_use = "dropping a FlowRule immediately destroys the hardware rule"]
pub struct FlowRule<'dev> {
    flow: NonNull<rte_flow>,
    port: DevIndex,
    dev: PhantomData<&'dev Dev<Started>>,
}

impl<'dev> FlowRule<'dev> {
    /// Wrap a freshly-created `rte_flow` handle. The handle must belong to `port` and be owned
    /// solely by the returned `FlowRule`.
    pub(crate) fn new(port: DevIndex, flow: NonNull<rte_flow>) -> FlowRule<'dev> {
        FlowRule {
            flow,
            port,
            dev: PhantomData,
        }
    }

    /// Destroy the rule explicitly, surfacing any PMD error.
    ///
    /// Prefer this over relying on [`Drop`] when you need to observe a destroy failure: `Drop` can
    /// only log it.
    pub fn destroy(self) -> Result<(), FlowError> {
        // Suppress the `Drop` below so the handle is freed exactly once.
        let this = ManuallyDrop::new(self);
        // SAFETY: `this.flow` is a live handle for `this.port`, owned solely by `self`, and the
        // `ManuallyDrop` guarantees `Drop` will not free it a second time.
        unsafe { destroy(this.port, this.flow) }
    }
}

impl Drop for FlowRule<'_> {
    fn drop(&mut self) {
        // SAFETY: `self.flow` is a live handle for `self.port`; this is the sole owner, and
        // `destroy()` forgets the value before calling here, so there is no double free.
        if let Err(e) = unsafe { destroy(self.port, self.flow) } {
            warn!("failed to destroy flow rule on port {}: {e}", self.port);
        }
    }
}

/// Call `rte_flow_destroy` for a handle.
///
/// # Safety
///
/// `flow` must be a live `rte_flow` handle belonging to `port`, not already destroyed.
unsafe fn destroy(port: DevIndex, flow: NonNull<rte_flow>) -> Result<(), FlowError> {
    let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
    let ret = unsafe { rte_flow_destroy(port.as_u16(), flow.as_ptr(), &mut error) };
    if ret == 0 {
        Ok(())
    } else {
        Err(FlowError::from_raw(&error))
    }
}
