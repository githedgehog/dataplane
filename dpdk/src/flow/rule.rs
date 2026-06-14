// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! An installed flow rule: an RAII handle for a live hardware offload.

use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use dpdk_sys::{rte_flow, rte_flow_destroy, rte_flow_error};
use tracing::warn;

use crate::dev::DevIndex;
use crate::flow::error::FlowError;
use concurrency::sync::atomic::{AtomicUsize, Ordering};

/// An installed rule that borrows its [`Dev<Started>`](crate::dev::Dev) and destroys itself on drop.
/// The borrow prevents stopping the device while the rule exists; see [`Flow`](crate::flow::Flow).
#[must_use = "dropping a FlowRule immediately destroys the hardware rule"]
pub struct FlowRule<'dev> {
    flow: NonNull<rte_flow>,
    port: DevIndex,
    /// Borrows the device and counts failed destroys until the port is flushed.
    live_rules: &'dev AtomicUsize,
}

impl<'dev> FlowRule<'dev> {
    /// Wrap a freshly-created `rte_flow` handle. The handle must belong to `port` and be owned
    /// solely by the returned `FlowRule`.
    pub(crate) fn new(
        port: DevIndex,
        flow: NonNull<rte_flow>,
        live_rules: &'dev AtomicUsize,
    ) -> FlowRule<'dev> {
        live_rules.fetch_add(1, Ordering::AcqRel);
        FlowRule {
            flow,
            port,
            live_rules,
        }
    }

    /// Destroy the rule and return any PMD error. Drop can only log errors.
    pub fn destroy(self) -> Result<(), FlowError> {
        let this = ManuallyDrop::new(self);
        // SAFETY: the handle is live and owned; ManuallyDrop prevents a second destroy.
        let result = unsafe { destroy(this.port, this.flow) };
        if result.is_ok() {
            this.live_rules.fetch_sub(1, Ordering::AcqRel);
        }
        result
    }
}

impl Drop for FlowRule<'_> {
    fn drop(&mut self) {
        // SAFETY: this is the sole owner of a live handle; explicit destroy suppresses Drop.
        match unsafe { destroy(self.port, self.flow) } {
            Ok(()) => {
                self.live_rules.fetch_sub(1, Ordering::AcqRel);
            }
            Err(e) => warn!("failed to destroy flow rule on port {}: {e}", self.port),
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
