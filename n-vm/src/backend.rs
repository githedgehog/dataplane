// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared interface for cloud-hypervisor, QEMU, and future VM backends.

use n_vm_protocol::VsockChannel;

use crate::abort_on_drop::AbortOnDrop;
use crate::error::VmError;
use crate::vm::TestVmParams;

/// Normalized result of a hypervisor event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorVerdict {
    /// The VM shut down cleanly.
    CleanShutdown,
    /// The event stream reported a panic, an error, or no clean shutdown.
    Failure,
}

impl HypervisorVerdict {
    /// Returns `true` if the VM shut down cleanly.
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::CleanShutdown)
    }
}

/// Resources produced by a successful hypervisor launch.
pub struct LaunchedHypervisor<B: HypervisorBackend> {
    /// The hypervisor child process handle.
    pub(crate) child: tokio::process::Child,

    /// Background task monitoring hypervisor lifecycle events.
    pub(crate) event_watcher: AbortOnDrop<(B::EventLog, HypervisorVerdict)>,

    /// Backend-specific handle for lifecycle control.
    pub(crate) controller: B::Controller,
}

/// Hypervisor-specific VM lifecycle operations.
///
/// Implementations translate [`TestVmParams`] into backend-native config,
/// spawn the VMM, watch lifecycle events, and provide best-effort shutdown.
#[expect(
    async_fn_in_trait,
    reason = "this trait is only used within the crate; auto-trait bounds on the \
              returned futures are not required"
)]
pub trait HypervisorBackend: Send + Sized + 'static {
    /// Human-readable backend name for logs and diagnostics.
    const NAME: &str;

    /// The collected event log produced by the backend's event monitor.
    type EventLog: std::fmt::Display + std::fmt::Debug + Default + Send + 'static;

    /// Backend-specific handle for VM lifecycle control.
    type Controller: Send + 'static;

    /// Spawns the hypervisor process, boots the VM, and starts event monitoring.
    ///
    /// # Errors
    ///
    /// Returns [`VmError`] if any step of the launch sequence fails.
    async fn launch(params: &TestVmParams<'_>) -> Result<LaunchedHypervisor<Self>, VmError>;

    /// Performs best-effort graceful shutdown of the VM and VMM.
    async fn shutdown(controller: &Self::Controller);

    /// Binds a listener for the given [`VsockChannel`] and spawns a
    /// background task that accepts a single connection and reads it to
    /// EOF, returning the contents as a `String`.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::VsockBind`] if the listener cannot be bound.
    fn spawn_vsock_reader(channel: &VsockChannel) -> Result<AbortOnDrop<String>, VmError>;
}
