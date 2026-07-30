// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Error types specific to the cloud-hypervisor backend.
//!
//! These errors cover failure modes unique to cloud-hypervisor's
//! architecture:
//!
//! - **Event-monitor pipe** -- cloud-hypervisor uses an `--event-monitor
//!   fd=N` argument with a Unix pipe for lifecycle events.  Creating the
//!   pipe, converting the sender to a blocking fd, and mapping it into the
//!   child process are all CH-specific operations.
//! - **REST API** -- cloud-hypervisor separates process startup from VM
//!   boot: the VMM process starts first, then the container tier issues
//!   `create_vm` and `boot_vm` REST calls.  QEMU boots the VM immediately
//!   on process start, so these steps do not apply.
//!
//! Generic errors that apply to any hypervisor backend (e.g. spawning a
//! child process, waiting for sockets, `/dev/kvm` accessibility) remain in
//! [`VmError`](crate::error::VmError).

/// Errors specific to the cloud-hypervisor [`HypervisorBackend`](crate::backend::HypervisorBackend)
/// implementation.
///
/// These are wrapped into [`VmError::Backend`](crate::error::VmError::Backend)
/// by the [`CloudHypervisor`](super::CloudHypervisor) launch sequence,
/// preserving the full error chain for diagnostics while keeping the
/// generic [`VmError`](crate::error::VmError) enum free of
/// cloud-hypervisor-specific variants.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum CloudHypervisorError {
    /// The event-monitor pipe between the container tier and
    /// cloud-hypervisor could not be created.
    ///
    /// Cloud-hypervisor uses `--event-monitor fd=N` to stream lifecycle
    /// events (boot, shutdown, panic, etc.) over a Unix pipe.  This
    /// error indicates the initial `pipe()` call failed.
    #[error("failed to create event monitor pipe")]
    #[diagnostic(
        code(n_vm::cloud_hypervisor::event_pipe),
        help(
            "the initial pipe() syscall for cloud-hypervisor's --event-monitor \
              fd=N failed -- check system resource limits (ulimit -n)"
        )
    )]
    EventPipe(#[source] std::io::Error),

    /// The event-monitor pipe sender could not be converted to a blocking
    /// file descriptor for fd-mapping into the hypervisor process.
    ///
    /// The pipe is created as a tokio async pipe, but the child-side fd
    /// must be a regular blocking fd so that cloud-hypervisor (which does
    /// its own I/O) can write to it directly.
    #[error("failed to convert event monitor sender to blocking fd")]
    #[diagnostic(code(n_vm::cloud_hypervisor::event_sender_fd))]
    EventSenderFd(#[source] std::io::Error),

    /// File-descriptor mapping for the cloud-hypervisor child process
    /// failed (e.g. the `command-fds` crate detected an fd collision).
    ///
    /// The inner value is a stringified `command_fds::FdMappingCollision`
    /// because that type does not implement [`std::error::Error`].
    #[error("failed to set up fd mappings for cloud-hypervisor: {0}")]
    #[diagnostic(
        code(n_vm::cloud_hypervisor::fd_mapping),
        help(
            "this usually means an fd collision in the command-fds mapping; \
              check that no other code has claimed the target fd"
        )
    )]
    FdMapping(String),

    /// The event-monitor pipe was not readable after the hypervisor
    /// process started, indicating the VMM did not emit its initial event.
    ///
    /// After spawning the cloud-hypervisor process, the container tier
    /// waits for the first event to become readable on the pipe as a
    /// signal that the VMM has initialised.  This error means the pipe
    /// never became readable.
    #[error("event monitor pipe not readable after hypervisor start")]
    #[diagnostic(
        code(n_vm::cloud_hypervisor::event_monitor_not_readable),
        help(
            "cloud-hypervisor may have crashed before emitting its first \
              lifecycle event -- check the hypervisor stderr for details"
        )
    )]
    EventMonitorNotReadable(#[source] std::io::Error),

    /// The cloud-hypervisor REST API rejected the `create_vm` request.
    ///
    /// Cloud-hypervisor separates VMM startup from VM creation: after the
    /// process starts and the API socket appears, the container tier sends
    /// a `create_vm` request with the full [`VmConfig`].  This error
    /// indicates that request was rejected.
    ///
    /// [`VmConfig`]: cloud_hypervisor_client::models::VmConfig
    #[error("cloud-hypervisor API rejected create_vm: {reason}")]
    #[diagnostic(
        code(n_vm::cloud_hypervisor::vm_create),
        help(
            "the cloud-hypervisor REST API refused the VM configuration -- \
              check the `reason` field and cloud-hypervisor logs for details"
        )
    )]
    VmCreate {
        /// Stringified error from the cloud-hypervisor API client.
        ///
        /// The generated client crate's error types do not implement
        /// [`std::error::Error`], so the error is captured as a
        /// debug-formatted string.
        reason: String,
    },

    /// The cloud-hypervisor REST API rejected the `boot_vm` request.
    ///
    /// After a successful `create_vm`, the container tier sends `boot_vm`
    /// to begin guest execution.  This error indicates that request was
    /// rejected.
    #[error("cloud-hypervisor API rejected boot_vm: {reason}")]
    #[diagnostic(
        code(n_vm::cloud_hypervisor::vm_boot),
        help(
            "create_vm succeeded but boot_vm was rejected -- this can happen \
              if the kernel image is missing, the virtio devices failed to \
              initialise, or the VM configuration is internally inconsistent"
        )
    )]
    VmBoot {
        /// Stringified error from the cloud-hypervisor API client.
        ///
        /// See [`VmCreate::reason`](Self::VmCreate) for why this is a
        /// `String` rather than a typed error.
        reason: String,
    },
}
