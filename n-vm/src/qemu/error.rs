// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Error types specific to the QEMU backend.
//!
//! These errors cover failure modes unique to QEMU's architecture:
//!
//! - **QMP protocol** -- QEMU uses the QEMU Machine Protocol (QMP), a
//!   JSON-based protocol over a Unix socket, for lifecycle control and
//!   event monitoring.  Connecting to the socket, receiving the initial
//!   greeting, negotiating capabilities, and issuing commands are all
//!   QEMU-specific operations that can fail independently.
//! - **Process spawning** -- QEMU boots the VM immediately on process
//!   start (unlike cloud-hypervisor which separates VMM startup from VM
//!   boot), so there is no separate "create VM" or "boot VM" step.
//!   However, QEMU's command-line argument assembly can fail if the
//!   configuration is invalid.
//!
//! Generic errors that apply to any hypervisor backend (e.g. KVM
//! accessibility, socket polling, vsock listener binding) remain in
//! [`VmError`](crate::error::VmError).

/// Errors specific to the QEMU [`HypervisorBackend`](crate::backend::HypervisorBackend)
/// implementation.
///
/// These are wrapped into [`VmError::Backend`](crate::error::VmError::Backend)
/// by the [`Qemu`](super::Qemu) launch and shutdown sequences, preserving
/// the full error chain for diagnostics while keeping the generic
/// [`VmError`](crate::error::VmError) enum free of QEMU-specific variants.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum QemuError {
    /// Failed to connect to the QMP Unix socket.
    ///
    /// After QEMU starts, it creates a QMP control socket at the path
    /// specified by `-chardev socket,path=...`.  The container tier
    /// connects to this socket to issue lifecycle commands and receive
    /// async events.  This error means the connection attempt failed
    /// after the socket appeared on the filesystem.
    #[error("failed to connect to QMP socket")]
    #[diagnostic(
        code(n_vm::qemu::qmp_connect),
        help(
            "QEMU may have exited before creating the QMP socket -- \
              check the hypervisor stderr for early startup failures"
        )
    )]
    QmpConnect(#[source] std::io::Error),

    /// The QMP greeting was not received or could not be parsed.
    ///
    /// Upon connection, QEMU sends a JSON greeting message that is
    /// deserialized as [`qapi_qmp::QapiCapabilities`].  This error
    /// indicates the greeting was absent, malformed, or could not be
    /// deserialized into that type.
    #[error("QMP greeting not received or malformed: {reason}")]
    #[diagnostic(
        code(n_vm::qemu::qmp_greeting),
        help(
            "QEMU should send a QapiCapabilities JSON greeting immediately \
              on connection -- a malformed or missing greeting usually means \
              the QEMU version is incompatible or the socket is not a QMP socket"
        )
    )]
    QmpGreeting {
        /// Description of what went wrong with the greeting.
        reason: String,
    },

    /// QMP capabilities negotiation failed.
    ///
    /// After receiving the greeting, the client must send
    /// `{"execute": "qmp_capabilities"}` to enter command mode.  This
    /// error indicates QEMU rejected the negotiation request.
    #[error("QMP capabilities negotiation failed: {reason}")]
    #[diagnostic(
        code(n_vm::qemu::qmp_negotiate),
        help(
            "the qmp_capabilities handshake was rejected -- this can \
              indicate a QEMU version mismatch or a protocol error"
        )
    )]
    QmpNegotiate {
        /// The error message or description from the QMP response.
        reason: String,
    },

    /// A QMP command failed.
    ///
    /// This covers any command sent after successful negotiation (e.g.
    /// `query-status`, `system_powerdown`, `quit`) that QEMU rejected
    /// with an error response.
    #[error("QMP command `{command}` failed: {reason}")]
    #[diagnostic(
        code(n_vm::qemu::qmp_command),
        help(
            "a QMP command was rejected by QEMU -- check the `reason` \
              field for details; common causes include invalid arguments \
              or issuing commands in an unexpected VM state"
        )
    )]
    QmpCommand {
        /// The QMP command that was sent (e.g. `"system_powerdown"`).
        command: String,
        /// The error message from QEMU's response.
        reason: String,
    },

    /// An I/O error occurred while communicating over the QMP socket.
    ///
    /// This covers read/write failures on the QMP Unix stream after a
    /// successful connection, such as unexpected disconnection or pipe
    /// errors mid-conversation.
    #[error("QMP I/O error")]
    #[diagnostic(
        code(n_vm::qemu::qmp_io),
        help(
            "the QMP socket connection was lost mid-conversation -- \
              QEMU may have crashed or been killed externally"
        )
    )]
    QmpIo(#[source] std::io::Error),

    /// A QMP response could not be deserialized from JSON.
    ///
    /// QEMU sends responses and async events as newline-delimited JSON.
    /// This error indicates a response was received but could not be
    /// parsed into the expected structure.
    #[error("failed to deserialize QMP response")]
    #[diagnostic(
        code(n_vm::qemu::qmp_deserialize),
        help(
            "a QMP JSON response could not be parsed -- this may indicate \
              a QEMU version mismatch or an unexpected async event format"
        )
    )]
    QmpDeserialize(#[source] serde_json::Error),

    /// Host-side TAP configuration failed.
    ///
    /// After QEMU creates TAP devices via `-netdev tap`, the QEMU backend
    /// uses rtnetlink to bring them UP and assign IPv6 link-local
    /// addresses.  This error indicates one of those netlink operations
    /// failed.
    #[error("failed to configure host TAP `{tap}`: {reason}")]
    #[diagnostic(
        code(n_vm::qemu::tap_setup),
        help(
            "QEMU creates TAPs with `-netdev tap,script=no`, leaving them \
              DOWN and address-less.  The QEMU backend configures them via \
              rtnetlink after QEMU starts.  Check that the container has \
              NET_ADMIN capability and that the TAP devices exist."
        )
    )]
    TapSetup {
        /// The TAP device name that could not be configured.
        tap: String,
        /// Description of what went wrong.
        reason: String,
    },
}
