// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! QEMU Machine Protocol (QMP) client backed by [`qapi-rs`] type
//! definitions.
//!
//! QMP is a JSON-based protocol that QEMU exposes over a Unix socket for
//! machine lifecycle control and event monitoring.  This module provides
//! a purpose-built client covering only the operations needed by the
//! [`Qemu`](super::Qemu) hypervisor backend:
//!
//! 1. **Connection and negotiation** -- connect to the QMP socket, receive
//!    the greeting, and enter command mode via `qmp_capabilities`.
//! 2. **Command execution** -- send commands (fire-and-forget) for
//!    best-effort shutdown (`system_powerdown`, `quit`).
//! 3. **Event monitoring** -- read and deserialize async QMP events for
//!    the event watcher task.
//!
//! Wire types (events, error classes, version info, greeting structure)
//! are provided by the [`qapi_qmp`] crate, which is code-generated from
//! the upstream QEMU QAPI schema.  This gives us:
//!
//! - **Typed events** -- [`qapi_qmp::Event`] is an enum with variants
//!   like `SHUTDOWN`, `GUEST_PANICKED`, `RESUME`, etc., each carrying
//!   its schema-defined data payload.  Verdict computation can use
//!   pattern matching instead of string comparison.
//! - **Typed error classes** -- [`qapi_spec::ErrorClass`] enumerates the
//!   QMP error categories (`GenericError`, `CommandNotFound`, etc.).
//! - **Version information** -- [`qapi_qmp::VersionInfo`] and
//!   [`qapi_qmp::VersionTriple`] provide structured QEMU version data
//!   from the greeting.
//!
//! # Protocol overview
//!
//! ```mermaid
//! sequenceDiagram
//!     participant Client
//!     participant QEMU
//!
//!     QEMU->>Client: {"QMP": {"version": ...}} (greeting)
//!     Client->>QEMU: {"execute": "qmp_capabilities"} (negotiate)
//!     QEMU->>Client: {"return": {}} (success)
//!
//!     note over Client,QEMU: command mode active
//!
//!     QEMU->>Client: {"event": "SHUTDOWN", ...} (async event)
//!     Client->>QEMU: {"execute": "quit"} (command)
//!     QEMU->>Client: {"return": {}} (response)
//! ```
//!
//! After negotiation, the socket carries a mix of **responses** (to
//! commands) and **async events** (lifecycle transitions).  Since the
//! test infrastructure's shutdown path is best-effort and runs after the
//! event watcher has finished, the [`QmpWriter`] sends commands without
//! waiting for responses.
//!
//! # Socket split
//!
//! After negotiation, [`QmpConnection::into_split`] produces:
//!
//! - A [`QmpWriter`] that goes into the
//!   [`QemuController`](super::QemuController) for lifecycle commands.
//! - A [`QmpEventStream`] that goes into the background event-watcher
//!   task.
//!
//! The writer sends commands fire-and-forget (no response reading).  The
//! event stream consumes everything from the read half, discarding
//! command responses and yielding only [`qapi_qmp::Event`]s.  This
//! avoids the need for a multiplexer while keeping the API simple.
//!
//! [`qapi-rs`]: https://github.com/arcnmx/qapi-rs

use std::path::Path;

use qapi_qmp::QmpMessage;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, trace, warn};

use super::error::QemuError;

// ── Event display ────────────────────────────────────────────────────

/// Wrapper for human-readable [`Display`](std::fmt::Display) of a
/// [`qapi_qmp::Event`].
///
/// Produces a concise one-line representation showing the event name
/// followed by its data payload (if non-empty), suitable for diagnostic
/// output in test failure reports.
///
/// # Examples
///
/// An event with payload displays as `SHUTDOWN {"guest":true,"reason":"guest-shutdown"}`.
/// An event with an empty data struct displays as just `STOP`.
pub struct EventDisplay<'a>(pub &'a qapi_qmp::Event);

impl std::fmt::Display for EventDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Serialize to JSON to extract the event name and data fields.
        // `qapi_qmp::Event` is `#[serde(tag = "event")]`, so the JSON
        // object always contains an `"event"` key with the variant name.
        let Ok(json) = serde_json::to_value(self.0) else {
            // Fallback to Debug if serialization somehow fails.
            return write!(f, "{:?}", self.0);
        };

        let name = json
            .get("event")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        write!(f, "{name}")?;

        // Append the data payload unless it is an empty object (which
        // is the serialized form of events that carry no payload, e.g.
        // `STOP`, `RESUME`).
        if let Some(data) = json.get("data")
            && !data.as_object().is_some_and(serde_json::Map::is_empty)
        {
            write!(f, " {data}")?;
        }

        Ok(())
    }
}

// ── QMP command (outbound) ───────────────────────────────────────────

/// Enumerates the QMP commands used by this backend.
///
/// Each variant serializes to the wire-format command name that QEMU
/// expects in the `"execute"` field of a QMP command message.
/// Only argument-free commands are needed; the shutdown path uses
/// [`SystemPowerdown`](Self::SystemPowerdown) and [`Quit`](Self::Quit),
/// while connection setup uses
/// [`QmpCapabilities`](Self::QmpCapabilities).
#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) enum QmpCommandName {
    /// Enter command mode after the initial greeting.
    #[serde(rename = "qmp_capabilities")]
    QmpCapabilities,
    /// Send an ACPI power-button event to the guest.
    #[serde(rename = "system_powerdown")]
    SystemPowerdown,
    /// Immediately terminate the QEMU process.
    #[serde(rename = "quit")]
    Quit,
}

impl std::fmt::Display for QmpCommandName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QmpCapabilities => f.write_str("qmp_capabilities"),
            Self::SystemPowerdown => f.write_str("system_powerdown"),
            Self::Quit => f.write_str("quit"),
        }
    }
}

/// A QMP command message to send to QEMU.
///
/// Serializes to `{"execute": "<command_name>"}`, which is the format
/// QEMU expects for commands without arguments.
#[derive(Debug, Serialize)]
struct QmpCommand {
    execute: QmpCommandName,
}

// ── QMP connection ───────────────────────────────────────────────────

/// An established QMP connection that has completed capability
/// negotiation and is ready for command mode.
///
/// Created by [`QmpConnection::connect`], this type is consumed by
/// [`into_split`](Self::into_split) to produce a [`QmpWriter`] (for
/// sending commands) and a [`QmpEventStream`] (for reading events).
pub(crate) struct QmpConnection {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl QmpConnection {
    /// Connects to the QMP socket at `path`, reads the greeting, and
    /// negotiates capabilities.
    ///
    /// The greeting is deserialized as [`qapi_qmp::QapiCapabilities`],
    /// which provides typed access to the QEMU version and advertised
    /// capabilities.
    ///
    /// After this returns successfully, the connection is in command mode
    /// and ready to send commands or read events.
    ///
    /// # Errors
    ///
    /// Returns [`QemuError`] if the connection, greeting, or negotiation
    /// fails.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, QemuError> {
        let stream = UnixStream::connect(path.as_ref())
            .await
            .map_err(QemuError::QmpConnect)?;

        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut writer = write_half;

        // ── Phase 1: read the QMP greeting ───────────────────────────
        let greeting = read_line_json::<qapi_qmp::QapiCapabilities>(&mut reader).await?;

        let v = &greeting.QMP.version;
        debug!(
            "QMP greeting: QEMU {}.{}.{} (package: {:?})",
            v.qemu.major, v.qemu.minor, v.qemu.micro, v.package,
        );

        // ── Phase 2: negotiate capabilities ──────────────────────────
        send_command(&mut writer, QmpCommandName::QmpCapabilities).await?;

        let msg = read_line_json::<qapi_qmp::QmpMessageAny>(&mut reader).await?;
        match msg {
            QmpMessage::Response(resp) => match resp.result() {
                Ok(_) => {
                    debug!("QMP capabilities negotiated successfully");
                }
                Err(error) => {
                    return Err(QemuError::QmpNegotiate {
                        reason: format!("{:?}: {}", error.class, error.desc),
                    });
                }
            },
            QmpMessage::Event(event) => {
                // Events during negotiation are unexpected but not
                // impossible (e.g. a race with early device init).
                warn!(
                    "unexpected QMP event during negotiation: {}",
                    EventDisplay(&event),
                );
                return Err(QemuError::QmpNegotiate {
                    reason: format!(
                        "unexpected event during negotiation: {}",
                        EventDisplay(&event),
                    ),
                });
            }
        }

        Ok(Self { reader, writer })
    }

    /// Splits the connection into a writer (for sending commands) and an
    /// event stream (for reading events in a background task).
    ///
    /// The writer goes into the [`QemuController`](super::QemuController)
    /// and the event stream goes into the background event-watcher task
    /// spawned during [`launch`](super::Qemu::launch).
    pub fn into_split(self) -> (QmpWriter, QmpEventStream) {
        (
            QmpWriter {
                writer: self.writer,
            },
            QmpEventStream {
                reader: self.reader,
            },
        )
    }
}

// ── QmpWriter ────────────────────────────────────────────────────────

/// Write half of a QMP connection, used for sending lifecycle commands.
///
/// Commands are sent fire-and-forget: the response (if any) will be
/// consumed and discarded by the [`QmpEventStream`] on the read half,
/// or simply lost if QEMU has already exited.
///
/// This design is appropriate because:
///
/// - **During normal operation**, the event stream task owns the read
///   half and will discard any command responses it encounters.
/// - **During shutdown** (which runs after the event stream task
///   completes), the VM has usually already exited, so writes may fail
///   with a broken pipe.  The best-effort semantics mean these failures
///   are harmless.
pub struct QmpWriter {
    writer: OwnedWriteHalf,
}

impl QmpWriter {
    /// Sends a QMP command without waiting for a response.
    ///
    /// This is suitable for best-effort operations like shutdown where
    /// the caller does not need to know whether the command succeeded.
    /// Errors are logged at debug level but not propagated.
    pub async fn send_command_fire_and_forget(&mut self, command: QmpCommandName) {
        if let Err(err) = send_command(&mut self.writer, command).await {
            debug!("QMP command `{command}` send failed (best-effort): {err}");
        }
    }
}

// ── QmpEventStream ───────────────────────────────────────────────────

/// Read half of a QMP connection, used for consuming events in a
/// background task.
///
/// Reads newline-delimited JSON messages from the QMP socket and yields
/// [`qapi_qmp::Event`]s.  Command responses that arrive on the stream
/// are logged and discarded, since the writer sends commands
/// fire-and-forget.
pub(crate) struct QmpEventStream {
    reader: BufReader<OwnedReadHalf>,
}

impl QmpEventStream {
    /// Reads the next QMP event from the stream.
    ///
    /// Skips over command responses (which may arrive if the writer sent
    /// a fire-and-forget command while the event stream was active).
    ///
    /// Returns `Ok(None)` when the stream is closed (QEMU exited and
    /// the socket was shut down).
    ///
    /// # Errors
    ///
    /// Returns [`QemuError`] on I/O or deserialization errors.
    pub async fn next_event(&mut self) -> Result<Option<qapi_qmp::Event>, QemuError> {
        loop {
            let mut line = String::new();
            let bytes_read = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(QemuError::QmpIo)?;

            if bytes_read == 0 {
                // EOF -- QEMU exited and the socket was closed.
                return Ok(None);
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            trace!("QMP recv: {trimmed}");

            let msg: qapi_qmp::QmpMessageAny =
                serde_json::from_str(trimmed).map_err(QemuError::QmpDeserialize)?;

            match msg {
                QmpMessage::Event(event) => return Ok(Some(event)),
                QmpMessage::Response(resp) => match resp.result() {
                    Ok(_) => {
                        // Discard command responses -- the writer
                        // doesn't wait for them.
                        trace!("QMP: discarding command success response");
                    }
                    Err(error) => {
                        // Log command errors but don't propagate -- the
                        // writer sent fire-and-forget.
                        debug!(
                            "QMP: discarding command error response: {:?}: {}",
                            error.class, error.desc,
                        );
                    }
                },
            }
        }
    }
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Reads a single newline-delimited JSON message from the buffered
/// reader and deserializes it into `T`.
async fn read_line_json<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<OwnedReadHalf>,
) -> Result<T, QemuError> {
    let mut line = String::new();
    let bytes_read = reader
        .read_line(&mut line)
        .await
        .map_err(QemuError::QmpIo)?;
    if bytes_read == 0 {
        return Err(QemuError::QmpGreeting {
            reason: "connection closed before message received".into(),
        });
    }
    let trimmed = line.trim();
    trace!("QMP recv: {trimmed}");
    serde_json::from_str(trimmed).map_err(QemuError::QmpDeserialize)
}

/// Serializes and sends a QMP command as a newline-terminated JSON
/// message.
async fn send_command(
    writer: &mut OwnedWriteHalf,
    command: QmpCommandName,
) -> Result<(), QemuError> {
    let cmd = QmpCommand { execute: command };
    let mut payload = serde_json::to_string(&cmd).map_err(|e| QemuError::QmpCommand {
        command: command.to_string(),
        reason: format!("serialization failed: {e}"),
    })?;
    payload.push('\n');
    trace!("QMP send: {}", payload.trim());
    writer
        .write_all(payload.as_bytes())
        .await
        .map_err(QemuError::QmpIo)?;
    writer.flush().await.map_err(QemuError::QmpIo)?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Greeting deserialization ─────────────────────────────────────

    #[test]
    fn deserialize_greeting() {
        let json = r#"{"QMP": {"version": {"qemu": {"micro": 0, "minor": 2, "major": 9}, "package": "v9.2.0"}, "capabilities": ["oob"]}}"#;
        let greeting: qapi_qmp::QapiCapabilities = serde_json::from_str(json).unwrap();
        assert_eq!(greeting.QMP.version.qemu.major, 9);
        assert_eq!(greeting.QMP.version.qemu.minor, 2);
        assert_eq!(greeting.QMP.version.qemu.micro, 0);
    }

    #[test]
    fn deserialize_greeting_without_capabilities() {
        let json = r#"{"QMP": {"version": {"qemu": {"micro": 1, "minor": 0, "major": 8}, "package": ""}, "capabilities": []}}"#;
        let greeting: qapi_qmp::QapiCapabilities = serde_json::from_str(json).unwrap();
        assert_eq!(greeting.QMP.version.qemu.major, 8);
        assert!(greeting.QMP.capabilities.is_empty());
    }

    // ── Response deserialization ─────────────────────────────────────

    #[test]
    fn deserialize_return_response() {
        let json = r#"{"return": {}}"#;
        let msg: qapi_qmp::QmpMessageAny = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Response(resp) => {
                resp.result().expect("expected successful response");
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_return_with_data() {
        let json = r#"{"return": {"status": "running", "singlestep": false}}"#;
        let msg: qapi_qmp::QmpMessageAny = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Response(resp) => {
                resp.result().expect("expected successful response");
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_error_response() {
        let json = r#"{"error": {"class": "GenericError", "desc": "something went wrong"}}"#;
        let msg: qapi_qmp::QmpMessageAny = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Response(resp) => match resp.result() {
                Err(error) => {
                    assert_eq!(error.class, qapi_spec::ErrorClass::GenericError,);
                    assert_eq!(error.desc, "something went wrong");
                }
                Ok(_) => panic!("expected error response, got success"),
            },
            QmpMessage::Event(e) => panic!("expected response, got event: {e:?}"),
        }
    }

    // ── Event deserialization ────────────────────────────────────────

    #[test]
    fn deserialize_shutdown_event() {
        let json = r#"{"event": "SHUTDOWN", "data": {"guest": true, "reason": "guest-shutdown"}, "timestamp": {"seconds": 1234, "microseconds": 5678}}"#;
        let msg: qapi_qmp::QmpMessageAny = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Event(qapi_qmp::Event::SHUTDOWN { data, .. }) => {
                assert!(data.guest);
                assert_eq!(data.reason, qapi_qmp::ShutdownCause::guest_shutdown,);
            }
            other => panic!("expected SHUTDOWN event, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_guest_panicked_event() {
        let json = r#"{"event": "GUEST_PANICKED", "data": {"action": "pause"}, "timestamp": {"seconds": 42, "microseconds": 0}}"#;
        let msg: qapi_qmp::QmpMessageAny = serde_json::from_str(json).unwrap();
        match msg {
            QmpMessage::Event(qapi_qmp::Event::GUEST_PANICKED { data, .. }) => {
                assert_eq!(data.action, qapi_qmp::GuestPanicAction::pause);
            }
            other => panic!("expected GUEST_PANICKED event, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_event_without_data() {
        let json = r#"{"event": "STOP", "timestamp": {"seconds": 10, "microseconds": 0}}"#;
        let msg: qapi_qmp::QmpMessageAny = serde_json::from_str(json).unwrap();
        assert!(
            matches!(msg, QmpMessage::Event(qapi_qmp::Event::STOP { .. })),
            "expected STOP event, got {msg:?}",
        );
    }

    // ── Event display ────────────────────────────────────────────────

    #[test]
    fn event_display_with_data() {
        let event: qapi_qmp::Event = serde_json::from_str(
            r#"{"event": "SHUTDOWN", "data": {"guest": true, "reason": "guest-shutdown"}, "timestamp": {"seconds": 0, "microseconds": 0}}"#,
        )
        .unwrap();
        let display = format!("{}", EventDisplay(&event));
        assert!(
            display.starts_with("SHUTDOWN"),
            "expected display to start with SHUTDOWN, got: {display}",
        );
        // The typed data includes both `guest` and `reason` fields.
        assert!(
            display.contains("guest"),
            "expected display to contain guest data, got: {display}",
        );
    }

    #[test]
    fn event_display_without_data() {
        let event: qapi_qmp::Event = serde_json::from_str(
            r#"{"event": "STOP", "timestamp": {"seconds": 0, "microseconds": 0}}"#,
        )
        .unwrap();
        // STOP carries no payload, so the display should be just the
        // event name with no trailing data.
        assert_eq!(format!("{}", EventDisplay(&event)), "STOP");
    }

    // ── Message disambiguation ───────────────────────────────────────

    #[test]
    fn messages_deserialize_unambiguously() {
        // Verify that each message type deserializes to the correct
        // variant and does not accidentally match another variant.
        let return_json = r#"{"return": {"id": 1}}"#;
        let error_json = r#"{"error": {"class": "GenericError", "desc": "Y"}}"#;
        let event_json = r#"{"event": "RESET", "data": {"guest": false, "reason": "host-qmp-system-reset"}, "timestamp": {"seconds": 0, "microseconds": 0}}"#;

        match serde_json::from_str::<qapi_qmp::QmpMessageAny>(return_json).unwrap() {
            QmpMessage::Response(r) => {
                r.result()
                    .expect("return_json should be a success response");
            }
            other => panic!("expected Response for return_json, got {other:?}"),
        }
        match serde_json::from_str::<qapi_qmp::QmpMessageAny>(error_json).unwrap() {
            QmpMessage::Response(r) => {
                r.result()
                    .expect_err("error_json should be an error response");
            }
            other => panic!("expected Response for error_json, got {other:?}"),
        }
        assert!(matches!(
            serde_json::from_str::<qapi_qmp::QmpMessageAny>(event_json).unwrap(),
            QmpMessage::Event(qapi_qmp::Event::RESET { .. }),
        ));
    }
}
