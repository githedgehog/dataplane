//! Cloud-hypervisor event monitoring and JSON stream decoding.
//!
//! This module provides types for deserializing the event stream emitted by
//! [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)
//! via its `--event-monitor` file descriptor, along with an async codec for
//! reading those events incrementally from a pipe.
//!
//! The [`watch`] function consumes the event stream and returns a
//! [`HypervisorVerdict`] indicating whether the VM shut down cleanly.
//!
//! Both [`Source`] and [`EventType`] use `#[serde(other)]` on their
//! `Unknown` variants so that unrecognised strings emitted by newer
//! cloud-hypervisor versions do not cause deserialization failures.
//! Without this, a new event string would downgrade the
//! [`HypervisorVerdict`] to [`Failure`](HypervisorVerdict::Failure) and
//! turn an otherwise passing test into a false negative.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::StreamDeserializer;
use tokio_stream::StreamExt;
use tokio_util::bytes::{Buf, BytesMut};
use tracing::warn;

pub use crate::backend::HypervisorVerdict;

/// The component that emitted a hypervisor event.
#[derive(Debug, Copy, Clone, Deserialize)]
pub enum Source {
    /// The virtual machine itself.
    #[serde(rename = "vm")]
    Vm,
    /// The virtual machine monitor (VMM) process.
    #[serde(rename = "vmm")]
    Vmm,
    /// The guest operating system.
    #[serde(rename = "guest")]
    Guest,
    /// A virtio device backend.
    #[serde(rename = "virtio-device")]
    VirtioDevice,
    /// An unrecognised source (see module-level docs on `#[serde(other)]`).
    #[serde(other)]
    Unknown,
}

/// The type of hypervisor lifecycle event.
#[derive(Debug, Copy, Clone, Deserialize)]
pub enum EventType {
    /// The VMM is starting up.
    #[serde(rename = "starting")]
    Starting,
    /// The VM is booting (kernel loaded, about to execute).
    #[serde(rename = "booting")]
    Booting,
    /// The VM has finished booting.
    #[serde(rename = "booted")]
    Booted,
    /// A virtio device has been activated.
    #[serde(rename = "activated")]
    Activated,
    /// The VM has been deleted.
    #[serde(rename = "deleted")]
    Deleted,
    /// The VM or VMM has shut down cleanly.
    #[serde(rename = "shutdown")]
    Shutdown,
    /// The guest kernel panicked.
    #[serde(rename = "panic")]
    Panic,
    /// An unrecognised event type (see module-level docs on `#[serde(other)]`).
    #[serde(other)]
    Unknown,
}

/// A single event from the cloud-hypervisor event monitor.
///
/// Events are emitted as newline-delimited JSON objects on the file descriptor
/// passed via `--event-monitor fd=N`.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    /// Time elapsed since the VMM process started.
    pub timestamp: Duration,
    /// Which component emitted the event.
    pub source: Source,
    /// The lifecycle event that occurred.
    pub event: EventType,
    /// Optional key-value properties attached to the event.
    #[serde(deserialize_with = "deserialize_null_default")]
    pub properties: BTreeMap<String, String>,
}

/// Deserializes `null` JSON values as `T::default()` instead of failing.
fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Computes the [`HypervisorVerdict`] from a collected event log and a
/// flag indicating whether any stream-level deserialization errors occurred
/// during collection.
///
/// This is a **pure function** extracted from [`watch`] so that verdict
/// logic can be unit-tested with hand-crafted event sequences without
/// needing a pipe or tokio runtime.
///
/// The verdict is [`CleanShutdown`](HypervisorVerdict::CleanShutdown)
/// only if **all** of the following hold:
///
/// 1. A `(Vmm, Shutdown)` event was received.
/// 2. No `(Guest, Panic)` event preceded the shutdown in the event log.
/// 3. No stream-level deserialization errors occurred (indicated by
///    `had_stream_errors`).
///
/// Otherwise the verdict is [`Failure`](HypervisorVerdict::Failure).
pub fn compute_verdict(events: &[Event], had_stream_errors: bool) -> HypervisorVerdict {
    let mut tainted = had_stream_errors;

    for event in events {
        match (event.source, event.event) {
            (Source::Vmm, EventType::Shutdown) => {
                return if tainted {
                    HypervisorVerdict::Failure
                } else {
                    HypervisorVerdict::CleanShutdown
                };
            }
            (Source::Guest, EventType::Panic) => {
                tainted = true;
            }
            _ => {}
        }
    }

    // Stream ended without a VMM Shutdown event.
    HypervisorVerdict::Failure
}

/// A [`tokio_util::codec::Decoder`] that incrementally deserializes
/// concatenated JSON [`Event`] values from a byte stream.
///
/// This is used to parse the cloud-hypervisor event monitor output, which
/// consists of concatenated JSON objects written to a pipe.
///
/// The previous implementation carried a phantom lifetime and generic type
/// parameter that were never used -- the `Decoder` impl was always
/// monomorphised for [`Event`].  This version is a simple unit struct.
#[derive(Debug, Default)]
pub struct AsyncJsonStreamDecoder;

impl AsyncJsonStreamDecoder {
    /// Creates a new decoder.
    pub fn new() -> Self {
        Self
    }
}

/// Errors that can occur while decoding a JSON stream.
#[derive(Debug, thiserror::Error)]
pub enum AsyncJsonStreamError {
    /// A JSON deserialization error.
    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// An I/O error from the underlying reader.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl tokio_util::codec::Decoder for AsyncJsonStreamDecoder {
    type Item = Event;
    type Error = AsyncJsonStreamError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Scope the immutable borrow of `src` (via `as_ref()`) so that we
        // can call `src.advance()` afterward without a borrow conflict.
        let (next, bytes_consumed) = {
            let mut stream: StreamDeserializer<'_, serde_json::de::SliceRead<'_>, Event> =
                serde_json::Deserializer::from_slice(src.as_ref()).into_iter::<Event>();
            let next = stream.next();
            (next, stream.byte_offset())
        };
        match next {
            Some(Ok(value)) => {
                src.advance(bytes_consumed);
                Ok(Some(value))
            }
            // An EOF error means the buffer contains a partial JSON object
            // that is still being written to the pipe.  Return `Ok(None)`
            // to tell the framing layer to wait for more data rather than
            // treating it as a fatal parse error.
            Some(Err(err)) if err.classify() == serde_json::error::Category::Eof => Ok(None),
            Some(Err(err)) => Err(AsyncJsonStreamError::Json(err)),
            None => Ok(None),
        }
    }
}

/// Drains remaining events from the stream for up to
/// [`config::POST_PANIC_DRAIN_TIMEOUT`](crate::config::POST_PANIC_DRAIN_TIMEOUT),
/// appending them to `hlog`.
///
/// Called after a guest panic is detected so that subsequent lifecycle
/// events (e.g. VMM Shutdown, Deleted) are captured for diagnostics.
async fn drain_after_panic(
    reader: &mut tokio_util::codec::FramedRead<
        tokio::net::unix::pipe::Receiver,
        AsyncJsonStreamDecoder,
    >,
    hlog: &mut Vec<Event>,
) {
    let drain_deadline = tokio::time::sleep(crate::config::POST_PANIC_DRAIN_TIMEOUT);
    tokio::pin!(drain_deadline);
    loop {
        tokio::select! {
            event = reader.next() => {
                match event {
                    Some(Ok(value)) => {
                        hlog.push(value);
                    }
                    Some(Err(e)) => {
                        warn!(
                            "hypervisor event error during post-panic drain: {e:#?}"
                        );
                    }
                    None => break,
                }
            }
            () = &mut drain_deadline => {
                break;
            }
        }
    }
}

/// Consumes the hypervisor event stream and returns the collected events
/// along with a [`HypervisorVerdict`].
///
/// Event collection terminates when:
/// - A `(Vmm, Shutdown)` event is received (normal completion).
/// - A `(Guest, Panic)` event is received (remaining events are drained
///   for up to [`POST_PANIC_DRAIN_TIMEOUT`]).
/// - The stream ends (pipe closed).
///
/// The verdict is computed by [`compute_verdict`] from the collected
/// events and a flag tracking whether any stream-level deserialization
/// errors occurred.
pub async fn watch(receiver: tokio::net::unix::pipe::Receiver) -> (Vec<Event>, HypervisorVerdict) {
    let decoder = AsyncJsonStreamDecoder::new();

    let mut reader = tokio_util::codec::FramedRead::new(receiver, decoder);
    let mut hlog = Vec::with_capacity(32);
    let mut had_stream_errors = false;

    loop {
        match reader.next().await {
            Some(Ok(value)) => {
                let is_shutdown = matches!(
                    (value.source, value.event),
                    (Source::Vmm, EventType::Shutdown)
                );
                let is_panic = matches!(
                    (value.source, value.event),
                    (Source::Guest, EventType::Panic)
                );
                hlog.push(value);

                if is_shutdown || is_panic {
                    if is_panic {
                        drain_after_panic(&mut reader, &mut hlog).await;
                    }
                    break;
                }
            }
            Some(Err(e)) => {
                // Deserialization errors may hide critical events (e.g.
                // a guest panic encoded in a malformed JSON object), so
                // they are tracked and fed into the verdict computation.
                warn!("hypervisor event deserialization error (marking as failure): {e:#?}");
                had_stream_errors = true;
            }
            None => {
                break;
            }
        }
    }

    let verdict = compute_verdict(&hlog, had_stream_errors);
    (hlog, verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a minimal [`Event`] with the given source and type.
    fn event(source: Source, event: EventType) -> Event {
        Event {
            timestamp: Duration::from_secs(0),
            source,
            event,
            properties: BTreeMap::new(),
        }
    }

    #[test]
    fn clean_shutdown_without_errors() {
        let events = vec![
            event(Source::Vmm, EventType::Starting),
            event(Source::Vmm, EventType::Booting),
            event(Source::Vmm, EventType::Shutdown),
        ];
        assert_eq!(
            compute_verdict(&events, false),
            HypervisorVerdict::CleanShutdown,
        );
    }

    #[test]
    fn shutdown_with_stream_errors_is_failure() {
        let events = vec![
            event(Source::Vmm, EventType::Starting),
            event(Source::Vmm, EventType::Shutdown),
        ];
        assert_eq!(compute_verdict(&events, true), HypervisorVerdict::Failure,);
    }

    #[test]
    fn panic_before_shutdown_is_failure() {
        let events = vec![
            event(Source::Vmm, EventType::Starting),
            event(Source::Guest, EventType::Panic),
            event(Source::Vmm, EventType::Shutdown),
        ];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure,);
    }

    #[test]
    fn panic_without_shutdown_is_failure() {
        let events = vec![
            event(Source::Vmm, EventType::Starting),
            event(Source::Guest, EventType::Panic),
        ];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure,);
    }

    #[test]
    fn stream_ended_without_shutdown_is_failure() {
        let events = vec![
            event(Source::Vmm, EventType::Starting),
            event(Source::Vmm, EventType::Booting),
        ];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure,);
    }

    #[test]
    fn empty_event_log_is_failure() {
        assert_eq!(compute_verdict(&[], false), HypervisorVerdict::Failure,);
    }

    #[test]
    fn events_after_shutdown_are_ignored_for_verdict() {
        // Events collected after the shutdown (e.g. Deleted) should not
        // affect the verdict -- the shutdown event is the decision point.
        let events = vec![
            event(Source::Vmm, EventType::Starting),
            event(Source::Vmm, EventType::Shutdown),
            event(Source::Guest, EventType::Panic), // after shutdown
        ];
        assert_eq!(
            compute_verdict(&events, false),
            HypervisorVerdict::CleanShutdown,
        );
    }
}
