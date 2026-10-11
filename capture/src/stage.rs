// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A pipeline stage which copies packets out to a [`CaptureSink`].

use crate::record::{CaptureRecord, Direction, ThreadLabel};
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::NetworkFunction;
use std::cell::OnceCell;

/// Where a [`CaptureStage`] sends its records.
///
/// Admission is a separate step from submission so that a sink can sample and filter before anything is
/// copied: a packet the sink does not want costs only the call to [`CaptureSink::admits`].
pub trait CaptureSink {
    /// Whether this burst can capture anything at all.
    ///
    /// Called once per burst, so that a sink with nothing to do (no capture running) costs one call per
    /// burst rather than one per packet.
    fn begin_burst(&mut self) -> bool {
        true
    }

    /// Whether to capture `packet`.
    fn admits<Buf: PacketBufferMut>(&mut self, packet: &Packet<Buf>) -> bool;

    /// Take a record of an admitted packet.
    ///
    /// This must not block: it runs on a packet-processing thread.
    fn submit(&mut self, record: CaptureRecord);
}

/// Keeps every packet. Meant for tests.
impl CaptureSink for Vec<CaptureRecord> {
    fn admits<Buf: PacketBufferMut>(&mut self, _: &Packet<Buf>) -> bool {
        true
    }

    fn submit(&mut self, record: CaptureRecord) {
        self.push(record);
    }
}

/// A network function which records the packets passing it and leaves them unchanged.
///
/// The same stage serves as the production ingress and egress capture points and as a probe anywhere in a
/// test pipeline.
pub struct CaptureStage<S> {
    direction: Direction,
    sink: S,
    thread: OnceCell<Option<ThreadLabel>>,
}

impl<S: CaptureSink> CaptureStage<S> {
    /// A stage which records packets going in `direction` and sends the records to `sink`.
    #[must_use]
    pub fn new(direction: Direction, sink: S) -> Self {
        CaptureStage {
            direction,
            sink,
            thread: OnceCell::new(),
        }
    }

    /// The sink this stage sends its records to.
    #[must_use]
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Consume the stage, returning its sink.
    #[must_use]
    pub fn into_sink(self) -> S {
        self.sink
    }

    /// The label of the thread processing packets.
    ///
    /// Read on first use rather than at construction, because a pipeline may be built on a different thread
    /// than the one which runs it.
    fn thread(&self) -> Option<ThreadLabel> {
        *self.thread.get_or_init(|| {
            std::thread::current().name().map(|name| {
                let mut label = ThreadLabel::new();
                for c in name.chars() {
                    if label.try_push(c).is_err() {
                        break;
                    }
                }
                label
            })
        })
    }
}

impl<Buf: PacketBufferMut, S: CaptureSink> NetworkFunction<Buf> for CaptureStage<S> {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        if !self.sink.begin_burst() {
            return;
        }
        for packet in burst.iter() {
            if !self.sink.admits(packet) {
                continue;
            }
            let thread = self.thread();
            let record = CaptureRecord::new(self.direction, packet, clock::system_now(), thread);
            self.sink.submit(record);
        }
    }
}
