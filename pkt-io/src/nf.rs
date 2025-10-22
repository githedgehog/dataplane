// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

#![allow(unused)]

use crossbeam::queue::ArrayQueue;
use net::packet::Packet;
use net::{buffer::PacketBufferMut, packet::DoneReason};
use pipeline::NetworkFunction;
use std::sync::Arc;
use tracectl::trace_target;
use tracing::trace;

const PKT_IO: &str = "pkt-io";
trace_target!(PKT_IO, LevelFilter::TRACE, &["pipeline"]);

// Type for a network function that performs two basic functions:
//    1) ability to inject packets into a pipeline (e.g. to transmit them).
//    2) ability to pull packets out of a pipeline (e.g. "punt" for local consumption).
//
// The above is achieved using two queues. One (inject) for the packets to be injected into the
// pipeline, which may be populated by other thread(s) to "send" packets to a pipeline. Another
// one (punt) that can contain packets that have been removed from the pipeline to be processed
// elsewhere, possibly by another thread. The two queues have a fixed capacity. They are defined
// to hold Box<Packet>'s so that setting large capacities does not consume a large amount of memory.
// For the same reason, the two queues are optional to accommodate for the case that only injection
// or punting are used.

#[repr(transparent)]
pub struct PktQueue<Buf: PacketBufferMut>(Arc<ArrayQueue<Box<Packet<Buf>>>>);
impl<Buf: PacketBufferMut> Clone for PktQueue<Buf> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<Buf: PacketBufferMut> PktQueue<Buf> {
    pub fn new(capacity: usize) -> Self {
        Self(Arc::new(ArrayQueue::new(capacity)))
    }
    pub fn pop(&self) -> Option<Box<Packet<Buf>>> {
        self.0.pop()
    }
    pub fn push(&self, packet: Box<Packet<Buf>>) -> Result<(), Box<Packet<Buf>>> {
        self.0.push(packet)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct PktIo<Buf: PacketBufferMut> {
    name: String,
    injectq: Option<PktQueue<Buf>>,
    puntq: Option<PktQueue<Buf>>,
}

impl<Buf: PacketBufferMut> PktIo<Buf> {
    #[must_use]
    pub fn create_queue(capacity: usize) -> Option<PktQueue<Buf>> {
        match capacity {
            0 => None,
            n => Some(PktQueue::new(n)),
        }
    }
    #[must_use]
    pub fn new(inject_capacity: usize, punt_capacity: usize) -> Self {
        Self {
            name: "anonymous".to_string(),
            injectq: Self::create_queue(inject_capacity),
            puntq: Self::create_queue(punt_capacity),
        }
    }
    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.to_owned();
        self
    }
    pub fn set_injectq(&mut self, queue: PktQueue<Buf>) {
        self.injectq = Some(queue)
    }
    pub fn set_puntq(&mut self, queue: PktQueue<Buf>) {
        self.puntq = Some(queue)
    }
    #[must_use]
    pub fn get_injectq(&self) -> Option<PktQueue<Buf>> {
        self.injectq.as_ref().map(|q| PktQueue(Arc::clone(&q.0)))
    }
    #[must_use]
    pub fn get_puntq(&self) -> Option<PktQueue<Buf>> {
        self.puntq.as_ref().map(|q| PktQueue(Arc::clone(&q.0)))
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PktIo<Buf> {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        // punt path: pull packets out of the input iterator, based on some criteria.
        // Here we assume that packets to be pulled off have been marked as local, but other
        // criteria may work. QUESTION: do we need/want this to be configurable?, or should this
        // stage remain simple and the preceding stages keep the knowledge of what needs to be
        // punted and set the local flag?

        let input = input.filter_map(|packet| {
            match &self.puntq {
                None => Some(packet),
                Some(puntq) => {
                    if packet.get_meta().local() && !packet.is_done() {
                        match puntq.push(Box::new(packet)) {
                            Ok(()) => None, // punted!
                            Err(mut packet) => {
                                trace!("Unable to punt packet\n{packet}");
                                packet.done(DoneReason::InternalDrop);
                                Some(*packet) // leave as is for accounting
                            }
                        }
                    } else {
                        Some(packet) // does not qualify
                    }
                }
            }
        });

        // injection path: fetch packets from injection queue (if there) and add them to the input iterator
        let mut accum = vec![];
        if let Some(injectq) = &self.injectq {
            while let Some(pkt) = injectq.pop() {
                accum.push(pkt);
            }
        }
        input.chain(accum.into_iter().map(|boxed| *boxed))
    }
}
