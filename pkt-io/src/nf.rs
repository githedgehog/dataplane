// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

#![allow(unused)]

use crossbeam::queue::ArrayQueue;
use net::packet::Packet;
use net::{buffer::PacketBufferMut, packet::DoneReason};
use pipeline::NetworkFunction;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::sync::futures::Notified;
use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, trace};

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

pub struct PktQueue<Buf: PacketBufferMut> {
    queue: Arc<ArrayQueue<Box<Packet<Buf>>>>,
    notify: Arc<Notify>,
}

impl<Buf: PacketBufferMut> Clone for PktQueue<Buf> {
    fn clone(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
            notify: Arc::clone(&self.notify),
        }
    }
}

impl<Buf: PacketBufferMut> PktQueue<Buf> {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let notify = Arc::new(Notify::new());
        Self {
            queue: Arc::new(ArrayQueue::new(capacity)),
            notify: Arc::new(Notify::new()),
        }
    }
    #[must_use]
    pub fn pop(&self) -> Option<Box<Packet<Buf>>> {
        self.queue.pop()
    }
    /// Push a [`Packet`] (boxed) to this queue.
    /// # Errors
    ///
    /// This method fails if the queue is full.
    pub fn push(&self, packet: Box<Packet<Buf>>) -> Result<(), Box<Packet<Buf>>> {
        self.queue.push(packet)
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
    pub fn notify(&self) {
        self.notify.notify_one();
    }
    pub fn notified(&self) -> Notified<'_> {
        self.notify.notified()
    }
}

pub struct PktIo<Buf: PacketBufferMut> {
    name: String,
    injectq: Option<PktQueue<Buf>>,
    puntq: Option<PktQueue<Buf>>,
}
impl<Buf: PacketBufferMut> Clone for PktIo<Buf> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            injectq: self.injectq.clone(),
            puntq: self.puntq.clone(),
        }
    }
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
    #[must_use]
    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }
    pub fn set_injectq(&mut self, queue: PktQueue<Buf>) {
        self.injectq = Some(queue);
    }
    pub fn set_puntq(&mut self, queue: PktQueue<Buf>) {
        self.puntq = Some(queue);
    }

    #[must_use]
    pub fn get_injectq(&self) -> Option<PktQueue<Buf>> {
        self.injectq.clone()
    }

    #[must_use]
    pub fn get_puntq(&self) -> Option<PktQueue<Buf>> {
        self.puntq.clone()
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

        let input = input.filter_map(|mut packet| {
            match &self.puntq {
                None => Some(packet),
                Some(puntq) => {
                        packet.get_meta_mut().set_local(true);
                        match puntq.push(Box::new(packet)) {
                            Ok(()) => None, // punted!
                            Err(mut packet) => {
                                trace!("Unable to punt packet\n{packet}");
                                packet.done(DoneReason::InternalDrop);
                                Some(*packet) // leave as is for accounting
                            }
                        }
                }
            }
        });

        if let Some(puntq) = &self.puntq {
            // Todo(fredi): only notify if we actually punted packets
            puntq.notify();
        }

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
