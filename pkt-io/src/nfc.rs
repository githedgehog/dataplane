// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

#![allow(unused)]

use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Receiver, Sender, channel};

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

pub type PktIOSender<Buf> = tokio::sync::mpsc::Sender<Box<Packet<Buf>>>;
pub type PktIOReceiver<Buf> = tokio::sync::mpsc::Receiver<Box<Packet<Buf>>>;

pub struct PktIORemote<Buf: PacketBufferMut> {
    inject_tx: PktIOSender<Buf>,
    punt_rx: PktIOReceiver<Buf>,
}

pub struct PktIo<Buf: PacketBufferMut> {
    name: String,
    inject_rx: PktIOReceiver<Buf>,
    punt_tx: PktIOSender<Buf>,
}

impl<Buf: PacketBufferMut> PktIo<Buf> {
    #[must_use]
    #[must_use]
    pub fn new(inject_capacity: usize, punt_capacity: usize) -> (Self, PktIORemote<Buf>) {
        let (inject_tx, inject_rx) = channel::<Box<Packet<Buf>>>(inject_capacity);
        let (punt_tx, punt_rx) = channel::<Box<Packet<Buf>>>(punt_capacity);
        let remote = PktIORemote { inject_tx, punt_rx };
        let this = Self {
            name: "anonymous".to_string(),
            inject_rx,
            punt_tx,
        };
        (this, remote)
    }
    #[must_use]
    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }
    pub fn punt(&self, packet: Box<Packet<Buf>>) -> Result<(), SendError<Box<Packet<Buf>>>> {
        self.punt_tx.blocking_send(packet)
    }
    pub fn inject_rx(&mut self) -> Option<Box<Packet<Buf>>> {
        self.inject_rx.blocking_recv()
    }

}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PktIo<Buf> {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        // injection path: fetch packets from injection queue (if there) and add them to the input iterator
        let mut accum = vec![];
        while let Some(pkt) = self.inject_rx() {
            accum.push(pkt);
        }

        // pint path
        let input = input.filter_map(|packet| {
            if packet.get_meta().local() {
                match self.punt(Box::new(packet)) {
                    Ok(()) => None, // punted!
                    Err(e) => {
                        let mut dropped= e.0;
                        dropped.done(DoneReason::InternalDrop);
                        trace!("Unable to punt packet\n{dropped}");
                        Some(*dropped) // leave as is for accounting
                    }
                }
            } else {
                Some(packet) // does not qualify
            }
        });

        input.chain(accum.into_iter().map(|boxed| *boxed))
    }
}
