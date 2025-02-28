// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements a packet stats sink.
//! Currently, it only includes `PacketDropStats`, but other type of statistics could
//! be added like protocol breakdowns.

use crate::NetworkFunction;
use crate::packet::Packet;
use crate::packet_meta::PacketDropStats;
use net::buffer::PacketBufferMut;
use tracing::trace;

use std::sync::Arc;
use std::sync::RwLock;

#[allow(unused)]
pub struct StatsSink {
    name: String,
    dropstats: Arc<RwLock<PacketDropStats>>,
    // other stats here
}

#[allow(dead_code)]
impl StatsSink {
    pub fn new(name: &str, dropstats: &Arc<RwLock<PacketDropStats>>) -> Self {
        Self {
            name: name.to_owned(),
            dropstats: dropstats.clone(),
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for StatsSink {
    fn nf_name(&self) -> &str {
        &self.name
    }
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        trace!(
            "Stage '{}'...",
            <Self as NetworkFunction<Buf>>::nf_name(self)
        );
        // locking once instead of inside filter map closure
        if let Ok(mut dropstats) = self.dropstats.write() {
            input.filter_map(move |packet| {
                if let Some(reason) = packet.get_drop() {
                    dropstats.incr(reason, 1);
                }
                packet.fate()
            })
        } else {
            panic!("Poisoned");
        }
    }
}
