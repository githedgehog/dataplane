// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The pipeline stage.

use crate::classify::{Classify, ip_bytes};
use crate::counts::Counts;
use crate::rules::{Enforcement, RateLimitReader, RateLimits};
use concurrency::sync::Arc;
use config::external::overlay::ratelimit::ColorAction;
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryIp, TryIpMut};
use net::ip::dscp::Dscp;
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use policer::{Color, LocalMeter};

/// One worker's hold on one rule.
#[derive(Debug)]
struct Local {
    enforcement: Arc<Enforcement>,
    meter: LocalMeter,
    counts: Arc<Counts>,
}

impl Local {
    fn new(enforcement: &Arc<Enforcement>) -> Local {
        Local {
            enforcement: Arc::clone(enforcement),
            meter: enforcement.meter.local(),
            counts: enforcement.counter(),
        }
    }
}

/// A worker's policing stage, following the rules published through a [`RateLimitReader`].
///
/// See the [rate-limit configuration](config::external::overlay::ratelimit) for matching and action
/// order, and [`policer::SharedMeter`] for token leasing.
pub struct RateLimiter<C> {
    reader: RateLimitReader<C>,
    /// The rules `locals` was made for.
    current: Option<Arc<RateLimits<C>>>,
    /// This worker's hold on each rule of `current`'s byte and packet tables, by index.
    locals: [Vec<Local>; 2],
}

impl<C> RateLimiter<C> {
    /// A stage enforcing what `reader` publishes.
    #[must_use]
    pub fn new(reader: RateLimitReader<C>) -> Self {
        RateLimiter {
            reader,
            current: None,
            locals: [Vec::new(), Vec::new()],
        }
    }

    /// Follow `limits`, keeping this worker's lease and counts of every rule that carries over.
    fn follow(&mut self, limits: &Arc<RateLimits<C>>) {
        if self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, limits))
        {
            return;
        }
        for (locals, table) in self.locals.iter_mut().zip(limits.tables()) {
            let mut previous = std::mem::take(locals);
            *locals = table
                .rules
                .iter()
                .map(|rule| {
                    previous
                        .iter()
                        .position(|local| Arc::ptr_eq(&local.enforcement, &rule.enforcement))
                        .map_or_else(
                            || Local::new(&rule.enforcement),
                            |i| previous.swap_remove(i),
                        )
                })
                .collect();
        }
        self.current = Some(Arc::clone(limits));
    }
}

fn remark<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, dscp: Dscp) {
    match packet.try_ip_mut() {
        Some(Net::Ipv4(ip)) => {
            ip.set_dscp(dscp);
        }
        Some(Net::Ipv6(ip)) => {
            ip.set_dscp(dscp);
        }
        None => return,
    }
    packet.meta_mut().set_checksum_refresh(true);
}

impl<Buf: PacketBufferMut, C: Classify> NetworkFunction<Buf> for RateLimiter<C> {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let limits = self.reader.load();
        if limits.tables().iter().all(|table| table.rules.is_empty()) {
            return;
        }
        self.follow(&limits);
        let now = clock::now();
        for packet in burst
            .iter_mut()
            .filter(|packet| !packet.is_done() && packet.meta().is_overlay())
        {
            let Some(bytes) = packet.try_ip().map(ip_bytes) else {
                continue;
            };
            let mut color = Color::Green;
            for (table, locals) in limits.tables().into_iter().zip(&mut self.locals) {
                let Some(index) = table.classifier.classify(packet) else {
                    continue;
                };
                let local = &mut locals[index];
                color = local.meter.color(now, table.unit().cost(bytes), color);
                local.counts.add(color, bytes);
                match table.rules[index].action(color) {
                    ColorAction::Pass => {}
                    ColorAction::Remark(dscp) => remark(packet, dscp),
                    ColorAction::Drop => {
                        packet.done(DoneReason::RateLimited);
                        break;
                    }
                }
            }
        }
    }
}
