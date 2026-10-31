// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The pipeline stage.

use crate::classify::{Classify, billed_bytes};
use crate::counts::Counts;
use crate::rules::{Enforcement, RateLimitReader, RateLimits};
use concurrency::sync::Arc;
use config::external::overlay::ratelimit::ColorAction;
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryIpMut};
use net::ip::dscp::Dscp;
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use policer::{Color, LocalMeter};

/// One worker's lease on one meter component.
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
    /// One lease per meter component, shared by every matching rule on this worker.
    locals: Vec<[Option<Local>; 2]>,
}

impl<C> RateLimiter<C> {
    /// A stage enforcing what `reader` publishes.
    #[must_use]
    pub fn new(reader: RateLimitReader<C>) -> Self {
        RateLimiter {
            reader,
            current: None,
            locals: Vec::new(),
        }
    }

    /// Follow `limits`, keeping this worker's lease and counts of every meter that carries over.
    fn follow(&mut self, limits: &Arc<RateLimits<C>>) {
        if self
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, limits))
        {
            return;
        }
        let mut previous: Vec<Local> = std::mem::take(&mut self.locals)
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        self.locals = limits
            .meters
            .iter()
            .map(|meter| {
                std::array::from_fn(|i| {
                    meter.components[i].as_ref().map(|component| {
                        let enforcement = &component.enforcement;
                        if let Some(index) = previous
                            .iter()
                            .position(|local| local.enforcement.shares_counts(enforcement))
                        {
                            let mut local = previous.swap_remove(index);
                            if !Arc::ptr_eq(&local.enforcement, enforcement) {
                                local.meter = enforcement.meter.local();
                                local.enforcement = Arc::clone(enforcement);
                            }
                            local
                        } else {
                            Local::new(enforcement)
                        }
                    })
                })
            })
            .collect();
        self.current = Some(Arc::clone(limits));
    }
}

/// Rewrite the packet's DSCP. Nothing needs a refresh: the IPv4 header folds the change into its own
/// checksum, IPv6 has none, and no transport checksum covers DSCP.
fn remark<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, dscp: Dscp) {
    match packet.try_ip_mut() {
        Some(Net::Ipv4(ip)) => {
            ip.set_dscp(dscp);
        }
        Some(Net::Ipv6(ip)) => {
            ip.set_dscp(dscp);
        }
        None => {}
    }
}

impl<Buf: PacketBufferMut, C: Classify> NetworkFunction<Buf> for RateLimiter<C> {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let limits = self.reader.load();
        self.follow(&limits);
        if limits.rules.is_empty() {
            return;
        }
        let now = clock::now();
        for packet in burst
            .iter_mut()
            .filter(|packet| !packet.is_done() && packet.meta().is_overlay())
        {
            let Some(bytes) = billed_bytes(packet) else {
                continue;
            };
            let Some(index) = limits.classifier.classify(packet) else {
                continue;
            };
            let meter_index = limits.rules[index].meter;
            let meter = &limits.meters[meter_index];
            let mut color = Color::Green;
            for unit in crate::rules::Unit::ALL {
                let i = unit.index();
                let Some(component) = meter.components[i].as_ref() else {
                    continue;
                };
                let Some(local) = self.locals[meter_index][i].as_mut() else {
                    continue;
                };
                color = local.meter.color(now, unit.cost(bytes), color);
                local.counts.add(color, bytes);
                match component.action(color) {
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
