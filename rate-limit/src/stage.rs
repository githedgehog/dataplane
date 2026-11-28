// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The pipeline stage.

use crate::classify::PeeringRules;
use crate::classify::{Classify, Vpcs};
use crate::counts::Counts;
use crate::drops::Dropped;
use crate::ingress::IngressRules;
use crate::rules::{Action, Enforcement, RateLimitReader, RateLimits};
use clock::Instant;
use concurrency::sync::Arc;
use config::external::overlay::ratelimit::ColorAction;
use dag::generation::Join;
use dag::{Burst, Drops, Emit, Has, Keep, Meta, Sel, State, kind};
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryIpMut};
use net::ip::dscp::Dscp;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use policer::{Color, LocalMeter};
use std::collections::HashMap;

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

/// This worker's leases and drop counts for one published configuration.
#[derive(Debug)]
struct Leases<C> {
    /// The rules they were made for.
    limits: Arc<RateLimits<C>>,
    /// One lease per meter component, shared by every matching rule on this worker.
    locals: Vec<[Option<Local>; 2]>,
    /// The count each drop rule adds to, by rule index: resolved when the configuration is, so a
    /// flood's drops cost no lookup.
    rule_drops: Vec<Option<Arc<Dropped>>>,
}

/// A worker's policing stage, following the rules published through a [`RateLimitReader`].
///
/// See the [rate-limit configuration](config::external::overlay::ratelimit) for matching and action
/// order, and [`policer::SharedMeter`] for token leasing.
///
/// It keeps leases for the two configurations it last served: while a generation flip drains,
/// a burst can hold packets of both (`dag::generation`), and the stage runs once for each. With
/// one set it rebuilt every lease twice per such burst, and a meter whose profile changed between
/// them lost its lease's tokens each time.
pub struct RateLimiter<C> {
    reader: RateLimitReader<C>,
    /// The leases of the two configurations last served.
    sets: [Option<Leases<C>>; 2],
    /// Which of `sets` was served last.
    current: usize,
    /// This worker's counts of what drop rules dropped, by source VPC, across configurations.
    dropped: HashMap<Vni, Arc<Dropped>>,
    /// Leases made, for tests.
    #[cfg(test)]
    pub(crate) leases_made: usize,
}

impl<C> RateLimiter<C> {
    /// A stage enforcing what `reader` publishes.
    #[must_use]
    pub fn new(reader: RateLimitReader<C>) -> Self {
        RateLimiter {
            reader,
            sets: [None, None],
            current: 0,
            dropped: HashMap::new(),
            #[cfg(test)]
            leases_made: 0,
        }
    }

    /// Where this stage reads its rules: the legacy path loads them itself, typed callers pass them.
    #[must_use]
    pub fn reader(&self) -> &RateLimitReader<C> {
        &self.reader
    }

    /// Serve `limits`: the leases already made for it, or new ones in place of the set served
    /// longest ago, keeping that set's lease and counts of every meter that carries over.
    pub(crate) fn follow(&mut self, limits: &Arc<RateLimits<C>>) {
        let serves = |set: &Option<Leases<C>>| {
            set.as_ref()
                .is_some_and(|set| Arc::ptr_eq(&set.limits, limits))
        };
        if serves(&self.sets[self.current]) {
            return;
        }
        let other = 1 - self.current;
        if serves(&self.sets[other]) {
            self.current = other;
            return;
        }
        let mut previous: Vec<Local> = self.sets[other].take().map_or_else(Vec::new, |set| {
            set.locals.into_iter().flatten().flatten().collect()
        });
        #[cfg(test)]
        let mut made = 0;
        let locals = limits
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
                                #[cfg(test)]
                                {
                                    made += 1;
                                }
                            }
                            local
                        } else {
                            #[cfg(test)]
                            {
                                made += 1;
                            }
                            Local::new(enforcement)
                        }
                    })
                })
            })
            .collect();
        #[cfg(test)]
        {
            self.leases_made += made;
        }
        let rule_drops = limits
            .rules
            .iter()
            .map(|rule| match (rule.action, rule.from) {
                (Action::Drop, Some(vni)) => Some(Arc::clone(
                    self.dropped
                        .entry(vni)
                        .or_insert_with(|| limits.drops.counter(vni)),
                )),
                _ => None,
            })
            .collect();
        self.sets[other] = Some(Leases {
            limits: Arc::clone(limits),
            locals,
            rule_drops,
        });
        self.current = other;
    }

    /// The leases of the configuration served now ([`RateLimiter::follow`]).
    fn served(&mut self) -> &mut Leases<C> {
        self.sets[self.current]
            .as_mut()
            .unwrap_or_else(|| unreachable!("followed before serving"))
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

impl<C: Classify> RateLimiter<C> {
    /// Police one packet going between `vpcs`: `Some(reason)` if it must be dropped. Remarking
    /// happens in place.
    fn police<Buf: PacketBufferMut>(
        &mut self,
        limits: &RateLimits<C>,
        packet: &mut Packet<Buf>,
        vpcs: Vpcs,
        now: Instant,
    ) -> Option<DoneReason> {
        let index = limits.classifier.classify_with(packet, vpcs)?;
        let leases = self.served();
        let meter_index = match limits.rules[index].action {
            Action::Police(meter) => meter,
            Action::Drop => {
                if let Some(Some(dropped)) = leases.rule_drops.get(index) {
                    dropped.add();
                }
                return Some(DoneReason::IngressDropped);
            }
        };
        let bytes = C::BILLING.bytes(packet)?;
        let meter = &limits.meters[meter_index];
        let mut color = Color::Green;
        for unit in crate::rules::Unit::ALL {
            let i = unit.index();
            let Some(component) = meter.components[i].as_ref() else {
                continue;
            };
            let Some(local) = leases.locals[meter_index][i].as_mut() else {
                continue;
            };
            color = local.meter.color(now, unit.cost(bytes), color);
            local.counts.add(color, bytes);
            match component.action(color) {
                ColorAction::Pass => {}
                ColorAction::Remark(dscp) => remark(packet, dscp),
                ColorAction::Drop => return Some(DoneReason::RateLimited),
            }
        }
        None
    }

    /// Police a selection: the typed stage, generic over what else its input carries. `vpcs`
    /// reads the VPCs from the proven metadata.
    fn run<'b, Buf: PacketBufferMut, S: State>(
        &mut self,
        burst: &mut Burst<'b, Buf>,
        input: Sel<'b, S>,
        limits: &Arc<RateLimits<C>>,
        vpcs: impl Fn(&Meta<'_, S>) -> Vpcs,
    ) -> Policed<'b, S> {
        self.follow(limits);
        if limits.rules.is_empty() {
            return Policed {
                passed: input,
                dropped: Drops::none(),
            };
        }
        let mut passed = Emit::<S, Keep>::new();
        let mut dropped = Drops::none();
        let now = clock::now();
        for i in input {
            let vpcs = vpcs(&burst.meta(&i));
            match self.police(limits, burst.packet_mut(&i), vpcs, now) {
                None => passed.push(i),
                Some(reason) => burst.drop(&mut dropped, i, reason),
            }
        }
        Policed {
            passed: passed.finish(),
            dropped,
        }
    }
}

/// The VNI of a VPC.
fn vni(VpcDiscriminant::VNI(vni): VpcDiscriminant) -> Vni {
    vni
}

/// What a typed rate limiter does with its input.
#[derive(Debug)]
pub struct Policed<'b, S> {
    /// Within their limits (possibly remarked).
    pub passed: Sel<'b, S>,
    /// Dropped by a drop rule or a meter.
    pub dropped: Drops<'b>,
}

impl<S: State> Join for Policed<'_, S> {
    fn join(self, other: Self) -> Self {
        Policed {
            passed: self.passed.union(other.passed),
            dropped: self.dropped.join(other.dropped),
        }
    }
}

impl RateLimiter<IngressRules> {
    /// The gateway's ingress policy, on packets whose source VPC is known.
    pub fn process_sel<'b, Buf: PacketBufferMut, S: Has<kind::SrcVpc>>(
        &mut self,
        burst: &mut Burst<'b, Buf>,
        input: Sel<'b, S>,
        limits: &'b Arc<RateLimits<IngressRules>>,
    ) -> Policed<'b, S> {
        self.run(burst, input, limits, |meta| Vpcs {
            src: Some(vni(*meta.get::<kind::SrcVpc>())),
            dst: None,
        })
    }
}

impl RateLimiter<PeeringRules> {
    /// Peering rate limits, on packets whose source and destination VPCs are known.
    pub fn process_sel<'b, Buf, S>(
        &mut self,
        burst: &mut Burst<'b, Buf>,
        input: Sel<'b, S>,
        limits: &'b Arc<RateLimits<PeeringRules>>,
    ) -> Policed<'b, S>
    where
        Buf: PacketBufferMut,
        S: Has<kind::SrcVpc> + Has<kind::DstVpc>,
    {
        self.run(burst, input, limits, |meta| Vpcs {
            src: Some(vni(*meta.get::<kind::SrcVpc>())),
            dst: Some(vni(*meta.get::<kind::DstVpc>())),
        })
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
            let vpcs = Vpcs::of(packet.meta());
            if let Some(reason) = self.police(&limits, packet, vpcs, now) {
                packet.done(reason);
            }
        }
    }
}
