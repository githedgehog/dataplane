// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Concurrent property tests for masquerade flow creation racing an allocator replacement.
//!
//! Packet workers send datagrams and replies through the masquerade NF while a writer publishes
//! configuration updates over the same flow table. A replacement allocator only learns about the
//! tuples of the flows it finds in the table, so a flow drawn from the previous allocator must not
//! be published once the replacement is installed: the replacement could hand its tuple to another
//! flow, possibly from another tenant, and replies would go to the wrong flow.
//!
//! Oracle: between two updates that may invalidate flows (an epoch), a public source tuple on the
//! wire must always come from the same private source tuple, and a reply to that public tuple must
//! reach that private source. Packets processed while such an update starts or ends are not
//! checked, because tuples of invalidated flows may be legitimately reused. Once workers are done,
//! live flows must serve the last generation, and new flows must not get their tuples.
//!
//! Loom is excluded, because its `Weak` shim keeps liveness entries alive.

#![cfg(test)]
#![cfg(not(feature = "loom"))]

use crate::Masquerade;
use crate::masquerade::probe::{destination_of, masquerade_expose, outbound_probe, source_of};
use crate::masquerade::{MasqueradeConfig, NatAllocatorWriter};
use crate::static_nat::probe::{build, vni};
use bolero::TypeGenerator;
use concurrency::sync::atomic::{AtomicU64, Ordering};
use concurrency::sync::{Arc, Mutex};
use concurrency::thread;
use config::GenId;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use flow_entry::flow_table::FlowTable;
use net::buffer::TestBuffer;
use net::flows::FlowStatus;
use net::packet::{Packet, VpcDiscriminant};
use pipeline::NetworkFunction;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::num::NonZero;

/// A local VPC masquerading toward the remote one: name, id, VNI, first octets of its private /24.
struct Tenant(&'static str, &'static str, u32, [u8; 2]);

// Two tenants sharing one public range, so that a reissued tuple can cross tenants
static TENANTS: [Tenant; 2] = [
    Tenant("VPC-1", "AAAAA", 100, [10, 0]),
    Tenant("VPC-3", "CCCCC", 300, [10, 3]),
];
const REMOTE_VNI: u32 = 200;
const SHARED_POOL: &str = "172.16.0.0/24";
const MOVED_POOL: &str = "172.16.2.0/24";

// Few hosts and peers, so that workers often send the same flow, and flows toward distinct peers
// can share a public tuple without colliding on the reverse key.
const HOSTS: u8 = 3;
const PEERS: u8 = 2;
const WORKERS: usize = 2;
const MAX_OPS: usize = 4;
const MAX_UPDATES: usize = 3;
const SPORT: u16 = 4000;
const DPORT: u16 = 8000;

/// What a packet worker does.
#[derive(Clone, Copy, Debug, TypeGenerator)]
enum Op {
    /// A datagram from a tenant's host to a peer
    Send { tenant: u8, host: u8, peer: u8 },
    /// A reply to one of the datagrams seen on the wire so far
    Reply { pick: u8 },
}

/// A configuration the writer can publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TypeGenerator)]
enum Layout {
    /// Both tenants masquerade onto the shared pool
    Base,
    /// Same as base, plus a disjoint pool for another prefix: this rebuilds the allocator, but
    /// carries all flows over
    Extended,
    /// Both tenants masquerade onto another pool: flows are invalidated
    Moved,
    /// No peerings, no masquerading: the allocator is removed and flows are invalidated
    Removed,
}

/// What the writer does.
#[derive(Clone, Copy, Debug, TypeGenerator)]
enum Update {
    /// Publish a layout, possibly the current one
    Publish(Layout),
    /// Publish the current layout again, which only advances the generation id
    Unchanged,
}

#[derive(Clone, Debug)]
struct Scenario {
    ops: [Vec<Op>; WORKERS],
    updates: Vec<Update>,
    randomize: bool,
}

impl TypeGenerator for Scenario {
    /// Ensure every generated shape has concurrent packet and configuration work.
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let mut ops: [Vec<Op>; WORKERS] = driver.produce()?;
        for worker in &mut ops {
            worker.truncate(MAX_OPS);
            if !worker.iter().any(|op| matches!(op, Op::Send { .. })) {
                let (tenant, host, peer) = driver.produce()?;
                worker.insert(0, Op::Send { tenant, host, peer });
            }
        }
        let mut updates: Vec<Update> = driver.produce()?;
        updates.truncate(MAX_UPDATES);
        if updates.is_empty() {
            updates.push(driver.produce()?);
        }
        Some(Self {
            ops,
            updates,
            randomize: driver.produce()?,
        })
    }
}

/// A scenario narrowed down to the race itself: datagrams only, and updates that rebuild the
/// allocator without invalidating flows, over sequential ports. Broad scenarios reach it much less
/// often.
#[derive(Clone, Debug)]
struct Rebuilds(Scenario);

impl TypeGenerator for Rebuilds {
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let mut sends: [Vec<(u8, u8, u8)>; WORKERS] = driver.produce()?;
        for worker in &mut sends {
            worker.truncate(MAX_OPS);
            if worker.is_empty() {
                worker.push(driver.produce()?);
            }
        }
        let ops = sends.map(|worker| {
            let send = |(tenant, host, peer)| Op::Send { tenant, host, peer };
            worker.into_iter().map(send).collect()
        });
        let count = usize::from(driver.produce::<u8>()?) % MAX_UPDATES + 1;
        let layouts = [Layout::Extended, Layout::Base].into_iter().cycle();
        let updates = layouts.take(count).map(Update::Publish).collect();
        Some(Self(Scenario {
            ops,
            updates,
            randomize: false,
        }))
    }
}

impl Layout {
    fn pool(self) -> Option<&'static str> {
        match self {
            Layout::Base | Layout::Extended => Some(SHARED_POOL),
            Layout::Moved => Some(MOVED_POOL),
            Layout::Removed => None,
        }
    }

    fn overlay(self) -> Overlay {
        let mut vpcs = VpcTable::new();
        let remote = ("VPC-2", "BBBBB", REMOTE_VNI);
        for (name, id, vni) in TENANTS.iter().map(|t| (t.0, t.1, t.2)).chain([remote]) {
            vpcs.add(Vpc::new(name, id, vni).unwrap_or_else(|e| unreachable!("{e}")))
                .unwrap_or_else(|e| unreachable!("{e}"));
        }
        let mut peerings = VpcPeeringTable::new();
        for (index, tenant) in TENANTS.iter().enumerate() {
            let Some(pool) = self.pool() else { break };
            let [a, b] = tenant.3;
            let mut local = VpcManifest::new(tenant.0)
                .exposing(masquerade_expose(&format!("{a}.{b}.0.0/24"), pool));
            if self == Layout::Extended && index == 0 {
                local = local.exposing(masquerade_expose("10.1.0.0/24", "172.16.1.0/24"));
            }
            let remote =
                VpcManifest::new("VPC-2").exposing(VpcExpose::empty().ip("3.3.3.0/24".into()));
            let name = format!("{}--VPC-2", tenant.0);
            peerings
                .add(VpcPeering::with_default_group(&name, local, remote))
                .unwrap_or_else(|e| unreachable!("{e}"));
        }
        Overlay::new(vpcs, peerings)
    }

    fn masquerade_config(self, randomize: bool) -> MasqueradeConfig {
        let overlay = self
            .overlay()
            .validate()
            .unwrap_or_else(|e| unreachable!("{e}"));
        MasqueradeConfig::new(overlay.vpc_table()).set_randomize(randomize)
    }
}

fn discriminant(raw: u32) -> VpcDiscriminant {
    VpcDiscriminant::from_vni(vni(raw))
}

fn tenant_of(address: IpAddr) -> &'static Tenant {
    TENANTS
        .iter()
        .find(|tenant| matches!(address, IpAddr::V4(ip) if ip.octets()[..2] == tenant.3))
        .unwrap_or_else(|| unreachable!("{address} is not a tenant's"))
}

fn datagram(tenant: &Tenant, host: u8, peer: u8, sport: u16) -> Packet<TestBuffer> {
    let [a, b] = tenant.3;
    let source = IpAddr::from([a, b, 0, host % HOSTS + 1]);
    let destination = IpAddr::from([3, 3, 3, peer % PEERS + 1]);
    let mut packet = outbound_probe(source, destination, sport, DPORT);
    packet.meta_mut().src_vpcd = Some(discriminant(tenant.2));
    packet
}

fn reply(emission: &Emission) -> Packet<TestBuffer> {
    let (peer, peer_port) = emission.peer;
    let (public, public_port) = emission.public;
    let mut packet: Packet<TestBuffer> = build(peer, public, false, peer_port, public_port);
    let meta = packet.meta_mut();
    meta.set_overlay(true);
    meta.set_masquerade(true);
    meta.src_vpcd = Some(discriminant(REMOTE_VNI));
    meta.dst_vpcd = Some(discriminant(tenant_of(emission.private.0).2));
    packet
}

/// A datagram seen on the wire.
#[derive(Clone, Copy, Debug)]
struct Emission {
    epoch: u64,
    private: (IpAddr, u16),
    public: (IpAddr, u16),
    peer: (IpAddr, u16),
}

/// What the workers saw on the wire, and the epoch they are in.
struct Wire {
    epoch: AtomicU64,
    emissions: Mutex<Vec<Emission>>,
}

impl Wire {
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    // Mark the start or the end of an update that may invalidate flows
    fn bump(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    fn sent(&self, emission: Emission) {
        let mut emissions = self.emissions.lock();
        for earlier in emissions.iter() {
            assert!(
                earlier.epoch != emission.epoch
                    || earlier.public != emission.public
                    || earlier.private == emission.private,
                "public tuple {:?} was used for both {:?} and {:?}",
                emission.public,
                earlier.private,
                emission.private
            );
        }
        emissions.push(emission);
    }

    fn pick(&self, pick: u8) -> Option<Emission> {
        let emissions = self.emissions.lock();
        (!emissions.is_empty()).then(|| emissions[usize::from(pick) % emissions.len()])
    }
}

/// Process one packet, and tell the epoch it was processed in, if no invalidating update started
/// or ended in the meantime.
fn process(
    masq: &mut Masquerade,
    wire: &Wire,
    packet: Packet<TestBuffer>,
) -> (Option<u64>, Vec<Packet<TestBuffer>>) {
    let before = wire.epoch();
    // Dropped packets come out too, marked done
    let out = masq
        .process(std::iter::once(packet))
        .filter(|packet| !packet.is_done())
        .collect();
    (Some(before).filter(|&epoch| epoch == wire.epoch()), out)
}

fn work(masq: &mut Masquerade, wire: &Wire, ops: &[Op]) {
    for &op in ops {
        match op {
            Op::Send { tenant, host, peer } => {
                let tenant = &TENANTS[usize::from(tenant) % TENANTS.len()];
                let packet = datagram(tenant, host, peer, SPORT);
                let (private, peer) = (source_of(&packet), destination_of(&packet));
                let (epoch, out) = process(masq, wire, packet);
                for out in out {
                    if let Some(epoch) = epoch {
                        let public = source_of(&out);
                        wire.sent(Emission {
                            epoch,
                            private,
                            public,
                            peer,
                        });
                    }
                }
            }
            Op::Reply { pick } => {
                let Some(emission) = wire.pick(pick) else {
                    continue;
                };
                let (epoch, out) = process(masq, wire, reply(&emission));
                if epoch != Some(emission.epoch) {
                    continue;
                }
                for out in out {
                    assert_eq!(
                        destination_of(&out),
                        emission.private,
                        "a reply from {:?} to {:?} was meant for {:?}",
                        emission.peer,
                        emission.public,
                        emission.private
                    );
                }
            }
        }
    }
}

impl Scenario {
    fn run(&self) {
        // Flow timers need a runtime outside of the model backends. It is never driven, so flows do
        // not expire during the scenario.
        #[cfg(not(feature = "shuttle"))]
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap_or_else(|e| unreachable!("{e}"));

        let flow_table = Arc::new(FlowTable::new(16));
        let mut writer = NatAllocatorWriter::new();
        let mut layout = Layout::Base;
        let mut genid: GenId = 1;
        writer.update_nat_allocator(layout.masquerade_config(self.randomize), genid, &flow_table);
        let reader = writer.get_reader();
        let masquerade = || Masquerade::new("masquerade", flow_table.clone(), reader.clone());
        let wire = Arc::new(Wire {
            epoch: AtomicU64::new(0),
            emissions: Mutex::new(Vec::new()),
        });

        let workers: Vec<_> = self
            .ops
            .iter()
            .map(|ops| {
                let mut masq = masquerade();
                let (ops, wire) = (ops.clone(), wire.clone());
                #[cfg(not(feature = "shuttle"))]
                let handle = runtime.handle().clone();
                thread::spawn(move || {
                    #[cfg(not(feature = "shuttle"))]
                    let _runtime = handle.enter();
                    work(&mut masq, &wire, &ops);
                })
            })
            .collect();

        for &update in &self.updates {
            let next = match update {
                Update::Publish(next) => next,
                Update::Unchanged => layout,
            };
            let invalidating = next.pool() != layout.pool();
            genid += 1;
            if invalidating {
                wire.bump();
            }
            writer.update_nat_allocator(next.masquerade_config(self.randomize), genid, &flow_table);
            if invalidating {
                wire.bump();
            }
            layout = next;
        }

        for worker in workers {
            worker
                .join()
                .unwrap_or_else(|_| panic!("a packet worker panicked"));
        }

        #[cfg(not(feature = "shuttle"))]
        let _runtime = runtime.enter();
        let mut live = BTreeSet::new();
        flow_table.for_each_flow(|key, flow| {
            if flow.status() != FlowStatus::Active {
                return;
            }
            assert_eq!(
                flow.genid(),
                genid,
                "flow {key} was left behind at generation {}",
                flow.genid()
            );
            // Reverse flows are keyed on the public tuple
            if key.src_vpcd() == Some(discriminant(REMOTE_VNI)) {
                let port = key.dst_port().map_or(0, NonZero::get);
                live.insert((key.dst_ip(), port));
            }
        });

        // New flows must not be given the tuple of a live flow
        let mut masq = masquerade();
        let mut fresh = BTreeMap::new();
        for tenant in &TENANTS {
            for host in 0..HOSTS {
                let packet = datagram(tenant, host, 0, SPORT + 1);
                let private = source_of(&packet);
                for out in masq
                    .process(std::iter::once(packet))
                    .filter(|p| !p.is_done())
                {
                    let public = source_of(&out);
                    assert!(
                        !live.contains(&public),
                        "{private:?} was given {public:?}, held by a live flow"
                    );
                    if let Some(other) = fresh.insert(public, private) {
                        panic!("{public:?} was given to both {other:?} and {private:?}");
                    }
                }
            }
        }
    }
}

#[concurrency::model_test]
fn masquerade_keeps_public_tuples_and_replies_apart_across_config_updates() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|scenario: Scenario| {
            concurrency::stress(move || {
                scenario.run();
            });
        });
}

#[concurrency::model_test]
fn flows_created_across_allocator_rebuilds_never_share_a_public_tuple() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|Rebuilds(scenario)| {
            concurrency::stress(move || {
                scenario.run();
            });
        });
}
