// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packets driven through the overlay pipeline, against a generated configuration.
//!
//! The per-network-function harnesses -- `nat::{static_nat,masquerade,portfw}::probe`,
//! `acl_filter::nf_fuzz`, `flow_filter`'s adversarial stacks -- each configure one stage and feed
//! it packets. They are what says a stage does its own job. What none of them can say is what
//! happens when the stages are put in a row, and that is where the defects have actually been:
//!
//! - the IPv6 extension-header ACL bypass needed a packet shape the ACL's own generator never
//!   produced, because the shape was legal and the *reading* of it was wrong;
//! - the VLAN passthrough needed decapsulation, a filter and egress in the same test, because no
//!   single stage was doing anything wrong -- the tag simply survived all of them.
//!
//! Both are interaction bugs. A single-stage harness cannot see one by construction.
//!
//! # What this covers, and what it does not
//!
//! The stages here are the overlay slice of the production pipeline, in production order:
//! `IcmpErrorHandler`, `FlowLookup`, `FlowFilter`, `AclFilter`, `StaticNat`, `PortForwarder`,
//! `Masquerade`. See `start_router` in the parent module for the whole list.
//!
//! `Ingress`, the two `IpForwarder` stages and `Egress` are **not** here. They need an interface
//! table, a FIB table and an adjacency table, and `routing::testing` exposes a `FibWriter` but not
//! the table readers those stages take. Closing that is the next step, and it matters: the VLAN
//! refusal lives in `IpForwarder` and has no test here for exactly this reason.
//!
//! # What the properties here do and do not catch
//!
//! Break-tested rather than assumed:
//!
//! - Removing the line in `flow_entry`'s `FlowLookup` that attaches flow state fails
//!   `a_translated_flow_comes_back_to_where_it_started`. That is the claim this harness exists to
//!   make: a one-line change in a different crate, in a stage that decides nothing by itself, is
//!   caught because five stages have to agree for a flow to come back.
//! - Reverting the `acl_filter` extension-header fix fails
//!   `the_acl_verdict_follows_the_protocol_the_packet_carries`. That is the bypass itself, caught
//!   at the altitude it lived at: a rule naming TCP, a TCP packet behind an extension header, and
//!   a filter reading the protocol out of a field that names the extension.
//!
//! `every_shape_leaves_the_pipeline_with_a_verdict` is deliberately weak: it says a verdict was
//! reached and attributed, not that it was right. It catches a lost packet, a panic, and a packet
//! forwarded with nobody having chosen where it goes. It would not have caught either of the two
//! defects above, and saying so is the point -- a liveness property that looks like a correctness
//! property is worse than no property.
//!
//! # The classifier is the production one
//!
//! `FlowFilterContext::try_from` and `AclFilterContext::try_from` build `rte_acl` tables, so these
//! tests need the EAL. That is deliberate. The reference backends exist to be a fast oracle for
//! the crates that own them; an end-to-end harness that used them would be testing a classifier
//! that never ships.

#![cfg(test)]
#![cfg(not(miri))]

use acl_filter::{AclFilter, AclFilterContext, AclFilterContextWriter};
use concurrency::sync::Arc;
use config::external::overlay::acl::Acl;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::{
    LOCAL_VNI, REMOTE_VNI, overlay_with_exposes_and_acl,
};
use flow_entry::flow_table::{FlowLookup, FlowTable};
use flow_filter::{FlowFilter, FlowFilterContext, FlowFilterContextWriter};
use nat::masquerade::{MasqueradeConfig, NatAllocatorWriter};
use nat::portfw::{PortForwarder, PortFwTableWriter};
use nat::static_nat::NatTablesWriter;
use nat::static_nat::setup::build_nat_configuration;
use nat::{IcmpErrorHandler, Masquerade, StaticNat};
use net::buffer::TestBuffer;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::{DynPipeline, NetworkFunction};
use std::net::IpAddr;

/// A configured overlay pipeline, and the handles that keep its tables alive.
///
/// Every writer is held for the fabric's lifetime: dropping one tears down the data it published,
/// so a fabric that let a writer go would be a pipeline whose configuration silently emptied.
pub(crate) struct Fabric {
    pipeline: DynPipeline<TestBuffer>,
    _flow_table: Arc<FlowTable>,
    _flow_filter: FlowFilterContextWriter,
    _acl: AclFilterContextWriter,
    _static_nat: NatTablesWriter,
    _portfw: PortFwTableWriter,
    _masquerade: NatAllocatorWriter,
}

impl Fabric {
    /// Build the overlay pipeline for a set of exposes, or `None` if they do not form a valid
    /// configuration.
    ///
    /// A rejection here is not a finding: two generated exposes may legitimately overlap, and the
    /// generator does not try to avoid it. What would be a finding is a configuration that
    /// validates and then cannot be lowered into tables, so that step is an `expect` rather than a
    /// `?`.
    pub(crate) fn build(exposes: &[VpcExpose]) -> Option<Self> {
        Self::build_with_acl(exposes, None)
    }

    /// As [`Self::build`], with an ACL on the peering.
    pub(crate) fn build_with_acl(exposes: &[VpcExpose], acl: Option<&Acl>) -> Option<Self> {
        let overlay = overlay_with_exposes_and_acl(exposes.to_vec(), acl)
            .ok()?
            .validate()
            .ok()?;

        let flow_table = Arc::new(FlowTable::default());
        let mut pipeline = DynPipeline::new();

        pipeline = pipeline.add_stage(IcmpErrorHandler::new(flow_table.clone()));
        pipeline = pipeline.add_stage(FlowLookup::new("flow-lookup", flow_table.clone()));

        let flow_filter = FlowFilterContextWriter::new();
        flow_filter.store(
            FlowFilterContext::try_from(&overlay).expect("a validated overlay lowers to tables"),
        );
        pipeline = pipeline.add_stage(FlowFilter::new("flow-filter", flow_filter.get_reader()));

        let acl = AclFilterContextWriter::new();
        acl.store(
            AclFilterContext::try_from(&overlay).expect("a validated overlay lowers to acls"),
        );
        pipeline = pipeline.add_stage(AclFilter::new("acl-filter", acl.get_reader()));

        let mut static_nat = NatTablesWriter::new();
        static_nat.update_nat_tables(
            build_nat_configuration(overlay.vpc_table())
                .expect("a validated overlay lowers to nat"),
        );
        pipeline = pipeline.add_stage(StaticNat::with_reader(
            "static-nat",
            static_nat.get_reader(),
        ));

        let mut portfw = PortFwTableWriter::new();
        portfw
            .update_from_vpc_table(overlay.vpc_table())
            .expect("a validated overlay lowers to port forwarding");
        pipeline = pipeline.add_stage(PortForwarder::new(
            "port-forwarder",
            portfw.reader(),
            flow_table.clone(),
        ));

        let mut masquerade = NatAllocatorWriter::new();
        // Randomised port selection would make two runs of one configuration disagree on every
        // flow, which is legitimate behaviour and useless to compare.
        masquerade.update_nat_allocator(
            MasqueradeConfig::new(overlay.vpc_table()).set_randomize(false),
            1,
            &flow_table,
        );
        pipeline = pipeline.add_stage(Masquerade::new(
            "masquerade",
            flow_table.clone(),
            masquerade.get_reader(),
        ));

        Some(Self {
            pipeline,
            _flow_table: flow_table,
            _flow_filter: flow_filter,
            _acl: acl,
            _static_nat: static_nat,
            _portfw: portfw,
            _masquerade: masquerade,
        })
    }

    /// Send one packet through, and hand back what came out.
    ///
    /// A stage may drop a packet but must not lose it: `enforce` keeps a done packet so the reason
    /// can be read, and a pipeline that returned nothing would be a packet that vanished. That is
    /// asserted here rather than in a property, because every property depends on it.
    pub(crate) fn send(&mut self, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        let mut out: Vec<_> = self.pipeline.process(std::iter::once(packet)).collect();
        assert_eq!(out.len(), 1, "the pipeline did not return the packet");
        out.pop().unwrap_or_else(|| unreachable!())
    }
}

/// The VPC a packet enters from.
pub(crate) fn local() -> VpcDiscriminant {
    VpcDiscriminant::VNI(Vni::new_checked(LOCAL_VNI).unwrap_or_else(|_| unreachable!()))
}

/// The VPC on the far side of the peering.
pub(crate) fn remote() -> VpcDiscriminant {
    VpcDiscriminant::VNI(Vni::new_checked(REMOTE_VNI).unwrap_or_else(|_| unreachable!()))
}

/// Stamp a packet as an overlay arrival from `src`, the way `IpForwarder` does after decapsulation.
///
/// `dst_vpcd` is deliberately left unset: the flow filter is what decides it, and setting it here
/// would skip the stage under test. See the note in `nat::masquerade::probe` -- an arrival is not
/// always a single stamp, and getting it wrong makes a harness lie.
pub(crate) fn arrive(packet: &mut Packet<TestBuffer>, src: VpcDiscriminant) {
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = Some(src);
    // Keep a dropped packet rather than letting `enforce` swallow it, so a verdict can be read.
    packet.meta_mut().set_keep(true);
}

/// What the pipeline did with a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Forwarded, with the VPC the flow filter chose.
    Forwarded {
        dst_vpcd: Option<VpcDiscriminant>,
        src: Option<IpAddr>,
        dst: Option<IpAddr>,
    },
    /// Dropped, with the reason the stage that dropped it gave.
    Dropped(DoneReason),
}

pub(crate) fn verdict(packet: &Packet<TestBuffer>) -> Verdict {
    match packet.get_done() {
        Some(reason) => Verdict::Dropped(reason),
        None => Verdict::Forwarded {
            dst_vpcd: packet.meta().dst_vpcd,
            src: packet.ip_source(),
            dst: packet.ip_destination(),
        },
    }
}

#[cfg(test)]
mod smoke {
    use super::*;
    use lpm::prefix::Prefix;
    use net::packet::test_utils::build_test_udp_ipv4_packet;

    fn masquerade_expose() -> VpcExpose {
        VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("1.1.0.0/16".parse::<Prefix>().unwrap().into())
            .as_range("2.2.0.0/16".parse::<Prefix>().unwrap().into())
            .unwrap()
    }

    /// The harness wires a pipeline that behaves like the one in `start_router`.
    ///
    /// Not a property: it is the fixture for the properties, and a fixture that quietly stopped
    /// translating would make every property below vacuously true. Asserting the translation here
    /// is what stops that.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn the_harness_builds_a_pipeline_that_translates() {
        let mut fabric = Fabric::build(&[masquerade_expose()]).expect("a valid configuration");

        let mut packet = build_test_udp_ipv4_packet("1.1.0.1", "3.3.3.1", 1234, 80);
        arrive(&mut packet, local());
        let out = fabric.send(packet);

        match verdict(&out) {
            Verdict::Forwarded { dst_vpcd, src, dst } => {
                assert_eq!(dst_vpcd, Some(remote()), "the flow filter chose no peer");
                let IpAddr::V4(src) = src.expect("no source") else {
                    panic!("came out IPv6")
                };
                assert_eq!(src.octets()[..2], [2, 2], "not masqueraded into the range");
                assert_eq!(dst, Some("3.3.3.1".parse().unwrap()));
            }
            Verdict::Dropped(reason) => panic!("the packet was dropped: {reason:?}"),
        }
    }
}

/// Header shapes fed through the whole pipeline.
///
/// Deliberately not "arbitrary bytes". The interesting shapes are the ones that parse into
/// something legal and unusual -- a tag, an extension header chain, a transport nobody has a
/// parser for -- because those are what a stage reaches into and reads wrong. Random bytes mostly
/// fail to parse and never reach a stage at all.
#[cfg(test)]
mod shapes {
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use config::external::overlay::vpcpeering::contract::MasqueradeExposes;
    use lpm::prefix::Prefix;
    use net::headers::builder::ChainBase;
    use net::headers::{Headers, TryIpv4Mut, TryIpv6Mut};
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::parse::DeParse;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MAX_EXPOSES: u8 = 2;

    /// The shapes generated, named so coverage can be required for each.
    ///
    /// `Vlan*` and `*Ext*` are the two that motivated this harness: both were legal, both were
    /// read wrong, and neither was reachable from a single stage's own generator.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Shape {
        V4Tcp,
        V4Udp,
        V4Icmp,
        VlanV4Tcp,
        V4ExoticProto,
        V6Tcp,
        V6HopByHopTcp,
        V6FragmentUdp,
        NoIp,
    }

    impl Shape {
        const ALL: [Shape; 9] = [
            Shape::V4Tcp,
            Shape::V4Udp,
            Shape::V4Icmp,
            Shape::VlanV4Tcp,
            Shape::V4ExoticProto,
            Shape::V6Tcp,
            Shape::V6HopByHopTcp,
            Shape::V6FragmentUdp,
            Shape::NoIp,
        ];
    }

    /// How many stacks share one built pipeline.
    ///
    /// Building one costs an `rte_acl` table compile, which dwarfs the cost of pushing a packet
    /// through it -- a fabric per stack spends the whole budget on configuration. A batch also
    /// buys something the single-packet form cannot: the stages share a flow table, so later
    /// packets meet the state earlier ones created, which is the pipeline's actual behaviour.
    const STACKS_PER_FABRIC: usize = 16;

    struct AnyStack;

    impl ValueGenerator for AnyStack {
        type Output = (Shape, Headers);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<(Shape, Headers)> {
            let shape = Shape::ALL[usize::from(driver.produce::<u8>()?) % Shape::ALL.len()];
            let headers = match shape {
                Shape::NoIp => ChainBase::new().eth(|_| {}).generate(driver),
                Shape::V4Tcp => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                Shape::V4Udp => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .udp(|_| {})
                    .generate(driver),
                Shape::V4Icmp => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .icmp4(|_| {})
                    .generate(driver),
                Shape::VlanV4Tcp => ChainBase::new()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                // A protocol number with no transport parser: the chain ends at the IP header.
                Shape::V4ExoticProto => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.set_next_header(net::ip::NextHeader::new(132));
                    })
                    .generate(driver),
                Shape::V6Tcp => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                Shape::V6HopByHopTcp => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .hop_by_hop(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                Shape::V6FragmentUdp => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .fragment(|_| {})
                    .udp(|_| {})
                    .generate(driver),
            }?;
            Some((shape, headers))
        }
    }

    /// One configuration and the stacks to run against it.
    struct Batch;

    impl ValueGenerator for Batch {
        type Output = (Vec<VpcExpose>, Vec<(Shape, Headers)>);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let exposes = MasqueradeExposes(MAX_EXPOSES).generate(driver)?;
            let mut stacks = Vec::with_capacity(STACKS_PER_FABRIC);
            for _ in 0..STACKS_PER_FABRIC {
                stacks.push(AnyStack.generate(driver)?);
            }
            Some((exposes, stacks))
        }
    }

    /// Point a generated stack at the configuration, so it has a chance of being forwarded.
    ///
    /// Addresses drawn independently of the overlay miss every table, and a property driven by one
    /// explores the miss path and nothing else -- the argument `nat::static_nat::probe` makes about
    /// packets, applied to whole stacks.
    fn aim(headers: &mut Headers, private: Option<Prefix>) {
        let Some(private) = private else { return };
        match private.as_address() {
            IpAddr::V4(addr) => {
                if let Some(ip) = headers.try_ipv4_mut() {
                    ip.set_source(
                        UnicastIpv4Addr::new(addr).unwrap_or_else(|_| unreachable!("prefix base")),
                    );
                    ip.set_destination(
                        "3.3.3.1"
                            .parse::<Ipv4Addr>()
                            .unwrap_or_else(|_| unreachable!()),
                    );
                }
            }
            IpAddr::V6(addr) => {
                if let Some(ip) = headers.try_ipv6_mut() {
                    ip.set_source(
                        UnicastIpv6Addr::new(addr).unwrap_or_else(|_| unreachable!("prefix base")),
                    );
                    ip.set_destination(
                        "2001:db8:ffff::1"
                            .parse::<Ipv6Addr>()
                            .unwrap_or_else(|_| unreachable!()),
                    );
                }
            }
        }
    }

    fn wire(headers: &Headers) -> Option<Packet<TestBuffer>> {
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).ok()?;
        Packet::new(buffer).ok()
    }

    /// Every packet leaves the pipeline with a verdict, whatever shape it arrived in.
    ///
    /// The weakest thing worth saying end to end, and the one both of this week's defects would
    /// have failed differently: a forwarded packet must have been given a destination VPC by the
    /// flow filter, and a dropped one must carry the reason of whichever stage refused it. A stage
    /// that reaches into a chain it did not account for produces neither -- it produces a packet
    /// forwarded on the strength of fields somebody read out of the wrong place.
    ///
    /// It does not say the verdict is *right*; the oracle for that is the next property. It says
    /// that one was reached, by a stage that meant to reach it.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn every_shape_leaves_the_pipeline_with_a_verdict() {
        static FORWARDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DROPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static BY_SHAPE: LazyLock<[AtomicU64; Shape::ALL.len()]> =
            LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));

        bolero::check!()
            .with_generator(Batch)
            .for_each(|(exposes, stacks)| {
                // The pipeline holds rte_acl tables and a flow table, neither of which is safe to
                // carry across bolero's unwind boundary; build one per batch.
                let Some(mut fabric) = Fabric::build(exposes) else {
                    return;
                };
                let private = exposes.first().and_then(|e| {
                    e.ips
                        .first()
                        .map(lpm::prefix::PrefixWithOptionalPorts::prefix)
                });

                for (shape, headers) in stacks {
                    let mut headers = headers.clone();
                    aim(&mut headers, private);
                    let Some(mut packet) = wire(&headers) else {
                        continue;
                    };
                    BY_SHAPE[*shape as usize].fetch_add(1, Ordering::Relaxed);

                    arrive(&mut packet, local());
                    let out = fabric.send(packet);

                    match verdict(&out) {
                        Verdict::Forwarded { dst_vpcd, .. } => {
                            assert_eq!(
                                dst_vpcd,
                                Some(remote()),
                                "forwarded without a destination VPC, on a {shape:?} stack: \
                                 nothing chose where this packet goes"
                            );
                            FORWARDED.fetch_add(1, Ordering::Relaxed);
                        }
                        Verdict::Dropped(_) => {
                            DROPPED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });

        let forwarded = FORWARDED.load(Ordering::Relaxed);
        let dropped = DROPPED.load(Ordering::Relaxed);
        let by_shape: Vec<_> = Shape::ALL
            .iter()
            .map(|s| format!("{s:?}={}", BY_SHAPE[*s as usize].load(Ordering::Relaxed)))
            .collect();
        eprintln!(
            "forwarded={forwarded} dropped={dropped}; {}",
            by_shape.join(" ")
        );

        assert!(
            forwarded > 0,
            "no packet was ever forwarded: the harness is exercising the drop path only"
        );
        assert!(dropped > 0, "no packet was ever dropped");
        for shape in Shape::ALL {
            assert!(
                BY_SHAPE[shape as usize].load(Ordering::Relaxed) > 0,
                "no {shape:?} packet ever reached the pipeline"
            );
        }
    }
}

/// Flows driven out and back through the whole pipeline.
///
/// The shape property above says a verdict was reached. This says the verdict was *right*, using
/// the only end-to-end oracle that does not restate the code: a translation the pipeline applied
/// on the way out has to be undone on the way back, by a different path through the same stages.
/// Nothing in the harness computes what the translation should be -- it is read off the outgoing
/// packet and required to reverse.
#[cfg(test)]
mod round_trip {
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use config::external::overlay::vpcpeering::contract::MasqueradeExposes;
    use lpm::prefix::{Prefix, PrefixWithOptionalPorts};
    use net::headers::builder::HeaderStack;
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::parse::DeParse;
    use net::udp::UdpPort;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MAX_EXPOSES: u8 = 2;
    const FLOWS_PER_FABRIC: usize = 8;

    /// A flow to try: which private prefix it comes from, and the ports it uses.
    #[derive(Debug, Clone, Copy)]
    struct FlowSpec {
        prefix: u8,
        host: u8,
        sport: u16,
        dport: u16,
    }

    struct Batch;

    impl ValueGenerator for Batch {
        type Output = (Vec<VpcExpose>, Vec<FlowSpec>);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let exposes = MasqueradeExposes(MAX_EXPOSES).generate(driver)?;
            let mut flows = Vec::with_capacity(FLOWS_PER_FABRIC);
            for _ in 0..FLOWS_PER_FABRIC {
                flows.push(FlowSpec {
                    prefix: driver.produce()?,
                    host: driver.produce()?,
                    // Port 0 is not a port; masquerade would refuse it for reasons that have
                    // nothing to do with whether a translation reverses.
                    sport: driver.produce::<u16>()?.max(1),
                    dport: driver.produce::<u16>()?.max(1),
                });
            }
            Some((exposes, flows))
        }
    }

    /// The private addresses a configuration exposes, one per prefix.
    ///
    /// One address per prefix rather than every address: masquerade puts many private addresses
    /// behind few public ones, so the prefixes are large and enumerating them buys no new
    /// behaviour. What matters is that distinct sources contend for the same public range.
    fn private_addresses(exposes: &[VpcExpose]) -> Vec<Prefix> {
        exposes
            .iter()
            .flat_map(|e| e.ips.iter().map(PrefixWithOptionalPorts::prefix))
            .collect()
    }

    /// The far side of the peering, which `overlay_with_exposes` fixes by address family.
    fn peer(family_of: IpAddr) -> IpAddr {
        match family_of {
            IpAddr::V4(_) => IpAddr::V4(
                "3.3.3.1"
                    .parse::<Ipv4Addr>()
                    .unwrap_or_else(|_| unreachable!()),
            ),
            IpAddr::V6(_) => IpAddr::V6(
                "2001:db8:ffff::1"
                    .parse::<Ipv6Addr>()
                    .unwrap_or_else(|_| unreachable!()),
            ),
        }
    }

    fn udp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16) -> Option<Packet<TestBuffer>> {
        // Validated out here: the header-stack closures cannot fail, so anything that can reject
        // an input has to reject it before the stack is built.
        let sport = UdpPort::new_checked(sport).ok()?;
        let dport = UdpPort::new_checked(dport).ok()?;
        let headers = match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let src = UnicastIpv4Addr::new(src).ok()?;
                HeaderStack::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.set_source(src);
                        ip.set_destination(dst);
                    })
                    .udp(|udp| {
                        udp.set_source(sport);
                        udp.set_destination(dport);
                    })
                    .build_headers()
                    .ok()?
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let src = UnicastIpv6Addr::new(src).ok()?;
                HeaderStack::new()
                    .eth(|_| {})
                    .ipv6(|ip| {
                        ip.set_source(src);
                        ip.set_destination(dst);
                    })
                    .udp(|udp| {
                        udp.set_source(sport);
                        udp.set_destination(dport);
                    })
                    .build_headers()
                    .ok()?
            }
            _ => return None,
        };
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).ok()?;
        Packet::new(buffer).ok()
    }

    /// A translation applied on the way out is undone on the way back.
    ///
    /// The reply is built from what came out, not from what went in: its source is the peer the
    /// request reached, its destination the public tuple the request was given. That is the packet
    /// the far side would actually send, and nothing in this test knows what the public tuple
    /// should have been -- only that whatever it was has to reverse.
    ///
    /// Five stages have to agree for this to hold: the flow filter has to find the peering in both
    /// directions, the flow table has to still hold the state masquerade created, and masquerade
    /// has to invert its own allocation. A single-stage harness can check the last of those and
    /// none of the rest.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_translated_flow_comes_back_to_where_it_started() {
        static ROUND_TRIPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static NOT_FORWARDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_generator(Batch)
            .for_each(|(exposes, flows)| {
                let Some(mut fabric) = Fabric::build(exposes) else {
                    return;
                };
                let privates = private_addresses(exposes);
                if privates.is_empty() {
                    return;
                }

                for flow in flows {
                    let prefix = privates[usize::from(flow.prefix) % privates.len()];
                    // The prefix base plus a small offset, so several flows share a prefix and
                    // contend for the same public range.
                    let src = match prefix.as_address() {
                        IpAddr::V4(a) => {
                            let mut o = a.octets();
                            o[3] = o[3].wrapping_add(flow.host % 8);
                            IpAddr::V4(Ipv4Addr::from(o))
                        }
                        IpAddr::V6(a) => {
                            let mut o = a.octets();
                            o[15] = o[15].wrapping_add(flow.host % 8);
                            IpAddr::V6(Ipv6Addr::from(o))
                        }
                    };
                    let dst = peer(src);

                    let Some(mut request) = udp(src, dst, flow.sport, flow.dport) else {
                        continue;
                    };
                    arrive(&mut request, local());
                    let out = fabric.send(request);

                    let Verdict::Forwarded {
                        src: public_src,
                        dst: reached,
                        ..
                    } = verdict(&out)
                    else {
                        NOT_FORWARDED.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let (Some(public_src), Some(reached)) = (public_src, reached) else {
                        continue;
                    };
                    let public_port = out
                        .transport_src_port()
                        .unwrap_or_else(|| unreachable!("a udp packet has a source port"))
                        .get();

                    // The reply the far side would send, addressed to what it actually saw.
                    let Some(mut reply) = udp(reached, public_src, flow.dport, public_port) else {
                        continue;
                    };
                    arrive(&mut reply, remote());
                    let back = fabric.send(reply);

                    match verdict(&back) {
                        Verdict::Forwarded { src: s, dst: d, .. } => {
                            assert_eq!(
                                d,
                                Some(src),
                                "the reply did not come back to the host that sent the request"
                            );
                            assert_eq!(s, Some(dst), "the reply's source was rewritten");
                            assert_eq!(
                                back.transport_dst_port().map(std::num::NonZero::get),
                                Some(flow.sport),
                                "the reply did not get the original source port back"
                            );
                            ROUND_TRIPPED.fetch_add(1, Ordering::Relaxed);
                        }
                        Verdict::Dropped(reason) => panic!(
                            "the reply of a forwarded flow was dropped: {reason:?} \
                             (request {src} -> {dst} became {public_src}:{public_port})"
                        ),
                    }
                }
            });

        let round_tripped = ROUND_TRIPPED.load(Ordering::Relaxed);
        eprintln!(
            "round-tripped={round_tripped} not-forwarded={}",
            NOT_FORWARDED.load(Ordering::Relaxed)
        );
        assert!(
            round_tripped > 0,
            "no flow was ever forwarded, so nothing was ever checked to come back"
        );
    }
}

/// ACL verdicts, read at the end of the pipeline rather than at the filter.
///
/// The configuration is shaped so its answer is knowable without evaluating it: one rule, matching
/// all of the peering's traffic in the request direction, discriminating only on protocol. The
/// oracle is then "does this packet's protocol match the rule's", and the packet's protocol is
/// known because the test built it -- not read back through the accessor the filter uses.
///
/// That narrowness is the point. The extension-header bypass was a stage reading the protocol out
/// of a field that names something else, and no property whose oracle asks the same accessor the
/// same question can see it.
#[cfg(test)]
mod acl {
    use super::*;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use config::external::overlay::acl::{AclAction, AclProtoMatch};
    use config::external::overlay::vpcpeering::contract::{MasqueradeExposes, peering_acl};
    use lpm::prefix::{Prefix, PrefixWithOptionalPorts};
    use net::headers::builder::ChainBase;
    use net::headers::{Headers, TryIpv4Mut, TryIpv6Mut};
    use net::ip::NextHeader;
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::parse::DeParse;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MAX_EXPOSES: u8 = 2;
    const PACKETS_PER_FABRIC: usize = 12;

    /// What the packet actually carries, and how it is wrapped.
    ///
    /// `behind_extension` is the whole reason this property exists: the protocol is the same, the
    /// rule's answer must be the same, and the field a careless reader would look at is different.
    #[derive(Debug, Clone, Copy, TypeGenerator)]
    struct PacketSpec {
        proto: Proto,
        behind_extension: bool,
        host: u8,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, TypeGenerator)]
    enum Proto {
        Tcp,
        Udp,
        Icmp,
    }

    impl Proto {
        /// The rule shape that names this protocol.
        fn as_match(self) -> AclProtoMatch {
            match self {
                Proto::Tcp => AclProtoMatch::Tcp,
                Proto::Udp => AclProtoMatch::Udp,
                // ICMP is not a first-class variant; it is matched by number, and the number
                // differs by address family.
                Proto::Icmp => AclProtoMatch::Other(NextHeader::ICMP.as_u8()),
            }
        }
    }

    /// Which protocol the generated rule names.
    #[derive(Debug, Clone, Copy, TypeGenerator)]
    enum RuleProto {
        Tcp,
        Udp,
        Icmp,
        Icmp6,
        Any,
    }

    impl RuleProto {
        fn as_match(self) -> AclProtoMatch {
            match self {
                RuleProto::Tcp => AclProtoMatch::Tcp,
                RuleProto::Udp => AclProtoMatch::Udp,
                RuleProto::Icmp => AclProtoMatch::Other(NextHeader::ICMP.as_u8()),
                RuleProto::Icmp6 => AclProtoMatch::Other(NextHeader::ICMP6.as_u8()),
                RuleProto::Any => AclProtoMatch::Any,
            }
        }
    }

    struct Batch;

    impl ValueGenerator for Batch {
        type Output = (Vec<VpcExpose>, bool, RuleProto, Vec<(PacketSpec, Headers)>);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let exposes = MasqueradeExposes(MAX_EXPOSES).generate(driver)?;
            // The packets have to be the family the exposes are, or they miss every table and the
            // ACL is never consulted.
            let v6 = exposes
                .first()
                .and_then(|e| e.ips.first())
                .is_some_and(|p| p.prefix().as_address().is_ipv6());
            let default_allow = driver.produce()?;
            let rule_proto = RuleProto::generate(driver)?;
            let mut packets = Vec::with_capacity(PACKETS_PER_FABRIC);
            for _ in 0..PACKETS_PER_FABRIC {
                let spec = PacketSpec::generate(driver)?;
                packets.push((spec, stack(driver, spec, v6)?));
            }
            Some((exposes, default_allow, rule_proto, packets))
        }
    }

    /// The protocol number a packet of this spec carries, in this address family.
    fn carried(proto: Proto, v6: bool) -> AclProtoMatch {
        match (proto, v6) {
            (Proto::Icmp, true) => AclProtoMatch::Other(NextHeader::ICMP6.as_u8()),
            (p, _) => p.as_match(),
        }
    }

    /// Whether the generated rule matches a packet carrying `carried`.
    fn rule_matches(rule: AclProtoMatch, carried: AclProtoMatch) -> bool {
        matches!(rule, AclProtoMatch::Any) || rule == carried
    }

    /// Build a header stack carrying `proto`, optionally behind an extension header.
    ///
    /// Done in the generator because that is where a driver exists; the address family is decided
    /// here too, since an IPv4 chain and an IPv6 chain are different types.
    fn stack<D: Driver>(driver: &mut D, spec: PacketSpec, v6: bool) -> Option<Headers> {
        if v6 {
            let chain = ChainBase::new().eth(|_| {}).ipv6(|_| {});
            if spec.behind_extension {
                let chain = chain.hop_by_hop(|_| {});
                match spec.proto {
                    Proto::Tcp => chain.tcp(|_| {}).generate(driver),
                    Proto::Udp => chain.udp(|_| {}).generate(driver),
                    Proto::Icmp => chain.icmp6(|_| {}).generate(driver),
                }
            } else {
                match spec.proto {
                    Proto::Tcp => chain.tcp(|_| {}).generate(driver),
                    Proto::Udp => chain.udp(|_| {}).generate(driver),
                    Proto::Icmp => chain.icmp6(|_| {}).generate(driver),
                }
            }
        } else {
            let chain = ChainBase::new().eth(|_| {}).ipv4(|_| {});
            if spec.behind_extension {
                // RFC 4302 Authentication Header: an IPv4 packet whose protocol field names the
                // extension rather than the transport, which is the v4 shape of the bug.
                let chain = chain.ipv4_auth(|_| {});
                match spec.proto {
                    Proto::Tcp => chain.tcp(|_| {}).generate(driver),
                    Proto::Udp => chain.udp(|_| {}).generate(driver),
                    Proto::Icmp => chain.icmp4(|_| {}).generate(driver),
                }
            } else {
                match spec.proto {
                    Proto::Tcp => chain.tcp(|_| {}).generate(driver),
                    Proto::Udp => chain.udp(|_| {}).generate(driver),
                    Proto::Icmp => chain.icmp4(|_| {}).generate(driver),
                }
            }
        }
    }

    fn wire(
        headers: &Headers,
        spec: PacketSpec,
        src: IpAddr,
        dst: IpAddr,
    ) -> Option<Packet<TestBuffer>> {
        let mut headers = headers.clone();
        aim(&mut headers, src, dst, spec.host);
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).ok()?;
        Packet::new(buffer).ok()
    }

    fn aim(headers: &mut Headers, src: IpAddr, dst: IpAddr, host: u8) {
        match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                if let Some(ip) = headers.try_ipv4_mut() {
                    let mut o = src.octets();
                    o[3] = o[3].wrapping_add(host % 8);
                    if let Ok(src) = UnicastIpv4Addr::new(Ipv4Addr::from(o)) {
                        ip.set_source(src);
                    }
                    ip.set_destination(dst);
                }
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                if let Some(ip) = headers.try_ipv6_mut() {
                    let mut o = src.octets();
                    o[15] = o[15].wrapping_add(host % 8);
                    if let Ok(src) = UnicastIpv6Addr::new(Ipv6Addr::from(o)) {
                        ip.set_source(src);
                    }
                    ip.set_destination(dst);
                }
            }
            _ => {}
        }
    }

    fn peer(family_of: IpAddr) -> IpAddr {
        match family_of {
            IpAddr::V4(_) => IpAddr::V4(
                "3.3.3.1"
                    .parse::<Ipv4Addr>()
                    .unwrap_or_else(|_| unreachable!()),
            ),
            IpAddr::V6(_) => IpAddr::V6(
                "2001:db8:ffff::1"
                    .parse::<Ipv6Addr>()
                    .unwrap_or_else(|_| unreachable!()),
            ),
        }
    }

    /// A packet the ACL denies never leaves, and one it permits is never dropped by the ACL.
    ///
    /// Two one-way claims rather than "forwarded iff permitted", because the ACL is not the only
    /// stage with an opinion and the ones ahead of it are allowed to have theirs. A generated
    /// ICMP error whose embedded packet does not parse is refused by `IcmpErrorHandler` before the
    /// ACL is consulted; a permitted packet can still fail to find a translation. Neither is the
    /// ACL letting something through.
    ///
    /// So: the deny direction is stated as "not forwarded", which is what a bypass violates, and
    /// the permit direction as "not `AclDropped`", which is what an over-strict filter violates.
    /// The counters below then have to show that some denial actually came *from* the ACL --
    /// otherwise a pipeline that dropped everything early would satisfy the deny direction
    /// vacuously.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn the_acl_verdict_follows_the_protocol_the_packet_carries() {
        static DENIED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PERMITTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static BEHIND_EXT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PERMITTED_OUT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DENIED_BY_ACL: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!().with_generator(Batch).for_each(
            |(exposes, default_allow, rule_proto, packets)| {
                let default = if *default_allow {
                    AclAction::Allow
                } else {
                    AclAction::Deny
                };
                let rule = rule_proto.as_match();
                let Some(mut fabric) =
                    Fabric::build_with_acl(exposes, Some(&peering_acl(default, rule)))
                else {
                    return;
                };
                let Some(private) = exposes
                    .iter()
                    .flat_map(|e| e.ips.iter().map(PrefixWithOptionalPorts::prefix))
                    .next()
                    .map(|p: Prefix| p.as_address())
                else {
                    return;
                };
                let v6 = private.is_ipv6();
                let dst = peer(private);

                for (spec, headers) in packets {
                    let Some(mut packet) = wire(headers, *spec, private, dst) else {
                        continue;
                    };
                    arrive(&mut packet, local());
                    let out = fabric.send(packet);

                    let permitted = rule_matches(rule, carried(spec.proto, v6)) != *default_allow;
                    if spec.behind_extension {
                        BEHIND_EXT.fetch_add(1, Ordering::Relaxed);
                    }

                    let seen = verdict(&out);
                    let acl_dropped = seen == Verdict::Dropped(DoneReason::AclDropped);
                    let forwarded = matches!(seen, Verdict::Forwarded { .. });
                    if permitted {
                        assert!(
                            !acl_dropped,
                            "the acl dropped a {:?} packet it permits (rule={rule:?} \
                             default={default:?} behind_extension={})",
                            spec.proto, spec.behind_extension
                        );
                        PERMITTED.fetch_add(1, Ordering::Relaxed);
                        if forwarded {
                            PERMITTED_OUT.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        assert!(
                            !forwarded,
                            "a {:?} packet the acl denies was forwarded (rule={rule:?} \
                             default={default:?} behind_extension={})",
                            spec.proto, spec.behind_extension
                        );
                        DENIED.fetch_add(1, Ordering::Relaxed);
                        if acl_dropped {
                            DENIED_BY_ACL.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            },
        );

        let (permitted, permitted_out, denied, denied_by_acl, behind) = (
            PERMITTED.load(Ordering::Relaxed),
            PERMITTED_OUT.load(Ordering::Relaxed),
            DENIED.load(Ordering::Relaxed),
            DENIED_BY_ACL.load(Ordering::Relaxed),
            BEHIND_EXT.load(Ordering::Relaxed),
        );
        eprintln!(
            "permitted={permitted} (forwarded {permitted_out}) denied={denied} \
             (by the acl {denied_by_acl}) behind-extension={behind}"
        );
        assert!(permitted > 0, "no packet was ever permitted");
        assert!(denied > 0, "no packet was ever denied");
        assert!(
            permitted_out > 0,
            "no permitted packet was ever forwarded: the permit direction is vacuous"
        );
        assert!(
            denied_by_acl > 0,
            "no denial ever came from the acl: the deny direction is being satisfied by stages \
             ahead of it, and would hold with the acl removed"
        );
        assert!(
            behind > 0,
            "no packet was ever sent behind an extension header, which is the shape this exists for"
        );
    }
}
