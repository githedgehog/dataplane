// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A gateway's state without a control plane: an overlay lowered into the tables the pipeline
//! reads, and an underlay of one uplink to one peer VTEP.
//!
//! The pipeline fuzz tests build their pipelines from this, and the loopback harness builds the
//! production pipeline from it, so both see the gateway the same way.

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use acl_filter::{AclFilterContext, AclFilterContextReaderFactory, AclFilterContextWriter};
use capture::CaptureController;
use concurrency::sync::Arc;
use config::external::GenId;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::LOCAL_VNI;
use flow_entry::flow_table::FlowTable;
use flow_filter::{FlowFilterContext, FlowFilterContextReaderFactory, FlowFilterContextWriter};
use lpm::prefix::Prefix;
use nat::masquerade::{MasqueradeConfig, NatAllocatorReaderFactory, NatAllocatorWriter};
use nat::migrate_tracked_flows;
use nat::portfw::{PortFwTableReaderFactory, PortFwTableWriter};
use nat::static_nat::invalidate_stale_static_nat_flows;
use nat::static_nat::setup::build_nat_configuration;
use nat::static_nat::{NatTablesReaderFactory, NatTablesWriter};
use net::buffer::TestBuffer;
use net::eth::mac::{Mac, SourceMac};
use net::interface::{InterfaceIndex, InterfaceName};
use net::ip::dscp::Dscp;
use net::ip::ecn::Ecn;
use net::packet::test_utils::{
    build_test_udp_ipv4_packet, build_test_vxlan_ipv4_packet_carrying_vni,
};
use net::packet::{Packet, PacketStats, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::PipelineData;
use rate_limit::{RateLimitWriter, RateLimits, VpcDestination};
use routing::testing::RouterTables;
use routing::testing::{FibGroup, FwAction, NhopKey, RouteOrigin};
use routing::{AtableReaderFactory, FibTableReaderFactory, IfTableReaderFactory};
use routing::{EgressObject, Encapsulation, FibEntry, PktInstruction, Vtep, VxlanEncapsulation};
use stats::{StatsCollector, VpcMapName, VpcStatsStore};
use vpcmap::map::VpcMapWriter;

use super::PipelineIngredients;

pub(crate) const FIRST_GENID: GenId = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Enact {
    FlowFilter,
    Acl,
    StaticNat,
    OpenGeneration,
    Masquerade,
    PortForward,
    FlowTracking,
    PublishGeneration,
    Everything,
}

/// The writers of an overlay's tables, which apply a configuration the way `mgmt` does.
pub(crate) struct Fleet {
    pub(super) flow_filter: FlowFilterContextWriter,
    pub(super) acl: AclFilterContextWriter,
    pub(super) static_nat: RefCell<NatTablesWriter>,
    pub(super) portfw: RefCell<PortFwTableWriter>,
    pub(super) masquerade: RefCell<NatAllocatorWriter>,
    pub(super) genid: Cell<GenId>,
    pub(super) randomize: Cell<bool>,
    pub(super) blueprint: Blueprint,
}

/// The readers of a [`Fleet`]'s tables, from which pipelines are built.
pub(crate) struct Blueprint {
    pub(super) flow_filter: FlowFilterContextReaderFactory,
    pub(super) acl: AclFilterContextReaderFactory,
    pub(super) static_nat: NatTablesReaderFactory,
    pub(super) portfw: PortFwTableReaderFactory,
    pub(super) masquerade: NatAllocatorReaderFactory,
    pub(super) pipeline: Arc<PipelineData>,
    pub(super) underlay: Option<Underlay>,
    pub(super) flow_table: Arc<FlowTable>,
    pub(super) declared: Arc<[DeclaredPool]>,
}

pub(crate) struct Underlay {
    pub(super) interfaces: IfTableReaderFactory,
    pub(super) fibs: FibTableReaderFactory,
    pub(super) adjacencies: AtableReaderFactory,
}

impl Fleet {
    pub(crate) fn lowering(
        overlay: &ValidatedOverlay,
        tables: Option<&RouterTables>,
        flow_table: Arc<FlowTable>,
    ) -> Self {
        let flow_filter = FlowFilterContextWriter::new();
        flow_filter.store(
            FlowFilterContext::try_from(overlay).expect("a validated overlay lowers to tables"),
        );

        let acl = AclFilterContextWriter::new();
        acl.store(AclFilterContext::try_from(overlay).expect("a validated overlay lowers to acls"));

        let mut static_nat = NatTablesWriter::new();
        static_nat.update_nat_tables(
            build_nat_configuration(overlay.vpc_table())
                .expect("a validated overlay lowers to nat"),
        );

        let mut portfw = PortFwTableWriter::new();
        portfw
            .update_from_vpc_table(overlay.vpc_table(), &flow_table, FIRST_GENID)
            .expect("a validated overlay lowers to port forwarding");

        let mut masquerade = NatAllocatorWriter::new();
        masquerade.update_nat_allocator(
            MasqueradeConfig::new(overlay.vpc_table()).set_randomize(false),
            FIRST_GENID,
            &flow_table,
        );

        let blueprint = Blueprint {
            flow_filter: flow_filter.get_reader_factory(),
            acl: acl.get_reader_factory(),
            static_nat: static_nat.get_reader_factory(),
            portfw: portfw.reader().factory(),
            masquerade: masquerade.get_reader_factory(),
            pipeline: Arc::new(PipelineData::new(FIRST_GENID)),
            underlay: tables.map(|tables| Underlay {
                interfaces: tables.interface_factory(),
                fibs: tables.fib_factory(),
                adjacencies: tables.adjacency_factory(),
            }),
            flow_table,
            declared: declared_pools(overlay),
        };

        Self {
            flow_filter,
            acl,
            static_nat: RefCell::new(static_nat),
            portfw: RefCell::new(portfw),
            masquerade: RefCell::new(masquerade),
            genid: Cell::new(FIRST_GENID),
            randomize: Cell::new(false),
            blueprint,
        }
    }

    pub(crate) fn reconfigure(&self, overlay: &ValidatedOverlay) {
        self.enact(overlay, Enact::Everything);
    }

    pub(crate) fn enact_with_router_gap(&self, overlay: &ValidatedOverlay, gap: Duration) {
        for step in [
            Enact::FlowFilter,
            Enact::Acl,
            Enact::StaticNat,
            Enact::OpenGeneration,
            Enact::Masquerade,
            Enact::PortForward,
            Enact::FlowTracking,
        ] {
            self.enact(overlay, step);
        }
        std::thread::sleep(gap);
        self.enact(overlay, Enact::PublishGeneration);
    }

    pub(crate) fn randomizing(&self, on: bool) -> &Self {
        self.randomize.set(on);
        self
    }

    pub(crate) fn enact(&self, overlay: &ValidatedOverlay, which: Enact) {
        let doing = |step: Enact| which == Enact::Everything || which == step;
        if doing(Enact::FlowFilter) {
            self.flow_filter.store(
                FlowFilterContext::try_from(overlay).expect("a validated overlay lowers to tables"),
            );
        }
        if doing(Enact::Acl) {
            self.acl.store(
                AclFilterContext::try_from(overlay).expect("a validated overlay lowers to acls"),
            );
        }
        if doing(Enact::StaticNat) {
            self.static_nat.borrow_mut().update_nat_tables(
                build_nat_configuration(overlay.vpc_table())
                    .expect("a validated overlay lowers to nat"),
            );
        }
        if doing(Enact::OpenGeneration) {
            self.genid.set(self.genid.get() + 1);
            // Match `mgmt`: open the generation before migration and publish it after apply.
            self.blueprint.pipeline.open_generation(self.genid.get());
        }
        if doing(Enact::Masquerade) {
            self.masquerade.borrow_mut().update_nat_allocator(
                MasqueradeConfig::new(overlay.vpc_table()).set_randomize(self.randomize.get()),
                self.genid.get(),
                &self.blueprint.flow_table,
            );
        }
        if doing(Enact::PortForward) {
            self.portfw
                .borrow_mut()
                .update_from_vpc_table(
                    overlay.vpc_table(),
                    &self.blueprint.flow_table,
                    self.genid.get(),
                )
                .expect("a validated overlay lowers to port forwarding");
        }
        if doing(Enact::FlowTracking) {
            let context = self.flow_filter.get_reader().load();
            let nat_tables_reader = self.static_nat.borrow().get_reader();
            let nat_tables = nat_tables_reader
                .enter()
                .expect("a writer can always read its own tables");
            migrate_tracked_flows(
                &self.blueprint.flow_table,
                &nat_tables,
                self.genid.get(),
                |flow| context.keeps_tracked_flow(flow),
            );
            invalidate_stale_static_nat_flows(&self.blueprint.flow_table, &nat_tables);
        }
        if doing(Enact::PublishGeneration) {
            self.blueprint.pipeline.set_genid(self.genid.get());
        }
    }

    pub(crate) fn blueprint(&self) -> &Blueprint {
        &self.blueprint
    }
}

/// An expose's private range and the public pool allowed to translate it.
///
/// Keep them paired so the check rejects translations into another tenant's pool.
pub(crate) struct DeclaredPool {
    pub(super) private: Vec<Prefix>,
    pub(super) public: Vec<Prefix>,
    /// Destination VPC. The same private range may use different pools for different peers.
    pub(super) towards: Option<VpcDiscriminant>,
}

impl DeclaredPool {
    /// Whether this expose allows the translation from `private` to `public` towards `towards`.
    /// If the flow filter has not assigned a destination, check only the address ranges.
    pub(super) fn admits(
        &self,
        private: IpAddr,
        public: IpAddr,
        towards: Option<VpcDiscriminant>,
    ) -> bool {
        (towards.is_none() || self.towards.is_none() || self.towards == towards)
            && self.private.iter().any(|p| p.covers_addr(&private))
            && self.public.iter().any(|p| p.covers_addr(&public))
    }
}

pub(super) fn declared_pools(overlay: &ValidatedOverlay) -> Arc<[DeclaredPool]> {
    fn prefixes<'a, S>(set: S) -> Vec<Prefix>
    where
        S: IntoIterator<Item = &'a lpm::prefix::PrefixWithOptionalPorts>,
    {
        set.into_iter()
            .map(lpm::prefix::PrefixWithOptionalPorts::prefix)
            .collect()
    }

    let discriminant = |name: &str| {
        overlay
            .vpc_table()
            .values()
            .find(|vpc| vpc.name() == name)
            .map(|vpc| VpcDiscriminant::VNI(vpc.vni()))
    };

    let mut declared = Vec::new();
    for vpc in overlay.vpc_table().values() {
        for peering in vpc.peerings() {
            let (local, remote) = (peering.local(), peering.remote());
            // Each manifest exposes addresses to the other manifest's VPC.
            for (mine, theirs) in [(local, remote), (remote, local)] {
                let towards = discriminant(theirs.name());
                for expose in mine.valexp() {
                    declared.push(DeclaredPool {
                        private: prefixes(expose.ips()),
                        public: prefixes(expose.public_ips()),
                        towards,
                    });
                }
            }
        }
    }
    declared.into()
}

/// The underlay: one uplink, this gateway's VTEP and one peer VTEP behind it.
pub(crate) const UPLINK: u32 = 1;
pub(crate) const LOCAL_VTEP: &str = "5.6.7.8";
pub(crate) const PEER_VTEP: &str = "1.2.3.4";
pub(crate) const GATEWAY_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0xaa]);
pub(crate) const PEER_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0xbb]);

pub(crate) const UNDERLAY_VRF: u32 = 0;

pub(crate) fn uplink() -> InterfaceIndex {
    InterfaceIndex::try_new(UPLINK).unwrap_or_else(|_| unreachable!())
}

/// Routing tables for the underlay, with `vnis` reachable through the peer VTEP.
pub(crate) fn topology(vnis: &[Vni]) -> RouterTables {
    let mut tables = RouterTables::new();

    tables.vrf(UNDERLAY_VRF, None);
    tables.interface(
        uplink(),
        InterfaceName::try_from("uplink").unwrap(),
        SourceMac::new(GATEWAY_MAC).unwrap_or_else(|_| unreachable!()),
    );
    tables.attach(uplink(), UNDERLAY_VRF);
    tables.route_via(
        UNDERLAY_VRF,
        Prefix::expect_from((LOCAL_VTEP, 32)),
        nhop(&LOCAL_VTEP.parse().unwrap_or_else(|_| unreachable!())),
        &FibGroup::with_entry(FibEntry::with_inst(PktInstruction::Local(uplink()))),
    );

    for reachable in vnis {
        tables.vrf(reachable.as_u32(), Some(*reachable));
        encapsulate_out_of(&mut tables, reachable.as_u32(), *reachable);
    }

    tables.adjacency(
        PEER_VTEP.parse().unwrap_or_else(|_| unreachable!()),
        uplink(),
        PEER_MAC,
    );

    tables
}

pub(crate) fn encapsulate_out_of(tables: &mut RouterTables, vrfid: u32, out_vni: Vni) {
    tables.vtep(
        vrfid,
        Vtep::new(
            LOCAL_VTEP.parse().unwrap_or_else(|_| unreachable!()),
            SourceMac::new(GATEWAY_MAC).unwrap_or_else(|_| unreachable!()),
        ),
    );
    let peer: IpAddr = PEER_VTEP.parse().unwrap_or_else(|_| unreachable!());
    let mut out = FibEntry::with_inst(PktInstruction::Encap(Encapsulation::Vxlan(
        VxlanEncapsulation {
            vni: out_vni,
            remote: peer,
            rmac: SourceMac::new(PEER_MAC).unwrap_or_else(|_| unreachable!()),
        },
    )));
    out.add(PktInstruction::Egress(EgressObject::new(
        Some(uplink()),
        Some(peer),
    )));
    tables.route_via(
        vrfid,
        Prefix::root_v4(),
        nhop(&peer),
        &FibGroup::with_entry(out),
    );
}

pub(crate) fn nhop(address: &IpAddr) -> NhopKey {
    NhopKey::new(
        0,
        RouteOrigin::default(),
        Some(*address),
        None,
        None,
        FwAction::Forward,
    )
}

pub(crate) fn vni(raw: u32) -> Vni {
    Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
}

/// One masquerading expose: the local VPC's 1.1.0.0/16 leaves as 2.2.0.0/16.
pub(crate) fn exposes() -> Vec<VpcExpose> {
    vec![
        VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("1.1.0.0/16".parse::<Prefix>().unwrap().into())
            .as_range("2.2.0.0/16".parse::<Prefix>().unwrap().into())
            .unwrap(),
    ]
}

/// `inner`, arriving from the peer VTEP in VPC `from` and addressed to this gateway.
pub(crate) fn tunnelled_from(from: Vni, inner: &Packet<TestBuffer>) -> Packet<TestBuffer> {
    // The gateway only accepts inner frames addressed to its vtep mac
    let mut inner = inner.deep_copy().unwrap();
    inner
        .set_eth_destination(GATEWAY_MAC)
        .expect("the inner frame has an ethernet header");
    let bytes = inner.serialize().expect("the inner frame serializes");
    let mut packet = build_test_vxlan_ipv4_packet_carrying_vni(
        from,
        Dscp::default(),
        Ecn::default(),
        bytes.as_ref(),
    )
    .expect("a well-formed tunnelled frame");
    packet
        .set_eth_destination(GATEWAY_MAC)
        .expect("the frame has an ethernet header");
    packet.meta_mut().iif = Some(uplink());
    packet
}

/// `inner`, arriving from the peer VTEP in the local VPC.
pub(crate) fn tunnelled(inner: &Packet<TestBuffer>) -> Packet<TestBuffer> {
    tunnelled_from(vni(LOCAL_VNI), inner)
}

/// The frame a delivered packet carries, if it was encapsulated.
pub(crate) fn inside(delivered: &Packet<TestBuffer>) -> Option<Packet<TestBuffer>> {
    let mut copy = delivered.deep_copy().unwrap();
    matches!(copy.vxlan_decap(), Some(Ok(_))).then_some(copy)
}

/// A UDP packet from the local VPC towards the remote one.
pub(crate) fn inner() -> Packet<TestBuffer> {
    build_test_udp_ipv4_packet("1.1.0.1", "3.3.3.1", 1234, 80)
}

/// The writers and collectors that must outlive the readers in a fixture gateway's
/// [`PipelineIngredients`].
pub(crate) struct Upkeep {
    _rate_limits: RateLimitWriter<VpcDestination>,
    _stats: StatsCollector,
    _vpcs: VpcMapWriter<VpcMapName>,
}

impl Fleet {
    /// What the production pipeline needs to run this fleet's overlay over `tables`, for
    /// `workers` workers.
    ///
    /// The pipeline is the one `start_router` assembles, stage for stage; only where its tables
    /// come from differs. No rate limits are set and nothing reads the statistics it sends.
    pub(crate) fn ingredients(
        &self,
        tables: &RouterTables,
        workers: NonZeroUsize,
    ) -> (PipelineIngredients, Upkeep) {
        let vpcs = VpcMapWriter::<VpcMapName>::new();
        let (stats, stats_w, _) =
            StatsCollector::new_with_store(vpcs.get_reader(), VpcStatsStore::new());
        let rate_limits = RateLimitWriter::new(RateLimits::empty(), workers);
        let pipeline = PipelineIngredients {
            pdata: self.blueprint.pipeline.clone(),
            iftr_factory: tables.interface_factory(),
            fibtr_factory: tables.fib_factory(),
            atabler_factory: tables.adjacency_factory(),
            nattabler_factory: self.static_nat.borrow().get_reader_factory(),
            natallocator_factory: self.masquerade.borrow().get_reader_factory(),
            flow_filter_reader_factory: self.flow_filter.get_reader_factory(),
            aclfiltertablesr_factory: self.acl.get_reader_factory(),
            rate_limits: rate_limits.reader(),
            portfw_factory: self.portfw.borrow().reader().factory(),
            stats_w,
            pkt_stats: Arc::new(PacketStats::new()),
            flow_table: self.blueprint.flow_table.clone(),
            capture: CaptureController::new(),
        };
        let upkeep = Upkeep {
            _rate_limits: rate_limits,
            _stats: stats,
            _vpcs: vpcs,
        };
        (pipeline, upkeep)
    }
}
