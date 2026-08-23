// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]
#![cfg(not(miri))]

use acl_filter::{
    AclFilter, AclFilterContext, AclFilterContextReaderFactory, AclFilterContextWriter,
};
use concurrency::sync::{Arc, Mutex};
use config::external::overlay::acl::Acl;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::{
    LOCAL_VNI, REMOTE_VNI, overlay_with_exposes_and_acl,
};
use config::external::overlay::{Overlay, ValidatedOverlay};
use flow_entry::flow_table::{FlowLookup, FlowTable};
use flow_filter::{
    FlowFilter, FlowFilterContext, FlowFilterContextReaderFactory, FlowFilterContextWriter,
};
use lpm::prefix::Prefix;
use nat::masquerade::{MasqueradeConfig, NatAllocatorReaderFactory, NatAllocatorWriter};
use nat::portfw::{PortForwarder, PortFwTableReaderFactory, PortFwTableWriter};
use nat::static_nat::setup::build_nat_configuration;
use nat::static_nat::{NatTablesReaderFactory, NatTablesWriter};
use nat::{IcmpErrorHandler, Masquerade, StaticNat};
use net::buffer::{PacketBufferMut, TestBuffer};
use net::eth::mac::{Mac, SourceMac};
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::{DynPipeline, NetworkFunction};
use routing::testing::RouterTables;
use routing::testing::{FibGroup, FwAction, NhopKey, RouteOrigin};
use routing::{AtableReaderFactory, FibTableReaderFactory, IfTableReaderFactory};
use routing::{EgressObject, FibEntry, PktInstruction, ResolvedEncapsulation, ResolvedVxlan, Vtep};
use std::net::IpAddr;

use super::egress::Egress;
use super::ingress::Ingress;
use super::ipforward::IpForwarder;

pub(crate) struct Fleet {
    _flow_filter: FlowFilterContextWriter,
    _acl: AclFilterContextWriter,
    _static_nat: NatTablesWriter,
    _portfw: PortFwTableWriter,
    _masquerade: NatAllocatorWriter,
    blueprint: Blueprint,
}

pub(crate) struct Blueprint {
    flow_filter: FlowFilterContextReaderFactory,
    acl: AclFilterContextReaderFactory,
    static_nat: NatTablesReaderFactory,
    portfw: PortFwTableReaderFactory,
    masquerade: NatAllocatorReaderFactory,
    underlay: Option<Underlay>,
    flow_table: Arc<FlowTable>,
    declared: Arc<[Prefix]>,
}

struct Underlay {
    interfaces: IfTableReaderFactory,
    fibs: FibTableReaderFactory,
    adjacencies: AtableReaderFactory,
}

pub(crate) struct Worker {
    pipeline: DynPipeline<TestBuffer>,
    translations: Arc<Mutex<Translations>>,
    next_id: u64,
}

pub(crate) struct Fabric {
    _tables: Option<RouterTables>,
    fleet: Fleet,
    worker: Worker,
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
            .update_from_vpc_table(overlay.vpc_table())
            .expect("a validated overlay lowers to port forwarding");

        let mut masquerade = NatAllocatorWriter::new();
        masquerade.update_nat_allocator(
            MasqueradeConfig::new(overlay.vpc_table()).set_randomize(false),
            1,
            &flow_table,
        );

        let blueprint = Blueprint {
            flow_filter: flow_filter.get_reader_factory(),
            acl: acl.get_reader_factory(),
            static_nat: static_nat.get_reader_factory(),
            portfw: portfw.reader().factory(),
            masquerade: masquerade.get_reader_factory(),
            underlay: tables.map(|tables| Underlay {
                interfaces: tables.interface_factory(),
                fibs: tables.fib_factory(),
                adjacencies: tables.adjacency_factory(),
            }),
            flow_table,
            declared: declared_public_ranges(overlay),
        };

        Self {
            _flow_filter: flow_filter,
            _acl: acl,
            _static_nat: static_nat,
            _portfw: portfw,
            _masquerade: masquerade,
            blueprint,
        }
    }

    pub(crate) fn blueprint(&self) -> &Blueprint {
        &self.blueprint
    }
}

impl Blueprint {
    pub(crate) fn worker(&self) -> Worker {
        let translations = Arc::new(Mutex::new(Translations::declaring(&self.declared)));
        let mut pipeline = DynPipeline::new();

        if let Some(underlay) = &self.underlay {
            pipeline = pipeline.add_stage(Ingress::new("ingress", underlay.interfaces.handle()));
            pipeline = pipeline.add_stage(IpForwarder::new("ip-forward-1", underlay.fibs.handle()));
            pipeline = pipeline.add_stage(Checkpoint::new(
                "after ip-forward-1",
                contract::decapsulated,
            ));
        }

        pipeline = pipeline.add_stage(IcmpErrorHandler::new(self.flow_table.clone()));
        pipeline = pipeline.add_stage(FlowLookup::new("flow-lookup", self.flow_table.clone()));
        pipeline = pipeline.add_stage(FlowFilter::new("flow-filter", self.flow_filter.handle()));
        pipeline = pipeline.add_stage(Checkpoint::new("after flow-filter", contract::placed));
        pipeline = pipeline.add_stage(AclFilter::new("acl-filter", self.acl.handle()));
        pipeline = pipeline.add_stage(StaticNat::with_reader(
            "static-nat",
            self.static_nat.handle(),
        ));
        pipeline = pipeline.add_stage(PortForwarder::new(
            "port-forwarder",
            self.portfw.handle(),
            self.flow_table.clone(),
        ));

        pipeline = pipeline.add_stage(Checkpoint::new(
            "before masquerade",
            contract::ready_to_translate,
        ));
        let recording = translations.clone();
        pipeline = pipeline.add_stage(Checkpoint::new(
            "before masquerade",
            move |_: &str, packet: &Packet<TestBuffer>| {
                recording.lock().before(packet);
            },
        ));
        pipeline = pipeline.add_stage(Masquerade::new(
            "masquerade",
            self.flow_table.clone(),
            self.masquerade.handle(),
        ));

        let checking = translations.clone();
        pipeline = pipeline.add_stage(Checkpoint::new(
            "after masquerade",
            move |at: &str, packet: &Packet<TestBuffer>| {
                checking.lock().after(at, packet);
            },
        ));

        if let Some(underlay) = &self.underlay {
            pipeline = pipeline.add_stage(IpForwarder::new("ip-forward-2", underlay.fibs.handle()));
            pipeline = pipeline.add_stage(Egress::new(
                "egress",
                underlay.interfaces.handle(),
                underlay.adjacencies.handle(),
            ));
            pipeline = pipeline.add_stage(Checkpoint::new("after egress", contract::finished));
        }

        Worker {
            pipeline,
            translations,
            next_id: 0,
        }
    }
}

impl Worker {
    pub(crate) fn send(&mut self, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        let mut out = self.send_batch(vec![packet]);
        assert_eq!(out.len(), 1, "the pipeline did not return the packet");
        out.pop().unwrap_or_else(|| unreachable!())
    }

    pub(crate) fn send_batch(
        &mut self,
        mut packets: Vec<Packet<TestBuffer>>,
    ) -> Vec<Packet<TestBuffer>> {
        let sent = packets.len();
        for packet in &mut packets {
            self.next_id += 1;
            packet.meta_mut().test = Some(Box::new(net::packet::TestMeta { id: self.next_id }));
        }
        self.translations.lock().clear();

        let out: Vec<_> = self.pipeline.process(packets.into_iter()).collect();
        assert_eq!(out.len(), sent, "the pipeline did not return every packet");
        out
    }
}

impl Fabric {
    pub(crate) fn build(exposes: &[VpcExpose]) -> Option<Self> {
        Self::build_with_acl(exposes, None)
    }

    pub(crate) fn build_with_acl(exposes: &[VpcExpose], acl: Option<&Acl>) -> Option<Self> {
        Self::assemble(exposes, acl, None)
    }

    pub(crate) fn routed(exposes: &[VpcExpose], acl: Option<&Acl>) -> Option<Self> {
        Self::routed_sharing(exposes, acl, Arc::new(FlowTable::default()))
    }

    pub(crate) fn routed_sharing(
        exposes: &[VpcExpose],
        acl: Option<&Acl>,
        flow_table: Arc<FlowTable>,
    ) -> Option<Self> {
        let overlay = overlay_with_exposes_and_acl(exposes.to_vec(), acl)
            .ok()?
            .validate()
            .ok()?;
        Some(Self::over(
            &overlay,
            Some(topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)])),
            flow_table,
        ))
    }

    pub(crate) fn routed_over(overlay: &Overlay, tables: RouterTables) -> Option<Self> {
        Some(Self::over(
            &overlay.clone().validate().ok()?,
            Some(tables),
            Arc::new(FlowTable::default()),
        ))
    }

    pub(crate) fn routed_over_validated(overlay: &ValidatedOverlay, tables: RouterTables) -> Self {
        Self::over(overlay, Some(tables), Arc::new(FlowTable::default()))
    }

    fn assemble(
        exposes: &[VpcExpose],
        acl: Option<&Acl>,
        tables: Option<RouterTables>,
    ) -> Option<Self> {
        let overlay = overlay_with_exposes_and_acl(exposes.to_vec(), acl)
            .ok()?
            .validate()
            .ok()?;
        Some(Self::over(&overlay, tables, Arc::new(FlowTable::default())))
    }

    fn over(
        overlay: &ValidatedOverlay,
        tables: Option<RouterTables>,
        flow_table: Arc<FlowTable>,
    ) -> Self {
        let fleet = Fleet::lowering(overlay, tables.as_ref(), flow_table);
        let worker = fleet.blueprint().worker();
        Self {
            _tables: tables,
            fleet,
            worker,
        }
    }

    pub(crate) fn send(&mut self, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        self.worker.send(packet)
    }

    pub(crate) fn send_batch(
        &mut self,
        packets: Vec<Packet<TestBuffer>>,
    ) -> Vec<Packet<TestBuffer>> {
        self.worker.send_batch(packets)
    }

    pub(crate) fn worker(&mut self) -> &mut Worker {
        &mut self.worker
    }

    pub(crate) fn flows(&self) -> Option<usize> {
        self.fleet.blueprint().flow_table.len()
    }
}

pub(crate) fn local() -> VpcDiscriminant {
    VpcDiscriminant::VNI(Vni::new_checked(LOCAL_VNI).unwrap_or_else(|_| unreachable!()))
}

pub(crate) fn remote() -> VpcDiscriminant {
    VpcDiscriminant::VNI(Vni::new_checked(REMOTE_VNI).unwrap_or_else(|_| unreachable!()))
}

pub(crate) fn arrive(packet: &mut Packet<TestBuffer>, src: VpcDiscriminant) {
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = Some(src);
    packet.meta_mut().set_keep(true);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Forwarded {
        dst_vpcd: Option<VpcDiscriminant>,
        src: Option<IpAddr>,
        dst: Option<IpAddr>,
    },
    Delivered {
        oif: Option<InterfaceIndex>,
        src: Option<IpAddr>,
        dst: Option<IpAddr>,
    },
    Dropped(DoneReason),
}

pub(crate) fn verdict(packet: &Packet<TestBuffer>) -> Verdict {
    match packet.get_done() {
        Some(DoneReason::Delivered) => Verdict::Delivered {
            oif: packet.meta().oif,
            src: packet.ip_source(),
            dst: packet.ip_destination(),
        },
        Some(reason) => Verdict::Dropped(reason),
        None => Verdict::Forwarded {
            dst_vpcd: packet.meta().dst_vpcd,
            src: packet.ip_source(),
            dst: packet.ip_destination(),
        },
    }
}

pub(crate) const MAX_INPUT_LEN: usize = 65536;

#[cfg(test)]
fn largest_draw<G: bolero::ValueGenerator>(generator: &G) -> usize {
    use bolero::generator::bolero_generator::driver::{Options, bytes::Driver};

    const SAMPLES: usize = 64;
    const UNLIMITED: usize = 1 << 20;

    let options = Options::default().with_max_len(UNLIMITED);
    let mut state: u64 = 0x243f_6a88_85a3_08d3;
    let mut bytes = vec![0u8; UNLIMITED];
    (0..SAMPLES)
        .map(|_| {
            for byte in &mut bytes {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                #[allow(clippy::cast_possible_truncation)]
                {
                    *byte = (state >> 33) as u8;
                }
            }
            let mut driver = Driver::new(&bytes[..], &options);
            assert!(
                generator.generate(&mut driver).is_some(),
                "the generator gave up on a budget it cannot exhaust"
            );
            UNLIMITED - driver.as_slice().len()
        })
        .max()
        .unwrap_or_else(|| unreachable!("SAMPLES is not zero"))
}

#[cfg(test)]
fn assert_within_budget<G: bolero::ValueGenerator>(name: &str, generator: &G) {
    let largest = largest_draw(generator);
    eprintln!("{name}: largest draw {largest} of {MAX_INPUT_LEN} bytes");
    assert!(
        largest * 2 <= MAX_INPUT_LEN,
        "{name} drew {largest} bytes, over half of the {MAX_INPUT_LEN} budget. Raise \
         MAX_INPUT_LEN and `just fuzz`'s `-l`, or the tail of every batch will be zeros."
    );
}

#[cfg(test)]
fn assert_covered(covered: bool, what: &str) {
    assert!(
        covered,
        "{what}. Check for a `__fuzz__` corpus beside this test before reading further: replaying \
         one can spend the budget on inputs chosen for being unusual. Move it aside and re-run to \
         tell that apart from a real gap."
    );
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct Translations {
    was: std::collections::HashMap<u64, net::FlowKey>,
    from: std::collections::HashMap<u64, IpAddr>,
    given: std::collections::HashMap<net::FlowKey, (IpAddr, u16)>,
    declared: Arc<[Prefix]>,
}

#[cfg(test)]
impl Translations {
    fn before<Buf: PacketBufferMut>(&mut self, packet: &Packet<Buf>) {
        if packet.is_done() || !packet.meta().requires_masquerade() {
            return;
        }
        let (Some(test), Ok(key)) = (packet.meta().test.as_ref(), net::FlowKey::try_from(packet))
        else {
            return;
        };
        self.was.insert(test.id, key);
        if let Some(source) = packet.ip_source() {
            self.from.insert(test.id, source);
        }
    }

    fn after<Buf: PacketBufferMut>(&mut self, at: &str, packet: &Packet<Buf>) {
        if packet.is_done() {
            return;
        }
        let Some(test) = packet.meta().test.as_ref() else {
            return;
        };
        let Some(was) = self.was.get(&test.id).copied() else {
            return;
        };
        let (Some(source), Some(port)) = (packet.ip_source(), packet.transport_src_port()) else {
            return;
        };
        let now = (source, port.get());
        if let Some(before) = self.given.insert(was, now) {
            assert_eq!(
                before, now,
                "{at}: two packets of one flow in one burst were given different public tuples, \
                 so the burst allocated more than once for it"
            );
        }

        if self
            .from
            .get(&test.id)
            .is_some_and(|before| *before != source)
        {
            assert!(
                self.declared.iter().any(|p| p.covers_addr(&source)),
                "{at}: masquerade rewrote a source to {source}, which no declared public range \
                 covers"
            );
        }
    }

    fn clear(&mut self) {
        self.was.clear();
        self.from.clear();
        self.given.clear();
    }

    fn declaring(declared: &Arc<[Prefix]>) -> Self {
        Self {
            declared: declared.clone(),
            ..Self::default()
        }
    }
}

#[cfg(test)]
fn declared_public_ranges(overlay: &ValidatedOverlay) -> Arc<[Prefix]> {
    let mut declared = Vec::new();
    for vpc in overlay.vpc_table().values() {
        for peering in vpc.peerings() {
            for manifest in [peering.local(), peering.remote()] {
                for expose in manifest.valexp() {
                    declared.extend(
                        expose
                            .public_ips()
                            .into_iter()
                            .map(lpm::prefix::PrefixWithOptionalPorts::prefix),
                    );
                }
            }
        }
    }
    declared.into()
}

#[cfg(test)]
pub(crate) trait Load {
    fn next(&mut self) -> Option<Packet<TestBuffer>>;

    fn observe(&mut self, got: &Packet<TestBuffer>);

    fn finished(&self) -> bool;

    fn checked(&self) -> bool;

    fn describe(&self) -> String;
}

#[cfg(test)]
pub(crate) fn drive(worker: &mut Worker, load: &mut dyn Load) {
    for _ in 0..64 {
        if load.finished() {
            return;
        }
        let Some(packet) = load.next() else {
            panic!(
                "a load is neither finished nor willing to send: {}",
                load.describe()
            );
        };
        let out = worker.send(packet);
        load.observe(&out);
    }
    panic!("a load did not finish in 64 steps: {}", load.describe());
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pick {
    pub(crate) load: u8,
    pub(crate) take: u8,
}

#[cfg(test)]
pub(crate) type Poll = Vec<Pick>;

#[cfg(test)]
pub(crate) fn run_schedule(
    worker: &mut Worker,
    loads: &mut [Box<dyn Load>],
    schedule: &[Poll],
) -> Vec<Vec<usize>> {
    let mut bursts = Vec::new();
    for poll in schedule {
        let mut burst = Vec::new();
        let mut origin = Vec::new();
        for pick in poll {
            if loads.is_empty() {
                break;
            }
            let which = usize::from(pick.load) % loads.len();
            for _ in 0..pick.take {
                let Some(packet) = loads[which].next() else {
                    break;
                };
                burst.push(packet);
                origin.push(which);
            }
        }
        if burst.is_empty() {
            continue;
        }
        for (answer, which) in worker.send_batch(burst).iter().zip(&origin) {
            loads[*which].observe(answer);
        }
        bursts.push(origin);
    }

    for load in loads {
        drive(worker, load.as_mut());
    }
    bursts
}

#[cfg(test)]
pub(crate) mod derive {
    use super::routed::{Blast, Conversation, Inbound};
    use super::*;
    use config::external::overlay::ValidatedOverlay;
    use config::external::overlay::vpcpeering::ValidatedExpose;
    use lpm::prefix::{Prefix, PrefixWithOptionalPorts};

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Vary {
        pub(crate) host: u8,
        pub(crate) port: u8,
        pub(crate) sport: u16,
        pub(crate) dport: u16,
        pub(crate) burst: u8,
        pub(crate) blast: bool,
    }

    fn host_in(prefix: Prefix, n: u8) -> Option<IpAddr> {
        let full = if matches!(prefix.as_address(), IpAddr::V4(_)) {
            32
        } else {
            128
        };
        let width = u32::from(full - prefix.length());
        if width == 0 {
            return Some(prefix.as_address());
        }
        let span = 1u128.checked_shl(width.min(7))?;
        let offset = u128::from(n) % span;
        match prefix.as_address() {
            IpAddr::V4(base) => {
                let raw = u32::from(base).checked_add(u32::try_from(offset).ok()?)?;
                Some(IpAddr::V4(raw.into()))
            }
            IpAddr::V6(base) => {
                let raw = u128::from(base).checked_add(offset)?;
                Some(IpAddr::V6(raw.into()))
            }
        }
    }

    fn port_in(entry: &PrefixWithOptionalPorts, n: u8, fallback: u16) -> u16 {
        entry.ports().map_or(fallback.max(1), |range| {
            let span = u32::from(range.end()) - u32::from(range.start()) + 1;
            let offset = u32::from(n) % span;
            u16::try_from(u32::from(range.start()) + offset).unwrap_or(range.start())
        })
    }

    fn peer_of(
        peering: &config::external::overlay::vpc::ValidatedPeering,
        n: u8,
        usable: fn(&ValidatedExpose) -> bool,
    ) -> Option<IpAddr> {
        peering
            .remote()
            .valexp()
            .iter()
            .filter(|expose| usable(expose))
            .flat_map(|expose| expose.public_ips().into_iter())
            .find_map(|entry| host_in(entry.prefix(), n))
    }

    pub(crate) fn loads_for(overlay: &ValidatedOverlay, vary: &[Vary]) -> Vec<Box<dyn Load>> {
        let mut loads: Vec<Box<dyn Load>> = Vec::new();
        let mut nth = 0usize;
        for vpc in overlay.vpc_table().values() {
            for peering in vpc.peerings() {
                let path = super::routed::Path::new(vpc.vni(), peering.remote_vni());
                for expose in peering.local().valexp() {
                    let Some(v) = vary.get(nth % vary.len().max(1)).copied() else {
                        continue;
                    };
                    nth += 1;
                    let outward = peer_of(peering, v.host, |expose| {
                        expose.can_receive_connection() && !expose.has_port_forwarding()
                    });
                    let inward = peer_of(peering, v.host, ValidatedExpose::can_init_connection);

                    if expose.has_port_forwarding() {
                        let (Some(outside), Some(inside_entry)) = (
                            expose.public_ips().into_iter().next(),
                            expose.ips().into_iter().next(),
                        ) else {
                            continue;
                        };
                        let (Some(external), Some(internal)) = (
                            host_in(outside.prefix(), v.host),
                            host_in(inside_entry.prefix(), v.host),
                        ) else {
                            continue;
                        };
                        let Some(peer) = inward else {
                            continue;
                        };
                        loads.push(Box::new(Inbound::new(
                            path,
                            peer,
                            external,
                            port_in(outside, v.port, v.dport),
                            internal,
                            port_in(inside_entry, v.port, v.dport),
                            v.sport,
                        )));
                    } else if expose.has_static_nat() || expose.is_default() {
                    } else {
                        let (Some(peer), Some(src)) = (
                            outward,
                            expose
                                .ips()
                                .into_iter()
                                .next()
                                .and_then(|entry| host_in(entry.prefix(), v.host)),
                        ) else {
                            continue;
                        };
                        loads.push(if v.blast {
                            Box::new(Blast::new(path, src, peer, v.sport, v.dport, v.burst))
                        } else {
                            Box::new(Conversation::new(path, src, peer, v.sport, v.dport))
                                as Box<dyn Load>
                        });
                    }
                }
            }
        }
        loads
    }
}

pub(crate) struct Checkpoint<F> {
    at: &'static str,
    check: F,
}

impl<F> Checkpoint<F> {
    pub(crate) fn new(at: &'static str, check: F) -> Self {
        Self { at, check }
    }
}

impl<Buf: PacketBufferMut, F: Fn(&str, &Packet<Buf>) + 'static> NetworkFunction<Buf>
    for Checkpoint<F>
{
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.inspect(move |packet| (self.check)(self.at, packet))
    }
}

mod contract {
    use super::*;
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};

    pub(super) static JUDGED: LazyLock<[AtomicU64; 4]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));

    pub(super) const DECAPSULATED: usize = 0;
    pub(super) const PLACED: usize = 1;
    pub(super) const READY: usize = 2;
    pub(super) const FINISHED: usize = 3;

    fn judged(which: usize) {
        JUDGED[which].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn decapsulated<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        if packet.is_done() || !packet.meta().is_overlay() {
            return;
        }
        judged(DECAPSULATED);
        assert!(
            packet.meta().src_vpcd.is_some(),
            "{at}: overlay traffic with no source vpc discriminant"
        );
        assert!(
            packet.meta().vrf.is_some(),
            "{at}: overlay traffic with no vrf to route it in"
        );
    }

    pub(super) fn placed<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        if packet.is_done() || !packet.meta().is_overlay() {
            return;
        }
        judged(PLACED);
        assert!(
            packet.meta().dst_vpcd.is_some(),
            "{at}: forwarded without a destination vpc: nothing chose where this packet goes"
        );
    }

    pub(super) fn ready_to_translate<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        if packet.is_done() || !packet.meta().requires_masquerade() {
            return;
        }
        judged(READY);
        assert!(
            packet.meta().src_vpcd.is_some() && packet.meta().dst_vpcd.is_some(),
            "{at}: a packet is to be masqueraded without both discriminants, which masquerade \
             itself calls a bug"
        );
    }

    pub(super) fn finished<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        judged(FINISHED);
        assert!(
            packet.is_done(),
            "{at}: a packet left the last stage of the pipeline without a verdict"
        );
    }
}

pub(crate) const UPLINK: u32 = 1;
pub(crate) const LOCAL_VTEP: &str = "5.6.7.8";
pub(crate) const PEER_VTEP: &str = "1.2.3.4";
pub(crate) const GATEWAY_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0xaa]);
pub(crate) const PEER_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0xbb]);

const UNDERLAY_VRF: u32 = 0;

pub(crate) fn uplink() -> InterfaceIndex {
    InterfaceIndex::try_new(UPLINK).unwrap_or_else(|_| unreachable!())
}

pub(crate) fn topology(vnis: &[Vni]) -> RouterTables {
    let mut tables = RouterTables::new();

    tables.vrf(UNDERLAY_VRF, None);
    tables.interface(
        uplink(),
        "uplink",
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

fn encapsulate_out_of(tables: &mut RouterTables, vrfid: u32, out_vni: Vni) {
    tables.vtep(
        vrfid,
        Vtep::with_ip_and_mac(
            LOCAL_VTEP.parse().unwrap_or_else(|_| unreachable!()),
            GATEWAY_MAC,
        ),
    );
    let peer: IpAddr = PEER_VTEP.parse().unwrap_or_else(|_| unreachable!());
    let mut out = FibEntry::with_inst(PktInstruction::Encap(ResolvedEncapsulation::Vxlan(
        ResolvedVxlan {
            vni: out_vni,
            remote: peer,
            dmac: PEER_MAC,
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

fn nhop(address: &IpAddr) -> NhopKey {
    NhopKey::new(
        RouteOrigin::default(),
        Some(*address),
        None,
        None,
        FwAction::Forward,
    )
}

fn vni(raw: u32) -> Vni {
    Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
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

    #[tokio::test]
    #[dpdk::with_eal]
    async fn every_contract_is_reached() {
        use net::packet::test_utils::build_test_udp_ipv4_packet;

        let before: Vec<u64> = contract::JUDGED
            .iter()
            .map(|c| c.load(concurrency::sync::atomic::Ordering::Relaxed))
            .collect();

        let mut fabric = Fabric::routed(&routed::exposes(), None).expect("a valid configuration");
        let inner = build_test_udp_ipv4_packet("1.1.0.1", "3.3.3.1", 1234, 80);
        let out = fabric.send(routed::tunnelled(&inner));
        assert!(
            matches!(verdict(&out), Verdict::Delivered { .. }),
            "the fixture packet did not reach the wire: {:?}",
            verdict(&out)
        );

        for (i, name) in ["decapsulated", "placed", "ready_to_translate", "finished"]
            .iter()
            .enumerate()
        {
            let after = contract::JUDGED[i].load(concurrency::sync::atomic::Ordering::Relaxed);
            assert!(
                after > before[i],
                "the `{name}` contract judged no packet of an ordinary delivered flow: its guard \
                 excuses everything, so it holds without ever having been evaluated"
            );
        }
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn the_same_input_twice_gives_the_same_answer() {
        let scenario = || {
            let mut flows: Vec<_> = (0..12u8)
                .flat_map(|host| (0..3u16).map(move |round| (host, round)))
                .filter_map(|(host, round)| {
                    let src: IpAddr = format!("1.1.0.{host}").parse().ok()?;
                    let dst: IpAddr = "3.3.3.1".parse().ok()?;
                    round_trip::udp(src, dst, 4000 + round, 80).map(|p| routed::tunnelled(&p))
                })
                .collect();
            flows.extend((0..8u8).filter_map(|h| {
                let src: IpAddr = format!("1.1.9.{h}").parse().ok()?;
                let dst: IpAddr = "3.3.3.1".parse().ok()?;
                round_trip::udp(src, dst, 5000, 80).map(|p| routed::tunnelled(&p))
            }));
            flows
        };

        let answers = |fabric: &mut Fabric| {
            let mut seen = Vec::new();
            let packets = scenario();
            let (singly, burst) = packets.split_at(packets.len() - 8);
            for packet in singly.iter().cloned() {
                let out = fabric.send(packet);
                seen.push(describe(&out));
            }
            for out in fabric.send_batch(burst.to_vec()) {
                seen.push(describe(&out));
            }
            seen
        };

        let mut once = Fabric::routed(&routed::exposes(), None).expect("a valid configuration");
        let mut again = Fabric::routed(&routed::exposes(), None).expect("a valid configuration");
        let first = answers(&mut once);
        let second = answers(&mut again);

        assert!(
            first.iter().any(|a| a.contains("Delivered")),
            "the scenario delivered nothing, so this compares two pipelines doing nothing"
        );
        assert_eq!(
            first, second,
            "two runs of one scenario disagreed: replay-based diagnosis cannot be trusted, and \
             neither can bolero's shrinking"
        );
    }

    fn describe(packet: &Packet<TestBuffer>) -> String {
        let carried = routed::inside(packet);
        format!(
            "{:?} {:?} {:?} {:?}",
            verdict(packet),
            carried.as_ref().and_then(Packet::ip_source),
            carried.as_ref().and_then(Packet::ip_destination),
            carried.as_ref().and_then(Packet::transport_src_port),
        )
    }

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
            Verdict::Delivered { .. } => {
                unreachable!("the overlay slice has no egress stage")
            }
        }
    }
}

#[cfg(test)]
mod shapes {
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use config::external::overlay::vpcpeering::contract::MasqueradeExposes;
    use lpm::prefix::Prefix;
    use net::headers::builder::ChainBase;
    use net::headers::{Headers, TryIpv4Mut, TryIpv6Mut};
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::parse::DeParse;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const MAX_EXPOSES: u8 = 2;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Shape {
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
        pub(super) const ALL: [Shape; 9] = [
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

    pub(super) struct Batch;

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

    pub(super) fn aim(headers: &mut Headers, private: Option<Prefix>) {
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

    pub(super) fn wire(headers: &Headers) -> Option<Packet<TestBuffer>> {
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).ok()?;
        Packet::new(buffer).ok()
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("shapes::Batch", &Batch);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn every_shape_leaves_the_pipeline_with_a_verdict() {
        static FORWARDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DROPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static BY_SHAPE: LazyLock<[AtomicU64; Shape::ALL.len()]> =
            LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Batch)
            .for_each(|(exposes, stacks)| {
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
                        Verdict::Delivered { .. } => {
                            unreachable!("the overlay slice has no egress stage")
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

        super::assert_covered(
            forwarded > 0,
            "no packet was ever forwarded: the harness is exercising the drop path only",
        );
        super::assert_covered(dropped > 0, "no packet was ever dropped");
        for shape in Shape::ALL {
            super::assert_covered(
                BY_SHAPE[shape as usize].load(Ordering::Relaxed) > 0,
                &format!("no {shape:?} packet ever reached the pipeline"),
            );
        }
    }
}

#[cfg(test)]
mod round_trip {
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use config::external::overlay::vpcpeering::contract::MasqueradeExposes;
    use lpm::prefix::{Prefix, PrefixWithOptionalPorts};
    use net::headers::builder::HeaderStack;
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::parse::DeParse;
    use net::udp::UdpPort;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const MAX_EXPOSES: u8 = 2;
    const FLOWS_PER_FABRIC: usize = 8;

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
                    sport: driver.produce::<u16>()?.max(1),
                    dport: driver.produce::<u16>()?.max(1),
                });
            }
            Some((exposes, flows))
        }
    }

    fn private_addresses(exposes: &[VpcExpose]) -> Vec<Prefix> {
        exposes
            .iter()
            .flat_map(|e| e.ips.iter().map(PrefixWithOptionalPorts::prefix))
            .collect()
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

    pub(super) fn udp(
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
    ) -> Option<Packet<TestBuffer>> {
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
                        ip.set_ttl(64);
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
                        ip.set_hop_limit(64);
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

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("round_trip::Batch", &Batch);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_translated_flow_comes_back_to_where_it_started() {
        static ROUND_TRIPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static NOT_FORWARDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
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
                        Verdict::Delivered { .. } => {
                            unreachable!("the overlay slice has no egress stage")
                        }
                    }
                }
            });

        let round_tripped = ROUND_TRIPPED.load(Ordering::Relaxed);
        eprintln!(
            "round-tripped={round_tripped} not-forwarded={}",
            NOT_FORWARDED.load(Ordering::Relaxed)
        );
        super::assert_covered(
            round_tripped > 0,
            "no flow was ever forwarded, so nothing was ever checked to come back",
        );
    }
}

#[cfg(test)]
mod acl {
    use super::*;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
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

    const MAX_EXPOSES: u8 = 2;
    const PACKETS_PER_FABRIC: usize = 12;

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
        fn as_match(self) -> AclProtoMatch {
            match self {
                Proto::Tcp => AclProtoMatch::Tcp,
                Proto::Udp => AclProtoMatch::Udp,
                Proto::Icmp => AclProtoMatch::Other(NextHeader::ICMP.as_u8()),
            }
        }
    }

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

    fn carried(proto: Proto, v6: bool) -> AclProtoMatch {
        match (proto, v6) {
            (Proto::Icmp, true) => AclProtoMatch::Other(NextHeader::ICMP6.as_u8()),
            (p, _) => p.as_match(),
        }
    }

    fn rule_matches(rule: AclProtoMatch, carried: AclProtoMatch) -> bool {
        matches!(rule, AclProtoMatch::Any) || rule == carried
    }

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

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("acl::Batch", &Batch);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn the_acl_verdict_follows_the_protocol_the_packet_carries() {
        static DENIED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PERMITTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static BEHIND_EXT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PERMITTED_OUT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DENIED_BY_ACL: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Batch)
            .for_each(|(exposes, default_allow, rule_proto, packets)| {
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
            });

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
        super::assert_covered(permitted > 0, "no packet was ever permitted");
        super::assert_covered(denied > 0, "no packet was ever denied");
        super::assert_covered(
            permitted_out > 0,
            "no permitted packet was ever forwarded: the permit direction is vacuous",
        );
        super::assert_covered(
            denied_by_acl > 0,
            "no denial ever came from the acl: the deny direction is being satisfied by stages \
             ahead of it, and would hold with the acl removed",
        );
        super::assert_covered(
            behind > 0,
            "no packet was ever sent behind an extension header, which is the shape this exists for",
        );
    }
}

#[cfg(test)]
mod port_forward {
    use super::round_trip::udp;
    use super::routed::{inside, tunnelled_from};
    use super::*;
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use config::external::overlay::vpcpeering::VpcExpose;
    use lpm::prefix::{L4Protocol, PortRange, Prefix, PrefixWithOptionalPorts};
    use net::headers::TryVxlan;

    const INTERNAL_NET: &str = "10.0.5.0/28";
    const EXTERNAL_NET: &str = "172.16.5.0/28";
    const HOSTS: u8 = 16;
    const INTERNAL_PORT: u16 = 8000;
    const EXTERNAL_PORT: u16 = 9000;
    const PORTS: u16 = 8;

    fn expose() -> VpcExpose {
        VpcExpose::empty()
            .make_port_forwarding(None, Some(L4Protocol::Udp))
            .unwrap_or_else(|_| unreachable!("udp port forwarding is a valid flavour"))
            .ip(PrefixWithOptionalPorts::new(
                INTERNAL_NET
                    .parse::<Prefix>()
                    .unwrap_or_else(|_| unreachable!()),
                Some(
                    PortRange::new(INTERNAL_PORT, INTERNAL_PORT + PORTS - 1)
                        .unwrap_or_else(|_| unreachable!()),
                ),
            ))
            .as_range(PrefixWithOptionalPorts::new(
                EXTERNAL_NET
                    .parse::<Prefix>()
                    .unwrap_or_else(|_| unreachable!()),
                Some(
                    PortRange::new(EXTERNAL_PORT, EXTERNAL_PORT + PORTS - 1)
                        .unwrap_or_else(|_| unreachable!()),
                ),
            ))
            .unwrap_or_else(|_| unreachable!("the two ranges are the same size"))
    }

    fn outside() -> IpAddr {
        "3.3.3.7".parse().unwrap_or_else(|_| unreachable!())
    }

    #[derive(Debug, Clone, Copy)]
    struct Reach {
        host: u8,
        port: u16,
        src_port: u16,
        past_the_range: bool,
    }

    struct Reaches;

    const REACHES_PER_FABRIC: usize = 8;

    impl bolero::ValueGenerator for Reaches {
        type Output = Vec<Reach>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Reach>> {
            (0..REACHES_PER_FABRIC)
                .map(|_| {
                    let choice = driver.produce::<u8>()?;
                    Some(Reach {
                        host: driver.produce::<u8>()? % HOSTS,
                        port: driver.produce::<u16>()? % PORTS,
                        src_port: driver.produce::<u16>()?.max(1),
                        past_the_range: choice % 4 == 3,
                    })
                })
                .collect()
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("port_forward::Reaches", &Reaches);
    }

    fn answers(
        fabric: &mut Fabric,
        host: IpAddr,
        reach: Reach,
        external: IpAddr,
        dport: u16,
    ) -> bool {
        let Some(reply) = udp(host, outside(), INTERNAL_PORT + reach.port, reach.src_port) else {
            return false;
        };
        let back = fabric.send(tunnelled_from(vni(LOCAL_VNI), &reply));
        assert!(
            matches!(verdict(&back), Verdict::Delivered { .. }),
            "the service's reply did not get out: {:?}",
            verdict(&back)
        );
        assert_eq!(
            back.try_vxlan().map(net::vxlan::Vxlan::vni),
            Some(vni(REMOTE_VNI)),
            "the reply went back into the wrong vpc"
        );
        let answered = inside(&back).expect("a delivered reply was not tunnelled");
        assert_eq!(
            answered.ip_source(),
            Some(external),
            "the reply was sourced from the internal address, which the outside host never \
             addressed"
        );
        assert_eq!(
            answered.transport_src_port().map(std::num::NonZero::get),
            Some(dport),
            "the reply came from the right address on the wrong port"
        );
        assert_eq!(
            answered.ip_destination(),
            Some(outside()),
            "the reply did not reach the host that made the request"
        );
        true
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_forwarded_port_reaches_the_host_behind_it() {
        static FORWARDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static ANSWERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static REFUSED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Reaches)
            .for_each(|reaches| {
                let Some(mut fabric) = Fabric::routed(&[expose()], None) else {
                    unreachable!("the port-forwarding fixture does not configure")
                };

                for reach in reaches {
                    let external: IpAddr = format!("172.16.5.{}", reach.host)
                        .parse()
                        .unwrap_or_else(|_| unreachable!());
                    let dport = if reach.past_the_range {
                        EXTERNAL_PORT + PORTS + (reach.port % PORTS)
                    } else {
                        EXTERNAL_PORT + reach.port
                    };

                    let Some(inbound) = udp(outside(), external, reach.src_port, dport) else {
                        continue;
                    };
                    let out = fabric.send(tunnelled_from(vni(REMOTE_VNI), &inbound));

                    if reach.past_the_range {
                        assert!(
                            !matches!(verdict(&out), Verdict::Delivered { .. }),
                            "a packet to {external}:{dport}, past the declared range, was \
                             forwarded anyway"
                        );
                        REFUSED.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    assert!(
                        matches!(verdict(&out), Verdict::Delivered { .. }),
                        "a packet to the declared {external}:{dport} was not forwarded: {:?}",
                        verdict(&out)
                    );
                    let arrived = inside(&out).expect("a forwarded packet was not tunnelled");
                    let expected_host: IpAddr = format!("10.0.5.{}", reach.host)
                        .parse()
                        .unwrap_or_else(|_| unreachable!());
                    assert_eq!(
                        arrived.ip_destination(),
                        Some(expected_host),
                        "{external}:{dport} reached the wrong host"
                    );
                    assert_eq!(
                        arrived.transport_dst_port().map(std::num::NonZero::get),
                        Some(INTERNAL_PORT + reach.port),
                        "{external}:{dport} reached the right host on the wrong port"
                    );
                    FORWARDED.fetch_add(1, Ordering::Relaxed);

                    if answers(&mut fabric, expected_host, *reach, external, dport) {
                        ANSWERED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let (forwarded, answered, refused) = (
            FORWARDED.load(Ordering::Relaxed),
            ANSWERED.load(Ordering::Relaxed),
            REFUSED.load(Ordering::Relaxed),
        );
        eprintln!("forwarded={forwarded} answered={answered} refused={refused}");
        super::assert_covered(forwarded > 0, "no packet was ever forwarded to the service");
        super::assert_covered(answered > 0, "the service never answered");
        super::assert_covered(
            refused > 0,
            "no packet was ever aimed past the declared range, so the negative half is vacuous",
        );
    }
}

#[cfg(test)]
mod interleaved {
    use super::routed::{Blast, Conversation, Path, exposes};
    use super::*;
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use std::ops::Bound::Included;

    const LOADS: usize = 6;
    const POLLS: usize = 10;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Kind {
        Conversation,
        Blast,
    }

    #[derive(Debug, Clone, Copy)]
    struct Sender {
        kind: Kind,
        host: u8,
        sport: u16,
        dport: u16,
        count: u8,
    }

    struct Interleaving;

    impl bolero::ValueGenerator for Interleaving {
        type Output = (Vec<Sender>, Vec<Poll>);

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let senders = (0..LOADS)
                .map(|_| {
                    Some(Sender {
                        kind: if driver.produce::<bool>()? {
                            Kind::Conversation
                        } else {
                            Kind::Blast
                        },
                        host: driver.produce::<u8>()?,
                        sport: driver.produce::<u16>()?.max(1),
                        dport: driver.produce::<u16>()?.max(1),
                        count: driver.gen_u8(Included(&2), Included(&5))?,
                    })
                })
                .collect::<Option<Vec<_>>>()?;

            let schedule = (0..POLLS)
                .map(|_| {
                    let picks = driver.gen_u8(Included(&1), Included(&3))?;
                    (0..picks)
                        .map(|_| {
                            Some(Pick {
                                load: driver.produce::<u8>()?,
                                take: driver.gen_u8(Included(&1), Included(&3))?,
                            })
                        })
                        .collect::<Option<Vec<_>>>()
                })
                .collect::<Option<Vec<_>>>()?;

            Some((senders, schedule))
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("interleaved::Interleaving", &Interleaving);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn interleaved_traffic_is_each_satisfied() {
        static CHECKED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static ABANDONED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static MIXED_LOADS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static MIXED_KINDS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Interleaving)
            .for_each(|(senders, schedule)| {
                let Some(mut fabric) = Fabric::routed(&exposes(), None) else {
                    return;
                };

                let dst: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
                let mut kinds = Vec::new();
                let mut loads: Vec<Box<dyn Load>> = Vec::new();
                for (i, sender) in senders.iter().enumerate() {
                    let Ok(src) = format!("1.1.{i}.{}", sender.host).parse::<IpAddr>() else {
                        continue;
                    };
                    kinds.push(sender.kind);
                    loads.push(match sender.kind {
                        Kind::Conversation => Box::new(Conversation::new(
                            Path::fixture(),
                            src,
                            dst,
                            sender.sport,
                            sender.dport,
                        )),
                        Kind::Blast => Box::new(Blast::new(
                            Path::fixture(),
                            src,
                            dst,
                            sender.sport,
                            sender.dport,
                            sender.count,
                        )) as Box<dyn Load>,
                    });
                }

                for burst in run_schedule(fabric.worker(), &mut loads, schedule) {
                    let mut loads_in: Vec<usize> = burst.clone();
                    loads_in.sort_unstable();
                    loads_in.dedup();
                    if loads_in.len() > 1 {
                        MIXED_LOADS.fetch_add(1, Ordering::Relaxed);
                    }
                    let mut kinds_in: Vec<Kind> = burst.iter().map(|i| kinds[*i]).collect();
                    kinds_in.sort_unstable_by_key(|k| format!("{k:?}"));
                    kinds_in.dedup();
                    if kinds_in.len() > 1 {
                        MIXED_KINDS.fetch_add(1, Ordering::Relaxed);
                    }
                }

                for load in &loads {
                    if load.checked() {
                        CHECKED.fetch_add(1, Ordering::Relaxed);
                    } else {
                        ABANDONED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let (checked, abandoned, mixed_loads, mixed_kinds) = (
            CHECKED.load(Ordering::Relaxed),
            ABANDONED.load(Ordering::Relaxed),
            MIXED_LOADS.load(Ordering::Relaxed),
            MIXED_KINDS.load(Ordering::Relaxed),
        );
        eprintln!(
            "checked={checked} abandoned={abandoned} mixed-loads={mixed_loads} \
             mixed-kinds={mixed_kinds}"
        );
        super::assert_covered(checked > 0, "no sender ever completed its business");
        super::assert_covered(
            mixed_loads > 0,
            "no burst ever carried more than one sender's traffic, so nothing was interleaved",
        );
        super::assert_covered(
            mixed_kinds > 0,
            "no burst ever mixed a conversation with a blast, so the two shapes never met",
        );
    }
}

#[cfg(test)]
mod offers {
    use super::derive::{Vary, loads_for};
    use super::*;
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use config::external::overlay::vpcpeering::VpcExpose;
    use config::external::overlay::vpcpeering::contract::overlay_with_exposes;
    use lpm::prefix::{L4Protocol, PortRange, Prefix, PrefixWithOptionalPorts};
    use std::ops::Bound::Included;

    const SENDERS: usize = 6;
    const POLLS: usize = 10;

    fn overlay() -> config::external::overlay::ValidatedOverlay {
        let masquerade = VpcExpose::empty()
            .make_masquerade(None)
            .unwrap_or_else(|_| unreachable!())
            .ip("1.1.0.0/16"
                .parse::<Prefix>()
                .unwrap_or_else(|_| unreachable!())
                .into())
            .as_range(
                "2.2.0.0/16"
                    .parse::<Prefix>()
                    .unwrap_or_else(|_| unreachable!())
                    .into(),
            )
            .unwrap_or_else(|_| unreachable!());

        let forwarded = VpcExpose::empty()
            .make_port_forwarding(None, Some(L4Protocol::Udp))
            .unwrap_or_else(|_| unreachable!())
            .ip(PrefixWithOptionalPorts::new(
                "10.0.5.0/28"
                    .parse::<Prefix>()
                    .unwrap_or_else(|_| unreachable!()),
                Some(PortRange::new(8000, 8007).unwrap_or_else(|_| unreachable!())),
            ))
            .as_range(PrefixWithOptionalPorts::new(
                "172.16.5.0/28"
                    .parse::<Prefix>()
                    .unwrap_or_else(|_| unreachable!()),
                Some(PortRange::new(9000, 9007).unwrap_or_else(|_| unreachable!())),
            ))
            .unwrap_or_else(|_| unreachable!());

        overlay_with_exposes(vec![masquerade, forwarded])
            .unwrap_or_else(|e| unreachable!("the fixture does not assemble: {e}"))
            .validate()
            .unwrap_or_else(|e| unreachable!("the fixture does not validate: {e}"))
    }

    struct Offered;

    impl bolero::ValueGenerator for Offered {
        type Output = (Vec<Vary>, Vec<Poll>);

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let vary = (0..SENDERS)
                .map(|_| {
                    Some(Vary {
                        host: driver.produce::<u8>()?,
                        port: driver.produce::<u8>()?,
                        sport: driver.produce::<u16>()?.max(1),
                        dport: driver.produce::<u16>()?.max(1),
                        burst: driver.gen_u8(Included(&2), Included(&5))?,
                        blast: driver.produce::<bool>()?,
                    })
                })
                .collect::<Option<Vec<_>>>()?;

            let schedule = (0..POLLS)
                .map(|_| {
                    let picks = driver.gen_u8(Included(&1), Included(&3))?;
                    (0..picks)
                        .map(|_| {
                            Some(Pick {
                                load: driver.produce::<u8>()?,
                                take: driver.gen_u8(Included(&1), Included(&3))?,
                            })
                        })
                        .collect::<Option<Vec<_>>>()
                })
                .collect::<Option<Vec<_>>>()?;

            Some((vary, schedule))
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("offers::Offered", &Offered);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_configuration_carries_everything_it_offers() {
        static CHECKED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static ABANDONED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DERIVED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static MIXED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static INBOUND: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static OUTBOUND: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let overlay = overlay();

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Offered)
            .for_each(|(vary, schedule)| {
                let mut fabric = Fabric::routed_over_validated(
                    &overlay,
                    topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]),
                );

                let mut loads = loads_for(&overlay, vary);
                DERIVED.fetch_add(loads.len() as u64, Ordering::Relaxed);
                for load in &loads {
                    if load.describe().starts_with("[inbound") {
                        INBOUND.fetch_add(1, Ordering::Relaxed);
                    } else {
                        OUTBOUND.fetch_add(1, Ordering::Relaxed);
                    }
                }

                for burst in run_schedule(fabric.worker(), &mut loads, schedule) {
                    let mut seen = burst.clone();
                    seen.sort_unstable();
                    seen.dedup();
                    if seen.len() > 1 {
                        MIXED.fetch_add(1, Ordering::Relaxed);
                    }
                }

                for load in &loads {
                    if load.checked() {
                        CHECKED.fetch_add(1, Ordering::Relaxed);
                    } else {
                        ABANDONED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let (checked, abandoned, derived, mixed) = (
            CHECKED.load(Ordering::Relaxed),
            ABANDONED.load(Ordering::Relaxed),
            DERIVED.load(Ordering::Relaxed),
            MIXED.load(Ordering::Relaxed),
        );
        let (inbound, outbound) = (
            INBOUND.load(Ordering::Relaxed),
            OUTBOUND.load(Ordering::Relaxed),
        );
        eprintln!(
            "checked={checked} abandoned={abandoned} derived={derived} \
             (inbound {inbound}, outbound {outbound}) mixed-bursts={mixed}"
        );
        super::assert_covered(derived > 0, "the configuration implied no traffic at all");
        super::assert_covered(
            inbound > 0,
            "the derivation produced no inbound traffic, so the port-forwarding expose this \
             fixture carries was skipped rather than tested",
        );
        super::assert_covered(
            outbound > 0,
            "the derivation produced no outbound traffic, so the masquerade expose was skipped",
        );
        super::assert_covered(checked > 0, "no derived sender ever completed its business");
        super::assert_covered(
            mixed > 0,
            "no burst ever carried more than one sender's traffic, so nothing was interleaved",
        );
    }
}

#[cfg(test)]
mod generated {
    use super::derive::{Vary, loads_for};
    use super::*;
    use bolero::ValueGenerator;
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use config::external::overlay::algebra::{Op, Sequence};
    use std::ops::Bound::Included;

    const SENDERS: usize = 6;
    const POLLS: usize = 8;

    pub(super) struct Generated;

    impl ValueGenerator for Generated {
        type Output = (Vec<Op>, Vec<Vary>, Vec<Poll>);

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let ops = Sequence::default().generate(driver)?;

            let vary = (0..SENDERS)
                .map(|_| {
                    Some(Vary {
                        host: driver.produce::<u8>()?,
                        port: driver.produce::<u8>()?,
                        sport: driver.produce::<u16>()?.max(1),
                        dport: driver.produce::<u16>()?.max(1),
                        burst: driver.gen_u8(Included(&2), Included(&5))?,
                        blast: driver.produce::<bool>()?,
                    })
                })
                .collect::<Option<Vec<_>>>()?;

            let schedule = (0..POLLS)
                .map(|_| {
                    let picks = driver.gen_u8(Included(&1), Included(&3))?;
                    (0..picks)
                        .map(|_| {
                            Some(Pick {
                                load: driver.produce::<u8>()?,
                                take: driver.gen_u8(Included(&1), Included(&3))?,
                            })
                        })
                        .collect::<Option<Vec<_>>>()
                })
                .collect::<Option<Vec<_>>>()?;

            Some((ops, vary, schedule))
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("generated::Generated", &Generated);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_generated_configuration_carries_its_own_traffic() {
        static CHECKED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DERIVED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static MIXED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PEERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static MULTI: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Generated)
            .for_each(|(ops, vary, schedule)| {
                let draft = Sequence::fold(ops);
                let overlay = draft
                    .overlay()
                    .unwrap_or_else(|e| panic!("{ops:?} does not assemble: {e}"));
                let validated = overlay
                    .validate()
                    .unwrap_or_else(|e| panic!("{ops:?} does not validate: {e}"));

                let vnis: Vec<Vni> = validated
                    .vpc_table()
                    .values()
                    .map(config::external::overlay::vpc::ValidatedVpc::vni)
                    .collect();
                if vnis.is_empty() {
                    return;
                }
                if validated.vpc_table().peerings().next().is_some() {
                    PEERED.fetch_add(1, Ordering::Relaxed);
                }
                if vnis.len() > 2 {
                    MULTI.fetch_add(1, Ordering::Relaxed);
                }

                let mut fabric = Fabric::routed_over_validated(&validated, topology(&vnis));

                let mut loads = loads_for(&validated, vary);
                DERIVED.fetch_add(loads.len() as u64, Ordering::Relaxed);

                for burst in run_schedule(fabric.worker(), &mut loads, schedule) {
                    let mut seen = burst.clone();
                    seen.sort_unstable();
                    seen.dedup();
                    if seen.len() > 1 {
                        MIXED.fetch_add(1, Ordering::Relaxed);
                    }
                }

                for load in &loads {
                    assert!(
                        load.checked(),
                        "a load derived from the configuration did not complete: {}",
                        load.describe()
                    );
                    CHECKED.fetch_add(1, Ordering::Relaxed);
                }
            });

        let (checked, derived, mixed) = (
            CHECKED.load(Ordering::Relaxed),
            DERIVED.load(Ordering::Relaxed),
            MIXED.load(Ordering::Relaxed),
        );
        let (peered, multi) = (
            PEERED.load(Ordering::Relaxed),
            MULTI.load(Ordering::Relaxed),
        );
        eprintln!(
            "checked={checked} derived={derived} peered-configs={peered} \
             configs-past-two-vpcs={multi} mixed-bursts={mixed}"
        );
        super::assert_covered(peered > 0, "no generated configuration ever had a peering");
        super::assert_covered(
            multi > 0,
            "no generated configuration ever had more than two vpcs, so this reached nothing the \
             two-vpc fixtures do not",
        );
        super::assert_covered(
            derived > 0,
            "no generated configuration ever implied any traffic",
        );
        super::assert_covered(checked > 0, "no derived sender ever completed its business");
        super::assert_covered(
            mixed > 0,
            "no burst ever carried more than one sender's traffic, so nothing was interleaved",
        );
    }
}

#[cfg(test)]
mod burst {
    use super::round_trip::udp;
    use super::routed::{exposes, inside, tunnelled};
    use super::*;
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use net::headers::TryVxlan;

    const BURST: usize = 8;

    #[derive(Debug, Clone, Copy)]
    struct Member {
        host: u8,
        dport: u16,
    }

    struct Burst;

    impl bolero::ValueGenerator for Burst {
        type Output = Vec<Member>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Member>> {
            (0..BURST)
                .map(|_| {
                    Some(Member {
                        host: driver.produce()?,
                        dport: driver.produce::<u16>()?.max(1),
                    })
                })
                .collect()
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("burst::Burst", &Burst);
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Treatment {
        verdict: Verdict,
        vni: Option<u32>,
        inner_src: Option<IpAddr>,
        inner_dst: Option<IpAddr>,
        inner_sport: Option<u16>,
    }

    fn treatment(packet: &Packet<TestBuffer>) -> Treatment {
        let carried = inside(packet);
        Treatment {
            verdict: verdict(packet),
            vni: packet.try_vxlan().map(|v| v.vni().as_u32()),
            inner_src: carried.as_ref().and_then(Packet::ip_source),
            inner_dst: carried.as_ref().and_then(Packet::ip_destination),
            inner_sport: carried
                .as_ref()
                .and_then(Packet::transport_src_port)
                .map(std::num::NonZero::get),
        }
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_burst_of_one_flow_allocates_once() {
        static CHECKED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Burst)
            .for_each(|members| {
                let m = members[0];
                let src: IpAddr = format!("1.1.0.{}", m.host)
                    .parse()
                    .unwrap_or_else(|_| unreachable!());
                let dst: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
                let packet = || udp(src, dst, 4000, m.dport).map(|p| tunnelled(&p));

                let (Some(mut alone), Some(mut burst)) = (
                    Fabric::routed(&exposes(), None),
                    Fabric::routed(&exposes(), None),
                ) else {
                    return;
                };
                let Some(one) = packet() else { return };
                let single = treatment(&alone.send(one));
                if !matches!(single.verdict, Verdict::Delivered { .. }) {
                    return;
                }
                let cost_of_one = alone.flows();

                let Some(together) = (0..BURST).map(|_| packet()).collect::<Option<Vec<_>>>()
                else {
                    return;
                };
                let out = burst.send_batch(together);

                for (i, packet) in out.iter().enumerate() {
                    let t = treatment(packet);
                    assert_eq!(
                        t.inner_sport, single.inner_sport,
                        "packet {i} of a burst of one flow was given a different public port \
                         from the same packet sent alone: the burst allocated more than once"
                    );
                    assert_eq!(
                        t.inner_src, single.inner_src,
                        "packet {i} of a burst of one flow left under a different public address"
                    );
                    assert_eq!(
                        t.verdict, single.verdict,
                        "packet {i} of a burst of one flow reached a different verdict"
                    );
                }
                assert_eq!(
                    burst.flows(),
                    cost_of_one,
                    "a burst of {BURST} packets of one flow cost more flow-table entries than \
                     one packet of it did"
                );
                CHECKED.fetch_add(1, Ordering::Relaxed);
            });

        let checked = CHECKED.load(Ordering::Relaxed);
        eprintln!("single-flow-bursts={checked}");
        super::assert_covered(checked > 0, "no burst of a single flow was ever delivered");
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_burst_is_treated_the_same_as_one_packet_at_a_time() {
        static COMPARED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DELIVERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Burst)
            .for_each(|members| {
                let packets = || {
                    members
                        .iter()
                        .enumerate()
                        .map(|(i, m)| {
                            let src: IpAddr = format!("1.1.{i}.{}", m.host)
                                .parse()
                                .unwrap_or_else(|_| unreachable!());
                            let dst: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
                            udp(src, dst, 1024 + u16::try_from(i).unwrap_or(0), m.dport)
                                .map(|p| tunnelled(&p))
                        })
                        .collect::<Option<Vec<_>>>()
                };
                let (Some(singly), Some(together)) = (packets(), packets()) else {
                    return;
                };

                let (Some(mut a), Some(mut b)) = (
                    Fabric::routed(&exposes(), None),
                    Fabric::routed(&exposes(), None),
                ) else {
                    return;
                };

                let one_at_a_time: Vec<_> =
                    singly.into_iter().map(|p| treatment(&a.send(p))).collect();
                let in_a_burst: Vec<_> = b.send_batch(together).iter().map(treatment).collect();

                assert_eq!(
                    one_at_a_time.len(),
                    in_a_burst.len(),
                    "a burst did not return as many packets as it was given"
                );
                for (i, (alone, batched)) in one_at_a_time.iter().zip(in_a_burst.iter()).enumerate()
                {
                    assert_eq!(
                        alone, batched,
                        "packet {i} of the burst was treated differently from the same packet \
                         sent on its own"
                    );
                    COMPARED.fetch_add(1, Ordering::Relaxed);
                    if matches!(alone.verdict, Verdict::Delivered { .. }) {
                        DELIVERED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let (compared, delivered) = (
            COMPARED.load(Ordering::Relaxed),
            DELIVERED.load(Ordering::Relaxed),
        );
        eprintln!("compared={compared} delivered={delivered}");
        super::assert_covered(compared > 0, "no burst was ever compared");
        super::assert_covered(
            delivered > 0,
            "no packet of any burst ever reached the wire, so the comparison is between drops",
        );
    }
}

#[cfg(test)]
mod destination {
    use super::round_trip::udp;
    use super::routed::{inside, tunnelled};
    use super::*;
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use config::external::overlay::vpcpeering::contract::{overlay_with_peers, peer_vni};
    use lpm::prefix::Prefix;
    use net::headers::TryVxlan;

    const PEERS: u8 = 3;

    fn local_prefix() -> Prefix {
        "1.1.0.0/16"
            .parse()
            .unwrap_or_else(|_| unreachable!("a well-formed prefix"))
    }

    #[derive(Debug, Clone, Copy)]
    struct Aim {
        peer: Option<u8>,
        host: u8,
        third: u8,
        sport: u16,
        dport: u16,
    }

    struct Aims;

    const AIMS_PER_FABRIC: usize = 12;

    impl bolero::ValueGenerator for Aims {
        type Output = Vec<Aim>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Aim>> {
            (0..AIMS_PER_FABRIC)
                .map(|_| {
                    let choice = driver.produce::<u8>()?;
                    Some(Aim {
                        peer: (choice % 4 != 3).then_some(choice % PEERS),
                        host: driver.produce()?,
                        third: driver.produce()?,
                        sport: driver.produce::<u16>()?.max(1),
                        dport: driver.produce::<u16>()?.max(1),
                    })
                })
                .collect()
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("destination::Aims", &Aims);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_packet_leaves_for_the_vpc_that_exposes_its_destination() {
        static REACHED: LazyLock<[AtomicU64; PEERS as usize]> =
            LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));
        static REFUSED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Aims)
            .for_each(|aims| {
                let vnis: Vec<_> = std::iter::once(vni(LOCAL_VNI))
                    .chain((0..PEERS).map(|n| vni(peer_vni(n))))
                    .collect();
                let overlay = overlay_with_peers(local_prefix(), PEERS).unwrap_or_else(|e| {
                    unreachable!("the multi-peer contract does not build: {e}")
                });
                let Some(mut fabric) = Fabric::routed_over(&overlay, topology(&vnis)) else {
                    unreachable!("the multi-peer contract does not validate")
                };

                for aim in aims {
                    let src: IpAddr = format!("1.1.0.{}", aim.host)
                        .parse()
                        .unwrap_or_else(|_| unreachable!());
                    let dst: IpAddr = match aim.peer {
                        Some(n) => format!("10.{}.{}.{}", n + 1, aim.third, aim.host),
                        None => format!("172.16.{}.{}", aim.third, aim.host),
                    }
                    .parse()
                    .unwrap_or_else(|_| unreachable!());

                    let Some(packet) = udp(src, dst, aim.sport, aim.dport) else {
                        continue;
                    };
                    let out = fabric.send(tunnelled(&packet));
                    let left = matches!(verdict(&out), Verdict::Delivered { .. });

                    if let Some(n) = aim.peer {
                        assert!(
                            left,
                            "a packet to {dst}, which peer {n} exposes, did not leave: {:?}",
                            verdict(&out)
                        );
                        assert_eq!(
                            out.try_vxlan().map(net::vxlan::Vxlan::vni),
                            Some(vni(peer_vni(n))),
                            "a packet to {dst} left for the wrong vpc"
                        );
                        let carried = inside(&out).expect("a delivered packet was not tunnelled");
                        assert_eq!(
                            carried.ip_destination(),
                            Some(dst),
                            "the destination was rewritten on the way out"
                        );
                        REACHED[n as usize].fetch_add(1, Ordering::Relaxed);
                    } else {
                        assert!(
                            !left,
                            "a packet to {dst}, which no peering covers, was sent to {:?}",
                            out.try_vxlan().map(net::vxlan::Vxlan::vni)
                        );
                        REFUSED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let reached: Vec<u64> = REACHED.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        let refused = REFUSED.load(Ordering::Relaxed);
        eprintln!("reached-per-peer={reached:?} refused={refused}");

        for (n, count) in reached.iter().enumerate() {
            super::assert_covered(*count > 0, &format!("peer {n} was never reached"));
        }
        super::assert_covered(
            refused > 0,
            "no packet was ever aimed outside every peering, so the negative half is vacuous",
        );
    }
}

#[cfg(test)]
mod routed {
    use super::round_trip::udp;
    use super::shapes::{Batch, Shape, aim, wire};
    use super::*;
    use super::{Load, drive};
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use net::buffer::TestBuffer;
    use net::headers::{TryEth, TryHeaders, TryHeadersMut, TryIpv4, TryVxlan};
    use net::ip::dscp::Dscp;
    use net::ip::ecn::Ecn;
    use net::packet::test_utils::{
        build_test_udp_ipv4_packet, build_test_vxlan_ipv4_packet_carrying_vni,
    };
    use net::parse::DeParse;
    use net::vlan::Vid;

    #[derive(Debug, Clone, Copy)]
    struct Flow {
        host: u8,
        sport: u16,
        dport: u16,
    }

    struct Flows;

    const FLOWS_PER_FABRIC: usize = 8;

    impl bolero::ValueGenerator for Flows {
        type Output = Vec<Flow>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Flow>> {
            (0..FLOWS_PER_FABRIC)
                .map(|_| {
                    Some(Flow {
                        host: driver.produce()?,
                        sport: driver.produce::<u16>()?.max(1),
                        dport: driver.produce::<u16>()?.max(1),
                    })
                })
                .collect()
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("routed::Flows", &Flows);
    }

    pub(super) fn exposes() -> Vec<VpcExpose> {
        vec![
            VpcExpose::empty()
                .make_masquerade(None)
                .unwrap()
                .ip("1.1.0.0/16".parse::<Prefix>().unwrap().into())
                .as_range("2.2.0.0/16".parse::<Prefix>().unwrap().into())
                .unwrap(),
        ]
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Path {
        pub(crate) from: Vni,
        pub(crate) to: Vni,
    }

    impl Path {
        pub(crate) fn new(from: Vni, to: Vni) -> Self {
            Self { from, to }
        }

        pub(crate) fn fixture() -> Self {
            Self::new(vni(LOCAL_VNI), vni(REMOTE_VNI))
        }

        fn reversed(self) -> Self {
            Self::new(self.to, self.from)
        }
    }

    pub(super) fn tunnelled_from(from: Vni, inner: &Packet<TestBuffer>) -> Packet<TestBuffer> {
        let bytes = inner
            .clone()
            .serialize()
            .expect("the inner frame serializes");
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
        packet.meta_mut().set_keep(true);
        packet
    }

    pub(super) fn tunnelled(inner: &Packet<TestBuffer>) -> Packet<TestBuffer> {
        tunnelled_from(vni(LOCAL_VNI), inner)
    }

    pub(super) fn inside(delivered: &Packet<TestBuffer>) -> Option<Packet<TestBuffer>> {
        let mut copy = delivered.clone();
        matches!(copy.vxlan_decap(), Some(Ok(_))).then_some(copy)
    }

    pub(super) fn inner() -> Packet<TestBuffer> {
        build_test_udp_ipv4_packet("1.1.0.1", "3.3.3.1", 1234, 80)
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_tunnelled_frame_is_decapsulated_translated_and_sent_back_out_tunnelled() {
        let mut fabric = Fabric::routed(&exposes(), None).expect("a valid configuration");

        let out = fabric.send(tunnelled(&inner()));

        match verdict(&out) {
            Verdict::Delivered { oif, src, dst } => {
                assert_eq!(oif, Some(uplink()), "delivered over the wrong interface");
                assert_eq!(
                    src,
                    Some(LOCAL_VTEP.parse().unwrap()),
                    "the outer source is not this gateway's vtep: it did not get re-encapsulated"
                );
                assert_eq!(dst, Some(PEER_VTEP.parse().unwrap()));
                assert_eq!(
                    out.try_vxlan().map(net::vxlan::Vxlan::vni),
                    Some(vni(REMOTE_VNI)),
                    "encapsulated towards the wrong vpc"
                );
                assert_eq!(
                    out.try_eth().map(|eth| eth.destination().inner()),
                    Some(PEER_MAC),
                    "the frame was not addressed to the resolved next hop"
                );
            }
            other => panic!("the frame did not leave the gateway: {other:?}"),
        }
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_vlan_tag_is_refused_at_decapsulation() {
        let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
        let mut pipeline = DynPipeline::new()
            .add_stage(Ingress::new("ingress", tables.interfaces()))
            .add_stage(IpForwarder::new("ip-forward-1", tables.fibs()));

        let plain = one(&mut pipeline, tunnelled(&inner()));
        assert_eq!(
            verdict(&plain),
            Verdict::Forwarded {
                dst_vpcd: None,
                src: Some("1.1.0.1".parse().unwrap()),
                dst: Some("3.3.3.1".parse().unwrap()),
            },
            "an untagged frame did not survive decapsulation: the fixture is refusing everything"
        );

        let tagged = one(&mut pipeline, tunnelled(&tagged_inner()));
        assert_eq!(
            verdict(&tagged),
            Verdict::Dropped(DoneReason::Unhandled),
            "a tagged frame survived decapsulation"
        );
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_vlan_tag_inside_the_tunnel_never_leaves_the_gateway() {
        let mut fabric = Fabric::routed(&exposes(), None).expect("a valid configuration");

        let out = fabric.send(tunnelled(&tagged_inner()));

        assert!(
            !matches!(verdict(&out), Verdict::Delivered { .. }),
            "a tagged frame was sent out onto the wire: {:?}",
            verdict(&out)
        );
    }

    fn tagged_inner() -> Packet<TestBuffer> {
        let mut inner = inner();
        inner
            .headers_mut()
            .push_vlan(Vid::new(42).expect("a valid vlan id"))
            .expect("the inner frame has an ethernet header");

        let bytes = inner.serialize().expect("a tagged frame serializes");
        let reparsed = Packet::new(TestBuffer::from_raw_data(bytes.as_ref()))
            .expect("a tagged frame parses back");
        assert!(
            !reparsed.headers().vlan().is_empty(),
            "the fixture did not actually tag the frame"
        );
        reparsed
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_tagged_shape_never_reaches_the_wire() {
        static TAGGED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Batch)
            .for_each(|(exposes, stacks)| {
                let Some(mut fabric) = Fabric::routed(exposes, None) else {
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
                    let Some(frame) = wire(&headers) else {
                        continue;
                    };
                    let tagged = *shape == Shape::VlanV4Tcp;
                    if tagged {
                        TAGGED.fetch_add(1, Ordering::Relaxed);
                    }

                    let out = fabric.send(tunnelled(&frame));
                    assert!(
                        !(tagged && matches!(verdict(&out), Verdict::Delivered { .. })),
                        "a tagged frame was sent out onto the wire"
                    );
                }
            });

        let tagged = TAGGED.load(Ordering::Relaxed);
        eprintln!("tagged={tagged}");

        let mut control = Fabric::routed(&exposes(), None).expect("a valid configuration");
        assert!(
            matches!(
                verdict(&control.send(tunnelled(&inner()))),
                Verdict::Delivered { .. }
            ),
            "the untagged control did not reach the wire, so no delivery was observable here"
        );
        super::assert_covered(tagged > 0, "no tagged shape was ever generated");
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_tunnelled_flow_comes_back_through_the_tunnel() {
        static ROUND_TRIPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static ABANDONED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Flows)
            .for_each(|flows| {
                let Some(mut fabric) = Fabric::routed(&exposes(), None) else {
                    return;
                };

                for flow in flows {
                    let src: IpAddr = format!("1.1.0.{}", flow.host)
                        .parse()
                        .unwrap_or_else(|_| unreachable!());
                    let dst: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
                    let mut load =
                        Conversation::new(Path::fixture(), src, dst, flow.sport, flow.dport);

                    drive(fabric.worker(), &mut load);

                    if load.checked() {
                        ROUND_TRIPPED.fetch_add(1, Ordering::Relaxed);
                    } else {
                        ABANDONED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let round_tripped = ROUND_TRIPPED.load(Ordering::Relaxed);
        eprintln!(
            "tunnelled-round-trips={round_tripped} abandoned={}",
            ABANDONED.load(Ordering::Relaxed)
        );
        super::assert_covered(
            round_tripped > 0,
            "no flow ever reached the wire, so no reply was ever checked to come back",
        );
    }

    pub(super) struct Conversation {
        path: Path,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        sent: Option<Packet<TestBuffer>>,
        state: State,
        log: Vec<String>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum State {
        Opening,
        AwaitingRequest,
        Replying { public: (IpAddr, u16) },
        AwaitingReply,
        Closed,
        Abandoned,
    }

    impl Conversation {
        pub(super) fn new(path: Path, src: IpAddr, dst: IpAddr, sport: u16, dport: u16) -> Self {
            Self {
                path,
                src,
                dst,
                sport,
                dport,
                sent: None,
                state: State::Opening,
                log: Vec::new(),
            }
        }

        fn note(&mut self, what: &str) {
            self.log.push(what.to_owned());
        }

        fn judge_request(&mut self, got: &Packet<TestBuffer>) {
            if !matches!(verdict(got), Verdict::Delivered { .. }) {
                self.note(&format!("request not delivered: {:?}", verdict(got)));
                self.state = State::Abandoned;
                return;
            }
            assert_eq!(
                got.try_vxlan().map(net::vxlan::Vxlan::vni),
                Some(self.path.to),
                "the request left tunnelled towards the wrong vpc. {}",
                self.describe()
            );

            let carried = inside(got).expect("a delivered request was not tunnelled");
            let sent = self.sent.as_ref().unwrap_or_else(|| unreachable!());
            assert_eq!(
                payload_of(&carried),
                payload_of(sent),
                "the tenant payload did not survive decap, nat and encap. {}",
                self.describe()
            );
            assert_eq!(
                ttl_of(&carried).map(|t| t + 1),
                ttl_of(sent),
                "the tenant packet was not charged exactly one hop. {}",
                self.describe()
            );

            let (Some(public_src), Some(port)) =
                (carried.ip_source(), carried.transport_src_port())
            else {
                self.note("the delivered request had no source tuple to answer");
                self.state = State::Abandoned;
                return;
            };
            self.note(&format!("request left as {public_src}:{}", port.get()));
            self.state = State::Replying {
                public: (public_src, port.get()),
            };
        }

        fn judge_reply(&mut self, got: &Packet<TestBuffer>) {
            assert!(
                matches!(verdict(got), Verdict::Delivered { .. }),
                "the reply of a delivered flow did not reach the wire: {:?}. {}",
                verdict(got),
                self.describe()
            );
            assert_eq!(
                got.try_vxlan().map(net::vxlan::Vxlan::vni),
                Some(self.path.from),
                "the reply went back into the wrong vpc. {}",
                self.describe()
            );

            let returned = inside(got).expect("a delivered reply was not tunnelled");
            assert_eq!(
                returned.ip_destination(),
                Some(self.src),
                "the reply did not come back to the host that sent the request. {}",
                self.describe()
            );
            assert_eq!(
                returned.ip_source(),
                Some(self.dst),
                "the reply's source was rewritten. {}",
                self.describe()
            );
            assert_eq!(
                returned.transport_dst_port().map(std::num::NonZero::get),
                Some(self.sport),
                "the reply did not get the original source port back. {}",
                self.describe()
            );
            self.note("reply came back");
            self.state = State::Closed;
        }
    }

    impl Load for Conversation {
        fn next(&mut self) -> Option<Packet<TestBuffer>> {
            match self.state {
                State::Opening => {
                    let request = udp(self.src, self.dst, self.sport, self.dport)?;
                    self.sent = Some(request.clone());
                    self.state = State::AwaitingRequest;
                    Some(tunnelled_from(self.path.from, &request))
                }
                State::Replying { public: (ip, port) } => {
                    let reply = udp(self.dst, ip, self.dport, port)?;
                    self.state = State::AwaitingReply;
                    Some(tunnelled_from(self.path.reversed().from, &reply))
                }
                State::AwaitingRequest
                | State::AwaitingReply
                | State::Closed
                | State::Abandoned => None,
            }
        }

        fn observe(&mut self, got: &Packet<TestBuffer>) {
            match self.state {
                State::AwaitingRequest => self.judge_request(got),
                State::AwaitingReply => self.judge_reply(got),
                ref state => panic!(
                    "a load was given an answer it was not waiting for (state {state:?}). {}",
                    self.describe()
                ),
            }
        }

        fn finished(&self) -> bool {
            matches!(self.state, State::Closed | State::Abandoned)
        }

        fn checked(&self) -> bool {
            self.state == State::Closed
        }

        fn describe(&self) -> String {
            format!(
                "[conversation {}:{} -> {}:{} | {}]",
                self.src,
                self.sport,
                self.dst,
                self.dport,
                if self.log.is_empty() {
                    "nothing yet".to_owned()
                } else {
                    self.log.join("; ")
                }
            )
        }
    }

    pub(super) struct Blast {
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        path: Path,
        to_send: u8,
        in_flight: u8,
        given: Option<(IpAddr, u16)>,
        delivered: u8,
        log: Vec<String>,
    }

    impl Blast {
        pub(super) fn new(
            path: Path,
            src: IpAddr,
            dst: IpAddr,
            sport: u16,
            dport: u16,
            count: u8,
        ) -> Self {
            Self {
                src,
                dst,
                sport,
                dport,
                path,
                to_send: count.max(2),
                in_flight: 0,
                given: None,
                delivered: 0,
                log: Vec::new(),
            }
        }
    }

    impl Load for Blast {
        fn next(&mut self) -> Option<Packet<TestBuffer>> {
            if self.to_send == 0 {
                return None;
            }
            let packet = udp(self.src, self.dst, self.sport, self.dport)?;
            self.to_send -= 1;
            self.in_flight += 1;
            Some(tunnelled_from(self.path.from, &packet))
        }

        fn observe(&mut self, got: &Packet<TestBuffer>) {
            assert!(
                self.in_flight > 0,
                "a blast was given an answer it was not waiting for. {}",
                self.describe()
            );
            self.in_flight -= 1;

            if !matches!(verdict(got), Verdict::Delivered { .. }) {
                self.log.push(format!("not delivered: {:?}", verdict(got)));
                return;
            }
            let Some(carried) = inside(got) else {
                self.log.push("delivered but not tunnelled".to_owned());
                return;
            };
            let (Some(source), Some(port)) = (carried.ip_source(), carried.transport_src_port())
            else {
                return;
            };
            let now = (source, port.get());
            self.delivered += 1;
            match self.given {
                None => {
                    self.log.push(format!("left as {source}:{}", port.get()));
                    self.given = Some(now);
                }
                Some(first) => assert_eq!(
                    now,
                    first,
                    "packets of one flow were given different public tuples, so the flow was \
                     allocated for more than once. {}",
                    self.describe()
                ),
            }
        }

        fn finished(&self) -> bool {
            self.to_send == 0 && self.in_flight == 0
        }

        fn checked(&self) -> bool {
            self.delivered >= 2
        }

        fn describe(&self) -> String {
            format!(
                "[blast {}:{} -> {}:{} | {} left, {} in flight, {} delivered | {}]",
                self.src,
                self.sport,
                self.dst,
                self.dport,
                self.to_send,
                self.in_flight,
                self.delivered,
                if self.log.is_empty() {
                    "nothing yet".to_owned()
                } else {
                    self.log.join("; ")
                }
            )
        }
    }

    pub(super) struct Inbound {
        path: Path,
        from: IpAddr,
        external: IpAddr,
        external_port: u16,
        internal: IpAddr,
        internal_port: u16,
        sport: u16,
        state: InboundState,
        log: Vec<String>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum InboundState {
        Reaching,
        AwaitingArrival,
        Answering,
        AwaitingAnswer,
        Closed,
        Abandoned,
    }

    impl Inbound {
        pub(super) fn new(
            path: Path,
            from: IpAddr,
            external: IpAddr,
            external_port: u16,
            internal: IpAddr,
            internal_port: u16,
            sport: u16,
        ) -> Self {
            Self {
                path,
                from,
                external,
                external_port,
                internal,
                internal_port,
                sport,
                state: InboundState::Reaching,
                log: Vec::new(),
            }
        }

        fn judge_arrival(&mut self, got: &Packet<TestBuffer>) {
            if !matches!(verdict(got), Verdict::Delivered { .. }) {
                self.log.push(format!("not forwarded: {:?}", verdict(got)));
                self.state = InboundState::Abandoned;
                return;
            }
            let arrived = inside(got).expect("a forwarded packet was not tunnelled");
            assert_eq!(
                arrived.ip_destination(),
                Some(self.internal),
                "reached the wrong host. {}",
                self.describe()
            );
            assert_eq!(
                arrived.transport_dst_port().map(std::num::NonZero::get),
                Some(self.internal_port),
                "reached the right host on the wrong port. {}",
                self.describe()
            );
            self.log.push("arrived inside".to_owned());
            self.state = InboundState::Answering;
        }

        fn judge_answer(&mut self, got: &Packet<TestBuffer>) {
            assert!(
                matches!(verdict(got), Verdict::Delivered { .. }),
                "the service's answer did not get out: {:?}. {}",
                verdict(got),
                self.describe()
            );
            let answered = inside(got).expect("a delivered answer was not tunnelled");
            assert_eq!(
                answered.ip_source(),
                Some(self.external),
                "the answer was sourced from the internal address, which the outside host never \
                 addressed. {}",
                self.describe()
            );
            assert_eq!(
                answered.transport_src_port().map(std::num::NonZero::get),
                Some(self.external_port),
                "the answer came from the right address on the wrong port. {}",
                self.describe()
            );
            assert_eq!(
                answered.ip_destination(),
                Some(self.from),
                "the answer did not reach the host that made the request. {}",
                self.describe()
            );
            self.log.push("answered".to_owned());
            self.state = InboundState::Closed;
        }
    }

    impl Load for Inbound {
        fn next(&mut self) -> Option<Packet<TestBuffer>> {
            match self.state {
                InboundState::Reaching => {
                    let request = udp(self.from, self.external, self.sport, self.external_port)?;
                    self.state = InboundState::AwaitingArrival;
                    Some(tunnelled_from(self.path.to, &request))
                }
                InboundState::Answering => {
                    let answer = udp(self.internal, self.from, self.internal_port, self.sport)?;
                    self.state = InboundState::AwaitingAnswer;
                    Some(tunnelled_from(self.path.from, &answer))
                }
                _ => None,
            }
        }

        fn observe(&mut self, got: &Packet<TestBuffer>) {
            match self.state {
                InboundState::AwaitingArrival => self.judge_arrival(got),
                InboundState::AwaitingAnswer => self.judge_answer(got),
                ref state => panic!(
                    "a load was given an answer it was not waiting for (state {state:?}). {}",
                    self.describe()
                ),
            }
        }

        fn finished(&self) -> bool {
            matches!(self.state, InboundState::Closed | InboundState::Abandoned)
        }

        fn checked(&self) -> bool {
            self.state == InboundState::Closed
        }

        fn describe(&self) -> String {
            format!(
                "[inbound {}:{} -> {}:{} (expects {}:{}) | {}]",
                self.from,
                self.sport,
                self.external,
                self.external_port,
                self.internal,
                self.internal_port,
                if self.log.is_empty() {
                    "nothing yet".to_owned()
                } else {
                    self.log.join("; ")
                }
            )
        }
    }

    fn payload_of(packet: &Packet<TestBuffer>) -> Vec<u8> {
        let bytes = packet
            .clone()
            .serialize()
            .expect("a packet in hand serializes");
        let headers = packet.headers().size().get() as usize;
        bytes.as_ref().get(headers..).unwrap_or_default().to_vec()
    }

    fn ttl_of(packet: &Packet<TestBuffer>) -> Option<u8> {
        packet.try_ipv4().map(net::ipv4::Ipv4::ttl)
    }

    fn one(
        pipeline: &mut DynPipeline<TestBuffer>,
        packet: Packet<TestBuffer>,
    ) -> Packet<TestBuffer> {
        let mut out: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
        assert_eq!(out.len(), 1, "the pipeline did not return the packet");
        out.pop().unwrap_or_else(|| unreachable!())
    }
}

#[cfg(test)]
mod model {
    use super::derive::loads_for;
    use super::routed::{Conversation, exposes, inner, inside, tunnelled};
    use super::*;
    use concurrency::sync::Mutex;
    use concurrency::thread;
    #[cfg_attr(not(feature = "shuttle"), allow(unused_imports))]
    use concurrency::thread::BuilderExt;
    use config::external::overlay::algebra::Sequence;
    use net::packet::test_utils::build_test_udp_ipv4_packet;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{LazyLock, OnceLock};

    type Tuple = (Option<IpAddr>, Option<u16>);

    type Reported = (Vec<Tuple>, tracectl::evidence::Evidence);

    fn on_two_threads(body: &(impl Fn() + Sync)) {
        thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    thread::Builder::new()
                        .spawn_scoped(scope, body)
                        .expect("spawn")
                })
                .collect();
            for handle in handles {
                handle.join().expect("join");
            }
        });
    }

    #[concurrency::model_test]
    fn a_lock_that_outlives_its_execution_is_not_model_checkable() {
        static LOCK: OnceLock<Mutex<u32>> = OnceLock::new();
        static RUNS: AtomicUsize = AtomicUsize::new(0);

        concurrency::stress(|| {
            let lock = concurrency::sync::Arc::new(Mutex::new(0u32));
            let inner = lock.clone();
            let bump = move || *inner.lock() += 1;
            on_two_threads(&bump);
            assert_eq!(*lock.lock(), 2);
        });

        concurrency::stress(|| {
            let first = RUNS.fetch_add(1, Ordering::Relaxed) == 0;
            let bump = move || {
                if first {
                    *LOCK.get_or_init(|| Mutex::new(0)).lock() += 1;
                }
            };
            on_two_threads(&bump);
        });
    }

    #[concurrency::model_test]
    fn a_pipeline_can_be_driven_inside_a_stress_run() {
        let _eal = dpdk::test_support::start_eal();

        let rt = cfg_select! {
            feature = "shuttle" => None::<tokio::runtime::Runtime>,
            _ => Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime")
            )
        };
        let handle = rt.as_ref().map(tokio::runtime::Runtime::handle).cloned();

        concurrency::stress(move || {
            let table = Arc::new(FlowTable::default());
            let sending = table.clone();
            let entering = handle.clone();

            thread::scope(|scope| {
                let sender = thread::Builder::new()
                    .name("sender".to_owned())
                    .spawn_scoped(scope, move || {
                        let _guard = entering.as_ref().map(tokio::runtime::Handle::enter);
                        let mut fabric = Fabric::routed_sharing(&exposes(), None, sending)
                            .unwrap_or_else(|| unreachable!("the fixture exposes do not validate"));
                        let out = fabric.send(tunnelled(&inner()));
                        assert!(
                            matches!(verdict(&out), Verdict::Delivered { .. }),
                            "a packet that is delivered single-threaded was not: {:?}",
                            verdict(&out)
                        );
                    })
                    .expect("spawn sender");

                let reader = thread::Builder::new()
                    .name("reader".to_owned())
                    .spawn_scoped(scope, move || {
                        for _ in 0..3 {
                            let seen = table.len();
                            assert!(seen.is_some(), "the flow table refused a concurrent read");
                            table.for_each_flow(|_, flow| {
                                let _ = flow.status();
                            });
                            thread::yield_now();
                        }
                    })
                    .expect("spawn reader");

                sender.join().expect("sender panicked");
                reader.join().expect("reader panicked");
            });
        });
    }
    fn _a_blueprint_crosses_a_thread_boundary(blueprint: &Blueprint) {
        fn shareable<T: Sync>(_: &T) {}
        shareable(blueprint);
    }

    #[concurrency::model_test]
    fn two_workers_are_not_given_the_same_public_tuple() {
        const FLOWS: u16 = 3;

        let _eal = dpdk::test_support::start_eal();

        let rt = cfg_select! {
            feature = "shuttle" => None::<tokio::runtime::Runtime>,
            _ => Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime")
            )
        };
        let handle = rt.as_ref().map(tokio::runtime::Runtime::handle).cloned();

        concurrency::stress(move || {
            let overlay = overlay_with_exposes_and_acl(exposes(), None)
                .expect("the fixture exposes form an overlay")
                .validate()
                .expect("the fixture overlay validates");
            let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
            let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
            let blueprint = fleet.blueprint();

            let workers = [("1.1.0.1", 1000u16), ("1.1.0.2", 2000u16)];
            let given: Vec<Reported> = thread::scope(|scope| {
                let running: Vec<_> = workers
                    .iter()
                    .map(|(host, first)| {
                        let entering = handle.clone();
                        thread::Builder::new()
                            .name(format!("worker-{host}"))
                            .spawn_scoped(scope, move || {
                                let _guard = entering.as_ref().map(tokio::runtime::Handle::enter);
                                let recording =
                                    tracectl::evidence::capture(format!("worker-{host}"));
                                let mut worker = blueprint.worker();
                                let burst = (0..FLOWS)
                                    .map(|n| {
                                        tunnelled(&build_test_udp_ipv4_packet(
                                            host,
                                            "3.3.3.1",
                                            first + n,
                                            80,
                                        ))
                                    })
                                    .collect();
                                let tuples = worker
                                    .send_batch(burst)
                                    .iter()
                                    .map(|out| {
                                        assert!(
                                            matches!(verdict(out), Verdict::Delivered { .. }),
                                            "a packet that is delivered single-threaded was not: \
                                             {:?}",
                                            verdict(out)
                                        );
                                        let tenant = inside(out).expect(
                                            "a delivered frame leaves this gateway tunnelled",
                                        );
                                        (
                                            tenant.ip_source(),
                                            tenant.transport_src_port().map(std::num::NonZero::get),
                                        )
                                    })
                                    .collect::<Vec<_>>();
                                (tuples, recording.evidence())
                            })
                            .expect("spawn worker")
                    })
                    .collect();
                running
                    .into_iter()
                    .map(|worker| worker.join().expect("worker panicked"))
                    .collect()
            });

            let (given, evidence): (Vec<Vec<Tuple>>, Vec<_>) = given.into_iter().unzip();
            let given: Vec<_> = given.into_iter().flatten().collect();
            let _explain = tracectl::evidence::dump_on_panic(evidence);

            let mut seen = std::collections::BTreeMap::new();
            for tuple in &given {
                let count: &mut usize = seen.entry(format!("{tuple:?}")).or_default();
                *count += 1;
                assert_eq!(
                    *count,
                    1,
                    "{} distinct flows were translated and {tuple:?} was handed out twice, so a \
                     reply to it cannot be attributed to either of them: {given:?}",
                    given.len()
                );
            }
        });
    }

    #[concurrency::model_test]
    fn generated_traffic_survives_being_split_across_two_workers() {
        const CASES: usize = 64;

        static SPLIT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static THIN: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let _eal = dpdk::test_support::start_eal();

        let rt = cfg_select! {
            feature = "shuttle" => None::<tokio::runtime::Runtime>,
            _ => Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime")
            )
        };
        let handle = rt.as_ref().map(tokio::runtime::Runtime::handle).cloned();

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(generated::Generated)
            .with_iterations(CASES)
            .for_each(|(ops, vary, schedule)| {
                let validated = Sequence::fold(ops)
                    .overlay()
                    .unwrap_or_else(|e| panic!("{ops:?} does not assemble: {e}"))
                    .validate()
                    .unwrap_or_else(|e| panic!("{ops:?} does not validate: {e}"));

                let vnis: Vec<Vni> = validated
                    .vpc_table()
                    .values()
                    .map(config::external::overlay::vpc::ValidatedVpc::vni)
                    .collect();
                if vnis.is_empty() || loads_for(&validated, vary).len() < 2 {
                    THIN.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                SPLIT.fetch_add(1, Ordering::Relaxed);

                let drawn = std::sync::Arc::new((validated, vnis, vary.clone(), schedule.clone()));
                let entering = handle.clone();

                concurrency::stress(move || {
                    let (validated, vnis, vary, schedule) = &*drawn;
                    let tables = topology(vnis);
                    let fleet =
                        Fleet::lowering(validated, Some(&tables), Arc::new(FlowTable::default()));
                    let blueprint = fleet.blueprint();

                    thread::scope(|scope| {
                        let running: Vec<_> = (0..2)
                            .map(|which| {
                                let entering = entering.clone();
                                thread::Builder::new()
                                    .name(format!("worker-{which}"))
                                    .spawn_scoped(scope, move || {
                                        let _guard =
                                            entering.as_ref().map(tokio::runtime::Handle::enter);
                                        let _evidence =
                                            tracectl::evidence::capture(format!("worker-{which}"));
                                        let mut worker = blueprint.worker();
                                        let mut mine: Vec<Box<dyn Load>> =
                                            loads_for(validated, vary)
                                                .into_iter()
                                                .enumerate()
                                                .filter(|(nth, _)| nth % 2 == which)
                                                .map(|(_, load)| load)
                                                .collect();
                                        run_schedule(&mut worker, &mut mine, schedule);
                                    })
                                    .expect("spawn worker")
                            })
                            .collect();
                        for worker in running {
                            worker.join().expect("worker panicked");
                        }
                    });
                });
            });

        let (split, thin) = (SPLIT.load(Ordering::Relaxed), THIN.load(Ordering::Relaxed));
        eprintln!("split={split} thin={thin}");
        super::assert_covered(
            split > 0,
            "no drawn configuration ever implied enough traffic to load two workers, so this ran \
             nothing concurrently",
        );
    }

    fn step(worker: &mut Worker, load: &mut dyn Load) {
        let Some(packet) = load.next() else {
            panic!(
                "a load was asked for a packet it would not give: {}",
                load.describe()
            );
        };
        let out = worker.send(packet);
        load.observe(&out);
    }

    #[concurrency::model_test]
    fn a_reply_is_translated_by_a_worker_that_never_saw_the_request() {
        const FLOWS: u8 = 2;

        static CLOSED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static ABANDONED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let _eal = dpdk::test_support::start_eal();

        let rt = cfg_select! {
            feature = "shuttle" => None::<tokio::runtime::Runtime>,
            _ => Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime")
            )
        };
        let handle = rt.as_ref().map(tokio::runtime::Runtime::handle).cloned();

        concurrency::stress(move || {
            let overlay = overlay_with_exposes_and_acl(exposes(), None)
                .expect("the fixture exposes form an overlay")
                .validate()
                .expect("the fixture overlay validates");
            let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
            let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
            let blueprint = fleet.blueprint();
            let entering = handle.clone();

            let mut opened: Vec<Vec<Conversation>> = thread::scope(|scope| {
                let running: Vec<_> = (0..2u8)
                    .map(|which| {
                        let entering = entering.clone();
                        thread::Builder::new()
                            .name(format!("open-{which}"))
                            .spawn_scoped(scope, move || {
                                let _guard = entering.as_ref().map(tokio::runtime::Handle::enter);
                                let _evidence =
                                    tracectl::evidence::capture(format!("open-{which}"));
                                let mut worker = blueprint.worker();
                                (0..FLOWS)
                                    .map(|nth| {
                                        let src = format!("1.1.{which}.{}", nth + 1);
                                        let mut convo = Conversation::new(
                                            super::routed::Path::fixture(),
                                            src.parse().unwrap_or_else(|e| {
                                                unreachable!("{src} is an address: {e}")
                                            }),
                                            "3.3.3.1"
                                                .parse()
                                                .unwrap_or_else(|e| unreachable!("{e}")),
                                            u16::from(nth) + 1000,
                                            80,
                                        );
                                        step(&mut worker, &mut convo);
                                        convo
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .expect("spawn opener")
                    })
                    .collect();
                running
                    .into_iter()
                    .map(|opener| opener.join().expect("opener panicked"))
                    .collect()
            });

            let second = opened
                .pop()
                .unwrap_or_else(|| unreachable!("two openers ran"));
            let first = opened
                .pop()
                .unwrap_or_else(|| unreachable!("two openers ran"));

            let answered: Vec<Vec<Conversation>> = thread::scope(|scope| {
                let running: Vec<_> = [(0u8, second), (1u8, first)]
                    .into_iter()
                    .map(|(which, mut theirs)| {
                        let entering = entering.clone();
                        thread::Builder::new()
                            .name(format!("answer-{which}"))
                            .spawn_scoped(scope, move || {
                                let _guard = entering.as_ref().map(tokio::runtime::Handle::enter);
                                let _evidence =
                                    tracectl::evidence::capture(format!("answer-{which}"));
                                let mut worker = blueprint.worker();
                                for convo in &mut theirs {
                                    if !convo.finished() {
                                        step(&mut worker, convo);
                                    }
                                }
                                theirs
                            })
                            .expect("spawn answerer")
                    })
                    .collect();
                running
                    .into_iter()
                    .map(|answerer| answerer.join().expect("answerer panicked"))
                    .collect()
            });

            for convo in answered.into_iter().flatten() {
                if convo.checked() {
                    CLOSED.fetch_add(1, Ordering::Relaxed);
                } else {
                    ABANDONED.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let (closed, abandoned) = (
            CLOSED.load(Ordering::Relaxed),
            ABANDONED.load(Ordering::Relaxed),
        );
        eprintln!("closed={closed} abandoned={abandoned}");
        super::assert_covered(
            closed > 0,
            "no conversation was ever answered by the other worker, so nothing crossed",
        );
    }

    fn unreachable(
        code: net::icmp4::Icmp4DestUnreachable,
        public: (IpAddr, u16),
        target: IpAddr,
    ) -> Packet<TestBuffer> {
        let (IpAddr::V4(public_v4), IpAddr::V4(target_v4)) = (public.0, target) else {
            unreachable!("the fixture is v4 throughout")
        };
        let inner =
            net::packet::test_utils::build_test_icmp4_destination_unreachable_packet_with_code(
                code,
                net::packet::test_utils::IcmpErrorAddrs {
                    outer_src: target_v4,
                    outer_dst: public_v4,
                    inner_src: public_v4,
                    inner_dst: target_v4,
                },
                net::ip::NextHeader::UDP,
                public.1,
                80,
            )
            .unwrap_or_else(|e| unreachable!("the icmp error builds: {e:?}"));
        super::routed::tunnelled_from(vni(REMOTE_VNI), &inner)
    }

    #[concurrency::model_test]
    fn an_icmp_teardown_leaves_another_workers_flow_alone() {
        static REPORTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static SURVIVED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let _eal = dpdk::test_support::start_eal();

        let rt = cfg_select! {
            feature = "shuttle" => None::<tokio::runtime::Runtime>,
            _ => Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime")
            )
        };
        let handle = rt.as_ref().map(tokio::runtime::Runtime::handle).cloned();

        concurrency::stress(move || {
            let target: IpAddr = "3.3.3.1".parse().unwrap_or_else(|e| unreachable!("{e}"));

            for (code, tears_down) in [
                (net::icmp4::Icmp4DestUnreachable::Network, true),
                (
                    net::icmp4::Icmp4DestUnreachable::FragmentationNeeded {
                        next_hop_mtu: Some(1400.try_into().unwrap_or_else(|_| unreachable!())),
                    },
                    false,
                ),
            ] {
                let overlay = overlay_with_exposes_and_acl(exposes(), None)
                    .expect("the fixture exposes form an overlay")
                    .validate()
                    .expect("the fixture overlay validates");
                let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
                let fleet =
                    Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
                let blueprint = fleet.blueprint();
                let entering = handle.clone();

                let opening = entering.clone();
                let answering = entering.clone();
                let (doomed, mut spared): ((IpAddr, u16), Conversation) = thread::scope(|scope| {
                    let doomed = thread::Builder::new()
                        .name("open-doomed".to_owned())
                        .spawn_scoped(scope, move || {
                            let _guard = opening.as_ref().map(tokio::runtime::Handle::enter);
                            let _evidence = tracectl::evidence::capture("open-doomed");
                            let mut worker = blueprint.worker();
                            let request = super::round_trip::udp(
                                "1.1.0.1".parse().unwrap_or_else(|e| unreachable!("{e}")),
                                target,
                                1000,
                                80,
                            )
                            .unwrap_or_else(|| unreachable!("the fixture request builds"));
                            let out = worker.send(tunnelled(&request));
                            let carried = inside(&out).unwrap_or_else(|| {
                                unreachable!(
                                    "the request was not delivered tunnelled: {:?}",
                                    verdict(&out)
                                )
                            });
                            let (Some(public), Some(port)) =
                                (carried.ip_source(), carried.transport_src_port())
                            else {
                                unreachable!("a delivered request had no public tuple")
                            };
                            (public, port.get())
                        })
                        .expect("spawn opener");

                    let spared = thread::Builder::new()
                        .name("open-spared".to_owned())
                        .spawn_scoped(scope, move || {
                            let _guard = answering.as_ref().map(tokio::runtime::Handle::enter);
                            let _evidence = tracectl::evidence::capture("open-spared");
                            let mut worker = blueprint.worker();
                            let mut convo = Conversation::new(
                                super::routed::Path::fixture(),
                                "1.1.0.2".parse().unwrap_or_else(|e| unreachable!("{e}")),
                                target,
                                2000,
                                80,
                            );
                            step(&mut worker, &mut convo);
                            convo
                        })
                        .expect("spawn opener");

                    (
                        doomed.join().expect("opener panicked"),
                        spared.join().expect("opener panicked"),
                    )
                });

                let tearing = entering.clone();
                let keeping = entering.clone();
                let named = format!("{code:?}");
                let spared = thread::scope(|scope| {
                    let teardown = thread::Builder::new()
                        .name("teardown".to_owned())
                        .spawn_scoped(scope, move || {
                            let _guard = tearing.as_ref().map(tokio::runtime::Handle::enter);
                            let _evidence = tracectl::evidence::capture("teardown");
                            let mut worker = blueprint.worker();
                            let out = worker.send(unreachable(code, doomed, target));
                            matches!(verdict(&out), Verdict::Delivered { .. })
                        })
                        .expect("spawn teardown");

                    let answer = thread::Builder::new()
                        .name("answer".to_owned())
                        .spawn_scoped(scope, move || {
                            let _guard = keeping.as_ref().map(tokio::runtime::Handle::enter);
                            let _evidence = tracectl::evidence::capture("answer");
                            let mut worker = blueprint.worker();
                            step(&mut worker, &mut spared);
                            spared
                        })
                        .expect("spawn answer");

                    assert!(
                        teardown.join().expect("teardown panicked"),
                        "the icmp error never reached the flow it named, so this raced against \
                         nothing"
                    );
                    REPORTED.fetch_add(1, Ordering::Relaxed);
                    answer.join().expect("answer panicked")
                });

                assert!(
                    spared.checked(),
                    "a flow was disturbed by an icmp teardown of a different flow on another \
                     worker. {}",
                    spared.describe()
                );
                SURVIVED.fetch_add(1, Ordering::Relaxed);

                let mut worker = blueprint.worker();
                let reply = super::round_trip::udp(target, doomed.0, 80, doomed.1)
                    .unwrap_or_else(|| unreachable!("the reply builds"));
                let out = worker.send(super::routed::tunnelled_from(vni(REMOTE_VNI), &reply));
                let delivered = matches!(verdict(&out), Verdict::Delivered { .. });
                assert_eq!(
                    delivered,
                    !tears_down,
                    "an icmp error with code {named} left the flow it named {}: {:?}",
                    if delivered { "alive" } else { "torn down" },
                    verdict(&out)
                );
            }
        });

        let (reported, survived) = (
            REPORTED.load(Ordering::Relaxed),
            SURVIVED.load(Ordering::Relaxed),
        );
        eprintln!("reported={reported} survived={survived}");
        super::assert_covered(reported > 0, "no icmp error ever reached the flow it named");
    }

    #[concurrency::model_test]
    fn forwarding_survives_a_route_being_republished_underneath_it() {
        const FLOWS: u8 = 2;
        const CHURN: u8 = 6;

        static COMPLETED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PUBLISHED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let _eal = dpdk::test_support::start_eal();

        let rt = cfg_select! {
            feature = "shuttle" => None::<tokio::runtime::Runtime>,
            _ => Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime")
            )
        };
        let handle = rt.as_ref().map(tokio::runtime::Runtime::handle).cloned();

        concurrency::stress(move || {
            let overlay = overlay_with_exposes_and_acl(exposes(), None)
                .expect("the fixture exposes form an overlay")
                .validate()
                .expect("the fixture overlay validates");
            let mut tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
            let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
            let blueprint = fleet.blueprint();
            let entering = handle.clone();
            let start = Arc::new(concurrency::sync::Barrier::new(3));

            thread::scope(|scope| {
                let running: Vec<_> = (0..2u8)
                    .map(|which| {
                        let entering = entering.clone();
                        let start = start.clone();
                        thread::Builder::new()
                            .name(format!("forward-{which}"))
                            .spawn_scoped(scope, move || {
                                let _guard = entering.as_ref().map(tokio::runtime::Handle::enter);
                                let _evidence =
                                    tracectl::evidence::capture(format!("forward-{which}"));
                                let mut worker = blueprint.worker();
                                start.wait();
                                let mut done = 0u64;
                                for nth in 0..FLOWS {
                                    let src = format!("1.1.{which}.{}", nth + 1);
                                    let mut convo = Conversation::new(
                                        super::routed::Path::fixture(),
                                        src.parse().unwrap_or_else(|e| unreachable!("{src}: {e}")),
                                        "3.3.3.1".parse().unwrap_or_else(|e| unreachable!("{e}")),
                                        u16::from(nth) + 1000,
                                        80,
                                    );
                                    drive(&mut worker, &mut convo);
                                    assert!(
                                        convo.checked(),
                                        "a conversation did not complete while routes were being \
                                         republished. {}",
                                        convo.describe()
                                    );
                                    done += 1;
                                }
                                done
                            })
                            .expect("spawn forwarder")
                    })
                    .collect();

                let peer: IpAddr = PEER_VTEP.parse().unwrap_or_else(|_| unreachable!());
                let landing =
                    FibGroup::with_entry(FibEntry::with_inst(PktInstruction::Local(uplink())));
                start.wait();
                for nth in 0..CHURN {
                    let prefix = format!("9.9.{nth}.0");
                    tables.route_via(
                        UNDERLAY_VRF,
                        Prefix::expect_from((
                            prefix
                                .parse::<IpAddr>()
                                .unwrap_or_else(|e| unreachable!("{e}")),
                            24,
                        )),
                        nhop(&peer),
                        &landing,
                    );
                    PUBLISHED.fetch_add(1, Ordering::Relaxed);
                }

                for worker in running {
                    COMPLETED.fetch_add(
                        worker.join().expect("forwarder panicked"),
                        Ordering::Relaxed,
                    );
                }
            });
        });

        let (completed, published) = (
            COMPLETED.load(Ordering::Relaxed),
            PUBLISHED.load(Ordering::Relaxed),
        );
        eprintln!("completed={completed} published={published}");
        super::assert_covered(
            completed > 0 && published > 0,
            "either no conversation completed or no route was published, so nothing was raced",
        );
    }

    #[concurrency::model_test]
    fn a_next_hop_that_moves_is_never_seen_half_moved() {
        const CHURN: u8 = 3;
        const PER_ROUND: u8 = 2;

        static FRESH: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static STALE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        type Seen = Result<u8, String>;

        fn waypoint(nth: u8) -> (IpAddr, InterfaceIndex) {
            if nth == 0 {
                (
                    PEER_VTEP.parse().unwrap_or_else(|_| unreachable!()),
                    uplink(),
                )
            } else {
                (
                    IpAddr::from([10, 0, 0, nth]),
                    InterfaceIndex::try_new(UPLINK + u32::from(nth))
                        .unwrap_or_else(|_| unreachable!()),
                )
            }
        }

        fn framing(nth: u8) -> Mac {
            Mac([0x02, 0, 0, 0, 0x11, nth])
        }

        fn towards(nth: u8) -> FibGroup {
            let (remote, oif) = waypoint(nth);
            let mut out = FibEntry::with_inst(PktInstruction::Encap(ResolvedEncapsulation::Vxlan(
                ResolvedVxlan {
                    vni: vni(REMOTE_VNI),
                    remote,
                    dmac: framing(nth),
                },
            )));
            out.add(PktInstruction::Egress(EgressObject::new(
                Some(oif),
                Some(remote),
            )));
            FibGroup::with_entry(out)
        }

        let _eal = dpdk::test_support::start_eal();

        let rt = cfg_select! {
            feature = "shuttle" => None::<tokio::runtime::Runtime>,
            _ => Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime")
            )
        };
        let handle = rt.as_ref().map(tokio::runtime::Runtime::handle).cloned();

        concurrency::stress(move || {
            let overlay = overlay_with_exposes_and_acl(exposes(), None)
                .expect("the fixture exposes form an overlay")
                .validate()
                .expect("the fixture overlay validates");
            let mut tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
            for nth in 1..=CHURN {
                let (_, oif) = waypoint(nth);
                tables.interface(
                    oif,
                    &format!("uplink-{nth}"),
                    SourceMac::new(framing(nth)).unwrap_or_else(|_| unreachable!()),
                );
                tables.attach(oif, UNDERLAY_VRF);
            }
            for to in 0..=CHURN {
                for over in 0..=CHURN {
                    tables.adjacency(waypoint(to).0, waypoint(over).1, framing(to));
                }
            }
            let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
            let blueprint = fleet.blueprint();
            let entering = handle.clone();
            let gate = Arc::new(concurrency::sync::Barrier::new(3));
            let mut reports = Vec::new();

            thread::scope(|scope| {
                let running: Vec<_> = (0..2u8)
                    .map(|which| {
                        let entering = entering.clone();
                        let gate = gate.clone();
                        thread::Builder::new()
                            .name(format!("probe-{which}"))
                            .spawn_scoped(scope, move || {
                                let _guard = entering.as_ref().map(tokio::runtime::Handle::enter);
                                let _evidence =
                                    tracectl::evidence::capture(format!("probe-{which}"));
                                let mut worker = blueprint.worker();

                                let mut port = u16::from(which) * 1000 + 1000;
                                let send = |worker: &mut Worker, port: &mut u16| -> Seen {
                                    *port += 1;
                                    let src = format!("1.1.{which}.1");
                                    let out = worker.send(tunnelled(&build_test_udp_ipv4_packet(
                                        &src, "3.3.3.1", *port, 80,
                                    )));
                                    let Verdict::Delivered {
                                        oif: Some(oif),
                                        dst: Some(dst),
                                        ..
                                    } = verdict(&out)
                                    else {
                                        return Err(format!(
                                            "it did not leave the gateway: {:?}",
                                            verdict(&out)
                                        ));
                                    };
                                    (0..=CHURN)
                                        .find(|nth| waypoint(*nth) == (dst, oif))
                                        .ok_or_else(|| {
                                            format!(
                                                "it left over interface {oif} towards {dst}, which \
                                                 is no published next hop: either the \
                                                 encapsulation and the egress came from different \
                                                 versions, or the group was read while it was \
                                                 being written"
                                            )
                                        })
                                };

                                gate.wait();
                                let mut seen = Vec::with_capacity(
                                    usize::from(CHURN) * usize::from(PER_ROUND) + 1,
                                );
                                for _ in 1..=CHURN {
                                    for _ in 0..PER_ROUND {
                                        seen.push(send(&mut worker, &mut port));
                                    }
                                    gate.wait();
                                }
                                seen.push(send(&mut worker, &mut port));
                                seen
                            })
                            .expect("spawn prober")
                    })
                    .collect();

                let key = nhop(&PEER_VTEP.parse().unwrap_or_else(|_| unreachable!()));
                gate.wait();
                for round in 1..=CHURN {
                    tables.nexthop(REMOTE_VNI, &key, &towards(round));
                    gate.wait();
                }

                for prober in running {
                    reports.push(prober.join().expect("prober panicked"));
                }
            });

            for seen in reports {
                for (nth, observed) in seen.iter().enumerate() {
                    let last = nth == seen.len() - 1;
                    let round = if last {
                        CHURN
                    } else {
                        u8::try_from(nth).unwrap_or_else(|_| unreachable!()) / PER_ROUND + 1
                    };
                    let version = match observed {
                        Ok(version) => *version,
                        Err(why) => panic!(
                            "a probe sent in round {round}, while the next hop was moving, is not \
                             attributable to any version: {why}"
                        ),
                    };
                    if last {
                        assert_eq!(
                            version, CHURN,
                            "a probe sent after the churn had finished was forwarded by version \
                             {version}, not by version {CHURN}, the last one published. Every \
                             publish returned before the barrier that released this probe, so a \
                             reader still serving an earlier version is serving a next hop that \
                             no longer exists"
                        );
                        continue;
                    }
                    assert!(
                        version == round || version + 1 == round,
                        "a probe sent in round {round} was forwarded by version {version}. \
                         Version {} was published before this round opened, so no reader may \
                         still be serving anything older, and version {round} is the newest that \
                         exists",
                        round - 1
                    );
                    if version == round {
                        FRESH.fetch_add(1, Ordering::Relaxed);
                    } else {
                        STALE.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        let (fresh, stale) = (FRESH.load(Ordering::Relaxed), STALE.load(Ordering::Relaxed));
        eprintln!("fresh={fresh} stale={stale}");
        super::assert_covered(
            fresh > 0,
            "no probe was ever forwarded by the version published in its own round, so the publish \
             never once landed inside the window it was racing",
        );
    }
}
