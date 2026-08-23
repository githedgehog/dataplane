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
//! `Fabric::build` wires that slice alone; `Fabric::routed` wires the whole pipeline, `Ingress`,
//! both `IpForwarder`s and `Egress` included, over the underlay in `topology`. The difference is
//! whether a packet's arrival is stamped or earned -- see the `routed` module.
//!
//! Building the underlay needs the three tables those stages read populated to a known shape,
//! which is what `routing::testing::RouterTables` is for.
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
//! - Removing the VLAN guard in `IpForwarder` fails `a_vlan_tag_is_refused_at_decapsulation`, and
//!   *not* `a_tagged_shape_never_reaches_the_wire`, because the filters refuse the shape too. Two
//!   properties about one behaviour, kept apart on purpose: one says where the decision is made,
//!   the other says what the gateway does. Only the first can notice a layer going missing.
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

/// The write side of a configuration: the handles that keep its tables alive.
///
/// Every writer is held here for as long as any pipeline built from it runs. Dropping one tears
/// down the data it published, so a fleet that let a writer go would be a pipeline whose
/// configuration silently emptied. Nothing reads a `Fleet`; it exists to be held.
///
/// Kept apart from the pipeline because one configuration has to be able to feed *several*
/// pipelines. That is how production works -- `start_router` builds the writers once and hands
/// every worker a builder closure -- and it is not a stylistic choice: see [`Blueprint`] for why
/// a built pipeline cannot cross a thread boundary. A `Fleet` cannot cross one either, because
/// `RouterTables` is neither `Send` nor `Sync`, so it stays on the thread that made it and the
/// blueprint is what travels.
pub(crate) struct Fleet {
    _flow_filter: FlowFilterContextWriter,
    _acl: AclFilterContextWriter,
    _static_nat: NatTablesWriter,
    _portfw: PortFwTableWriter,
    _masquerade: NatAllocatorWriter,
    blueprint: Blueprint,
}

/// The read side of a configuration: everything a pipeline is built *from*.
///
/// A built pipeline cannot be handed to a thread. `DynPipeline` holds `dyn DynNetworkFunction`,
/// which is not `Send`, and underneath that the fib readers cache an `Rc<UnsafeCell<FibGroup>>`
/// per thread; the readers themselves are neither `Send` nor `Sync` for the same reason. The only
/// thing in the whole arrangement that crosses a thread boundary is a *factory*, on which the
/// receiving thread calls `handle()` locally. That is why `start_router` gives each worker a
/// builder closure rather than a pipeline, and it is why this type exists rather than a `Clone`
/// on [`Fabric`].
///
/// So: build a `Fleet` on one thread, share `&Blueprint` with as many as you like, and let each
/// call [`Blueprint::worker`] on itself.
pub(crate) struct Blueprint {
    flow_filter: FlowFilterContextReaderFactory,
    acl: AclFilterContextReaderFactory,
    static_nat: NatTablesReaderFactory,
    portfw: PortFwTableReaderFactory,
    masquerade: NatAllocatorReaderFactory,
    /// The underlay factories, or `None` for an overlay-slice fabric. The four stages that read
    /// them are added as a group, so they are present or absent together.
    underlay: Option<Underlay>,
    /// Shared by every worker, exactly as `start_router` shares one table across every pipeline it
    /// builds. This is the sharing the model tests are about.
    flow_table: Arc<FlowTable>,
    /// The configuration's public ranges, for each worker's [`Translations`] to judge against.
    declared: Arc<[Prefix]>,
}

/// The three underlay factories, kept together because the stages that read them are.
struct Underlay {
    interfaces: IfTableReaderFactory,
    fibs: FibTableReaderFactory,
    adjacencies: AtableReaderFactory,
}

/// One pipeline and the state that belongs to the thread driving it.
///
/// A worker's [`Translations`] is its own even though the flow table is shared, because that
/// record is scoped to a *burst*: [`Worker::send_batch`] clears it, and a second worker clearing
/// the first one's record mid-burst would turn correct behaviour into a failure. `next_id` is
/// per-worker for the same reason -- ids only have to distinguish packets within the record that
/// reads them.
pub(crate) struct Worker {
    pipeline: DynPipeline<TestBuffer>,
    /// Shared with the two checkpoints straddling masquerade, so a burst can be given a clean one.
    translations: Arc<Mutex<Translations>>,
    /// Distinguishes the packets this worker has been given, for those checkpoints.
    next_id: u64,
}

/// A configured overlay pipeline, and the handles that keep its tables alive.
///
/// A [`Fleet`] with a single [`Worker`], which is what every single-threaded property here wants.
/// The split behind it only shows through when a test needs two.
pub(crate) struct Fabric {
    /// Held because the fib writers live in here, and a fib whose writer is dropped is torn down.
    /// The [`Fleet`] only borrowed them, to take out reader factories.
    _tables: Option<RouterTables>,
    fleet: Fleet,
    worker: Worker,
}

impl Fleet {
    /// Lower a validated overlay into tables, and hold the writers.
    ///
    /// The lowering steps are `expect` rather than `?`: a configuration that validates and then
    /// cannot be lowered is a defect, not a rejected input. Rejection happens earlier, at
    /// `validate`.
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
        // Randomised port selection would make two runs of one configuration disagree on every
        // flow, which is legitimate behaviour and useless to compare.
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

    /// What a worker thread needs to build itself a pipeline over this configuration.
    pub(crate) fn blueprint(&self) -> &Blueprint {
        &self.blueprint
    }
}

impl Blueprint {
    /// Build a pipeline over this configuration, on the calling thread.
    ///
    /// Call this *from* the thread that will drive it. The readers it takes out are thread-local
    /// caches; a pipeline built here and moved elsewhere is the thing the type system already
    /// refuses, and the reason it refuses is not a formality.
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
    /// Send one packet through, and hand back what came out.
    ///
    /// A stage may drop a packet but must not lose it: `enforce` keeps a done packet so the reason
    /// can be read, and a pipeline that returned nothing would be a packet that vanished. That is
    /// asserted here rather than in a property, because every property depends on it.
    pub(crate) fn send(&mut self, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        let mut out = self.send_batch(vec![packet]);
        assert_eq!(out.len(), 1, "the pipeline did not return the packet");
        out.pop().unwrap_or_else(|| unreachable!())
    }

    /// Send several packets through as one burst, and hand back what came out.
    ///
    /// Not the same code path as calling [`Self::send`] repeatedly. `FlowFilter::process` collects
    /// its whole input before doing anything, so that it can pool the classifications into batched
    /// `rte_acl` calls -- which means that in a burst, every packet has been through `FlowLookup`
    /// before any of them reaches the nat stages. This is how the driver actually feeds the
    /// pipeline: one bounded rx burst per poll.
    pub(crate) fn send_batch(
        &mut self,
        mut packets: Vec<Packet<TestBuffer>>,
    ) -> Vec<Packet<TestBuffer>> {
        let sent = packets.len();
        // A fresh identity per packet, and a clean slate per burst: the contract straddling
        // masquerade is about one burst, and carrying a previous burst's allocations into this one
        // would report a legitimately re-allocated flow as a violation.
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
        Self::assemble(exposes, acl, None)
    }

    /// The whole pipeline, not just the overlay slice: `Ingress`, both `IpForwarder`s and `Egress`
    /// as well, over the topology in [`topology`].
    ///
    /// The difference this makes is that a packet has to *earn* its arrival. An overlay-slice
    /// fabric is handed a bare inner packet with [`arrive`] stamping the metadata that
    /// decapsulation would have set; here the metadata is set by decapsulating a real tunnelled
    /// frame, and everything that stamp asserts -- that the vni names a fib, that the frame parses
    /// back, that nothing in it disqualifies it -- is under test rather than assumed.
    pub(crate) fn routed(exposes: &[VpcExpose], acl: Option<&Acl>) -> Option<Self> {
        Self::routed_sharing(exposes, acl, Arc::new(FlowTable::default()))
    }

    /// As [`Self::routed`], over a flow table the caller already holds.
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

    /// A routed fabric over a configuration the caller built, rather than the two-vpc one.
    ///
    /// For properties about *where* a packet goes, which need more than one destination to choose
    /// between. The caller supplies the underlay too, because the vnis it has to be able to
    /// encapsulate into are the ones its own configuration names.
    pub(crate) fn routed_over(overlay: &Overlay, tables: RouterTables) -> Option<Self> {
        Some(Self::over(
            &overlay.clone().validate().ok()?,
            Some(tables),
            Arc::new(FlowTable::default()),
        ))
    }

    /// As [`Self::routed_over`], for a caller that validated once and reuses the result.
    ///
    /// Validation is not cheap and a property that rebuilds a fabric per case would otherwise pay
    /// for it every time, which at ten executions a second is most of the budget.
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

    /// Send one packet through. See [`Worker::send`].
    pub(crate) fn send(&mut self, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        self.worker.send(packet)
    }

    /// Send a burst through. See [`Worker::send_batch`].
    pub(crate) fn send_batch(
        &mut self,
        packets: Vec<Packet<TestBuffer>>,
    ) -> Vec<Packet<TestBuffer>> {
        self.worker.send_batch(packets)
    }

    /// The single pipeline this fabric drives, for [`drive`] and [`run_schedule`].
    pub(crate) fn worker(&mut self) -> &mut Worker {
        &mut self.worker
    }

    /// How many entries the flow table holds, for a property about state rather than packets.
    pub(crate) fn flows(&self) -> Option<usize> {
        self.fleet.blueprint().flow_table.len()
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
    ///
    /// This is what the *overlay slice* produces, because it has no egress stage to hand the
    /// packet to. A routed fabric never returns it.
    Forwarded {
        dst_vpcd: Option<VpcDiscriminant>,
        src: Option<IpAddr>,
        dst: Option<IpAddr>,
    },
    /// Framed and handed to an interface, with what it looked like on the wire.
    ///
    /// `Egress` finishes a packet with `DoneReason::Delivered`, which is a success and not a drop.
    /// Kept distinct from [`Verdict::Dropped`] so that a test cannot assert "not dropped" and
    /// accidentally accept a delivery, or the other way about.
    Delivered {
        oif: Option<InterfaceIndex>,
        src: Option<IpAddr>,
        dst: Option<IpAddr>,
    },
    /// Dropped, with the reason the stage that dropped it gave.
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

/// How many bytes of driver input a property here may draw before it is truncated.
///
/// The default is 4096, and it is not a cap on the *corpus entry* -- it is the point at which
/// `bolero`'s byte driver stops reading and **fills the rest of every draw with zeros**. Nothing
/// fails when that happens. The generator returns a value, the property runs, and the tail of the
/// batch is a run of identical all-zero stacks: shape zero, address zero, port zero. It looks like
/// coverage and is not.
///
/// That matters more here than for the single-value generators elsewhere in the tree, because a
/// batch draws a configuration *and* sixteen header stacks from one input. Measured by
/// [`the_generators_fit_the_input_budget`], `acl::Batch` wanted a median of 3001 bytes and a
/// maximum of 7272 -- so at the default more than half of its inputs were being cut short, and the
/// half being cut were the rich ones: deep chains, extension headers, ipv4 options. The fuzzer was
/// being steered away from complexity at exactly the point complexity begins.
///
/// Sized with room to grow rather than to the measurement: the driver only truncates, so a budget
/// larger than any generator wants costs nothing at all, and a budget that has to be revisited
/// every time a shape is added is a budget nobody will revisit.
///
/// The engine has a separate limit of its own. See `just fuzz` -- raising this constant alone
/// changes nothing under libfuzzer, which will not offer an input longer than its `-max_len`.
pub(crate) const MAX_INPUT_LEN: usize = 65536;

/// The largest number of bytes `generator` drew across `SAMPLES` runs against an unlimited budget.
///
/// Not an exact figure -- a generator's demand is a distribution and this is the top of a sample --
/// which is why [`MAX_INPUT_LEN`] is sized well above what it reports rather than to it.
#[cfg(test)]
fn largest_draw<G: bolero::ValueGenerator>(generator: &G) -> usize {
    use bolero::generator::bolero_generator::driver::{Options, bytes::Driver};

    const SAMPLES: usize = 64;
    /// Larger than any plausible demand, so the measurement is of the generator and not of this.
    const UNLIMITED: usize = 1 << 20;

    let options = Options::default().with_max_len(UNLIMITED);
    // A deterministic stream rather than a random one: the generator needs bytes that vary, and a
    // test whose reported figure moves between runs is one nobody can act on.
    let mut state: u64 = 0x243f_6a88_85a3_08d3;
    let mut bytes = vec![0u8; UNLIMITED];
    (0..SAMPLES)
        .map(|_| {
            for byte in &mut bytes {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                // Truncation is the point: the top bits of an LCG are the ones worth keeping.
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

/// No generator here draws more than [`MAX_INPUT_LEN`], with room to spare.
///
/// The failure this guards against is silent, which is the only reason it is worth a test. A
/// generator that outgrows the budget does not error -- it starts getting zeros, and the property
/// built on it goes on passing while testing less than it says. Enriching a shape is exactly the
/// kind of change that would do it, and exactly the kind nobody would think to re-measure after.
///
/// Called from each module rather than centrally so that each `Batch` can stay private to the
/// module that owns it.
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

/// Assert a coverage guard, naming the one way it fails that is not a defect.
///
/// These guards say a property was not vacuous -- that the inputs actually reached the behaviour
/// under test. There is one benign way to fail them, and it costs an afternoon to work out from
/// first principles: a `__fuzz__` corpus sitting beside this file, left by `just fuzz`.
///
/// `bolero` replays that corpus before it explores randomly, and a coverage-guided corpus is
/// selected for the *unusual* -- entries earn their place by reaching an edge nothing else reached,
/// which in a pipeline means error paths. A large one can consume the whole time budget before the
/// random phase starts, and a run made entirely of interesting inputs can contain no ordinary ones
/// at all. That is the corpus working as designed, and it is not this property failing.
#[cfg(test)]
fn assert_covered(covered: bool, what: &str) {
    assert!(
        covered,
        "{what}. Check for a `__fuzz__` corpus beside this test before reading further: replaying \
         one can spend the budget on inputs chosen for being unusual. Move it aside and re-run to \
         tell that apart from a real gap."
    );
}

/// What a burst has translated so far, shared between the two checkpoints that straddle masquerade.
///
/// Masquerade rewrites the source, so `FlowKey::try_from` on the way out describes the *translated*
/// packet -- a different key per allocation, which is exactly the thing being checked and so no use
/// for grouping. The flow a packet belonged to has to be read before the stage and recognised
/// after, which is what [`TestMeta`] is for and the only reason it exists.
///
/// Scoped to a burst rather than to the fabric, and the difference is not caution. Across bursts a
/// flow may legitimately be invalidated -- by an ICMP error, by a configuration change -- and
/// reallocated to a different port, so a fabric-lifetime memory would report correct behaviour as a
/// violation. Within a burst nothing does: `IcmpErrorHandler` runs ahead of the barrier, so any
/// invalidation it causes has happened before the first allocation of that burst.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Translations {
    /// The flow each packet belonged to before masquerade rewrote it.
    was: std::collections::HashMap<u64, net::FlowKey>,
    /// The source each packet had before masquerade, so a rewrite can be recognised as one.
    from: std::collections::HashMap<u64, IpAddr>,
    /// The public tuple each of those flows has been given in this burst.
    given: std::collections::HashMap<net::FlowKey, (IpAddr, u16)>,
    /// Every address range the configuration declares as public. See [`Translations::after`].
    ///
    /// Shared rather than owned because every worker over one configuration judges against the
    /// same set, and only the per-burst maps above are a worker's own.
    declared: Arc<[Prefix]>,
}

#[cfg(test)]
impl Translations {
    /// Remember which flow this packet belongs to, before the stage that will disguise it.
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

    /// One flow gets one public tuple, however many of its packets are in the burst.
    ///
    /// The defect this exists for: `FlowLookup` stamps each packet with the flow state it found,
    /// `FlowFilter` collects the whole burst before anything downstream runs, so every packet of a
    /// burst was stamped before any of them was masqueraded. Reading only that stamp meant a burst
    /// of sixteen packets of one flow took sixteen ports out of the pool.
    ///
    /// `burst::a_burst_of_one_flow_allocates_once` says the same thing, and this does not replace
    /// it -- that property drives the case deliberately, where this notices it in whatever traffic
    /// any property happens to generate. The property is the alarm you set; this is the one that
    /// goes off in a room nobody was watching.
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

        // A source this stage changed must be one the configuration says it may hand out.
        //
        // Stated as "changed" rather than "is in the pool" because masquerade is not always
        // rewriting the source: on the return path it puts the destination back and leaves the
        // source, which belongs to the far side and is in no pool of ours. A contract phrased the
        // other way would fail on correct reply traffic. Earlier stages that rewrite a source --
        // static nat, and port forwarding on its reverse path -- run ahead of the checkpoint that
        // records `from`, so what is compared here is masquerade's own doing and nothing else's.
        //
        // Reading the ranges out of the configuration is not the allocator's decision procedure
        // written twice: choosing *which* address and port is the allocator's job, and all this
        // asks is that the answer lie in a set the configuration named. A pool built from the
        // wrong prefix, or an allocator handing out an address it does not own, fails it.
        //
        // The limit is that "named" means named *anywhere* in the configuration, so this does not
        // catch one peering's range being handed to another peering's traffic. Narrowing it to the
        // peering the packet belongs to would mean resolving that peering here, which is the flow
        // filter's decision procedure -- and `destination::a_packet_leaves_for_the_vpc_that_
        // exposes_its_destination` is what covers the misrouting this would otherwise catch.
        //
        // It stays reachable because `smoke::the_harness_builds_a_pipeline_that_translates`
        // asserts the fixture masquerades at all; a pipeline that quietly stopped rewriting
        // sources would fail there rather than leave this silently judging nothing.
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

    /// A clean record judging against the ranges the configuration declared.
    fn declaring(declared: &Arc<[Prefix]>) -> Self {
        Self {
            declared: declared.clone(),
            ..Self::default()
        }
    }
}

/// The public ranges of every expose in the configuration, in both directions of every peering.
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

/// Traffic that knows what it sent, and therefore what should come back.
///
/// Every property above builds its packets inline and judges them inline, which works while there
/// is one conversation at a time. It stops working the moment two of them are interleaved: the
/// packets belong to different senders with different expectations, and a loop that generated them
/// cannot also be in the middle of judging them.
///
/// A [`Load`] is one sender. It is a state machine rather than a generator because the properties
/// worth having are *reactive*: a reply has to be addressed to whatever the far side actually saw,
/// which is knowable only after the request has come out the other end. That is also what keeps
/// the oracle honest -- the load is not told what the translation should be, it reads what the
/// translation was and requires it to reverse.
///
/// # The oracle lives here, and that is the point
///
/// The alternative is a global oracle: given this configuration and this interleaving, what should
/// have happened? That is the dataplane written a second time, which is the thing every property in
/// this module is built to avoid. A load judges only its own traffic, against what it itself chose,
/// so the oracle stays local and knowable by construction however many loads are running. The joint
/// claim is then just "every load was satisfied", and it needs no author.
///
/// # Describing itself is not optional
///
/// A failure under interleaved traffic is otherwise unreadable: the input is a schedule, and the
/// packet that failed is one of hundreds. [`Load::describe`] is what turns that back into a
/// sentence, and it is built in from the start rather than added after the first hour lost to it.
#[cfg(test)]
pub(crate) trait Load {
    /// The next packet this load wants to send.
    ///
    /// `None` means it is waiting on an observation, not that it is finished -- ask
    /// [`Load::finished`] for that. A scheduler draining several packets from one load therefore
    /// gets as many as the load can offer without hearing back, which is the load's own
    /// back-pressure rather than a rule the scheduler has to know.
    fn next(&mut self) -> Option<Packet<TestBuffer>>;

    /// Judge what came back for the packet most recently taken from [`Load::next`].
    ///
    /// # Panics
    ///
    /// If what came back is not what this load required. That is the assertion; a load that
    /// returns quietly has accepted the answer.
    fn observe(&mut self, got: &Packet<TestBuffer>);

    /// Whether this load has finished its business, successfully or otherwise.
    fn finished(&self) -> bool;

    /// Whether it got far enough to make the claim it exists to make.
    ///
    /// Separate from [`Load::finished`] because a load can legitimately give up -- a configuration
    /// that does not carry its traffic is not a defect -- and a run made entirely of loads that
    /// gave up is a run that checked nothing. This is what a coverage guard counts.
    fn checked(&self) -> bool;

    /// What this load has done so far, for reading a failure.
    fn describe(&self) -> String;
}

/// Run one load to completion against a fabric, one packet at a time.
///
/// Step A of the load design: enough to rewrite the existing properties on top of the trait and
/// find out whether it expresses them. Interleaving several loads is a scheduler, and comes next.
#[cfg(test)]
pub(crate) fn drive(worker: &mut Worker, load: &mut dyn Load) {
    // A load that neither finishes nor offers a packet is a bug in the load, and an infinite loop
    // is a bad way to report one.
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

/// Which load to draw from, and how many packets to take from it.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pick {
    pub(crate) load: u8,
    pub(crate) take: u8,
}

/// One poll of the driver: whatever several loads had to offer, sent as one burst.
///
/// Deliberately several loads per burst rather than one. A real rx burst carries traffic from
/// everybody at once, and one-load-per-burst would never produce the shape that matters -- a reply
/// for one conversation in the same burst as a request from another. The allocation defect this
/// harness already found lived in exactly that region.
#[cfg(test)]
pub(crate) type Poll = Vec<Pick>;

/// Run a schedule of polls against a set of loads, then let the unfinished ones finish.
///
/// A load offers what it can without hearing back -- `next` returning `None` means waiting, not
/// finished -- so a pick asking for more than a load can give simply gets less. The scheduler needs
/// to know nothing about any load's protocol.
///
/// The tail matters as much as the schedule. A conversation cut off mid-flight has checked nothing,
/// so a run whose schedule happened to be short would be a run that verified almost nothing while
/// looking busy. Draining afterwards means the interleaving decides *when* things happen and the
/// drain decides that they all eventually do.
///
/// Returns which loads each burst actually drew from. Reporting what happened rather than what was
/// asked for is the difference between a coverage guard that means something and one that does not:
/// a poll naming three loads that all had nothing to offer is not an interleaving, and counting the
/// schedule would call it one.
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
        // Order is relied on to route each answer back to the load that sent it. The pipeline
        // preserves it -- `burst::a_burst_is_treated_the_same_as_one_packet_at_a_time` compares
        // element-wise and would fail otherwise -- and `send_batch` asserts the count.
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

/// Traffic a configuration says should work, derived from the configuration itself.
///
/// Every property before this aimed its packets by hand: `1.1.0.5`, `3.3.3.1`, ports chosen to suit
/// the fixture. That works while the fixture is fixed and stops the moment it is not -- a generated
/// configuration exposes prefixes nobody wrote down, and hand-aimed traffic would miss all of them
/// and explore the drop path forever.
///
/// [`loads_for`] closes that: it walks what the configuration advertises and produces, for each
/// expose, a sender carrying the traffic that expose exists to carry. Nothing in it names an
/// address. When the configuration changes, the traffic follows.
///
/// It is deliberately not a model of the dataplane. It reads what the configuration *offers* --
/// which prefixes, which ports, which direction -- and each load then judges only its own traffic
/// against what it itself chose. Deciding what the dataplane should do with that traffic is still
/// nobody's job here.
#[cfg(test)]
pub(crate) mod derive {
    use super::routed::{Blast, Conversation, Inbound};
    use super::*;
    use config::external::overlay::ValidatedOverlay;
    use config::external::overlay::vpcpeering::ValidatedExpose;
    use lpm::prefix::{Prefix, PrefixWithOptionalPorts};

    /// How one sender should vary, drawn by the fuzzer and applied to whatever the config offers.
    ///
    /// Offsets rather than addresses: the configuration decides *where*, this decides *which one*.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Vary {
        pub(crate) host: u8,
        pub(crate) port: u8,
        pub(crate) sport: u16,
        pub(crate) dport: u16,
        pub(crate) burst: u8,
        pub(crate) blast: bool,
    }

    /// The first address of a prefix, offset by `n` within it.
    ///
    /// Stays inside the prefix by masking the offset to its host bits, so a drawn value can never
    /// aim traffic at somebody else's range and turn a coverage question into a routing one.
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

    /// A port inside whatever range an expose declares for a prefix, or any port if it declares
    /// none.
    fn port_in(entry: &PrefixWithOptionalPorts, n: u8, fallback: u16) -> u16 {
        entry.ports().map_or(fallback.max(1), |range| {
            let span = u32::from(range.end()) - u32::from(range.start()) + 1;
            let offset = u32::from(n) % span;
            u16::try_from(u32::from(range.start()) + offset).unwrap_or(range.start())
        })
    }

    /// Where the far side of a peering lives, as the configuration advertises it.
    ///
    /// `usable` is what the far side has to be able to do with the traffic, and skipping it is a
    /// mistake that costs a tenth of the derived senders. A masquerading expose is source NAT and
    /// nothing else -- `can_receive_connection` is false for one -- so a request aimed at its
    /// public range is *correctly* dropped as `Filtered`, and a derivation that aims one there
    /// spends the load on a legitimate refusal while looking exactly like a delivery failure.
    /// Symmetrically, a port-forwarded service is reached *by* the far side, so there the far side
    /// has to be able to initiate.
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

    /// One load per expose the configuration offers, carrying that expose's traffic.
    ///
    /// # A load kind belongs to an expose flavour
    ///
    /// The three kinds are not interchangeable and matching them to the wrong expose produces a
    /// failure that reads as a dataplane fault. A plain [`Conversation`] aimed at a port-forwarded
    /// range is the worked example: if the destination port happens to fall inside the forwarded
    /// window the request *is* delivered, so the load proceeds to reply -- from the external
    /// address, which no host in that vpc owns, because a conversation models a masquerade
    /// round trip where the far side answers from where it was addressed. The pipeline drops that
    /// reply, correctly, and the load reports "the reply of a delivered flow did not reach the
    /// wire". Nothing in the message says the test was asking the wrong question.
    ///
    /// That is why the peer's expose is filtered on what it can actually accept rather than on
    /// whether it is reachable at all. It cost one intermittent failure at about one run in ten to
    /// find, and it would have cost a great deal more to find from the message alone.
    ///
    /// # Panics
    ///
    /// Never; an expose it cannot build traffic for is skipped, which is a gap in this function
    /// rather than a defect in the configuration. [`unsupported`] counts them so the gap is
    /// visible instead of silent.
    pub(crate) fn loads_for(overlay: &ValidatedOverlay, vary: &[Vary]) -> Vec<Box<dyn Load>> {
        let mut loads: Vec<Box<dyn Load>> = Vec::new();
        let mut nth = 0usize;
        for vpc in overlay.vpc_table().values() {
            for peering in vpc.peerings() {
                // Which two vpcs this expose's traffic is between, read off the configuration.
                // A load that assumed the fixture's pair would still pass on a generated overlay
                // whose vpcs happen to be numbered differently, while testing a route nobody
                // configured.
                let path = super::routed::Path::new(vpc.vni(), peering.remote_vni());
                for expose in peering.local().valexp() {
                    let Some(v) = vary.get(nth % vary.len().max(1)).copied() else {
                        continue;
                    };
                    nth += 1;
                    // What the peer must be able to do depends on which way the traffic goes, so
                    // this is drawn per branch rather than once.
                    //
                    // Outward wants a peer expose that will take traffic on *any* port, which is
                    // stricter than `can_receive_connection`: that is only false for masquerade,
                    // and a port-forwarding expose will take traffic only on the ports it forwards.
                    // Aiming an arbitrary port at one is refused, correctly, and the load then
                    // abandons for a reason that has nothing to do with the pipeline.
                    let outward = peer_of(peering, v.host, |expose| {
                        expose.can_receive_connection() && !expose.has_port_forwarding()
                    });
                    let inward = peer_of(peering, v.host, ValidatedExpose::can_init_connection);

                    if expose.has_port_forwarding() {
                        // Reached from outside on the advertised tuple, expected to land on the
                        // internal one at the same offset. Offset-preserving is the mapping the
                        // configuration describes, and it is read off the two prefixes here
                        // rather than looked up in the table the stage reads.
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
                        // Not derived yet. Static NAT maps address to address across two
                        // differently shaped sets of prefixes, so which address a host ends up at
                        // is `RangeBuilder`'s answer rather than one this can read off a pair of
                        // offsets; a default expose names no prefix at all.
                    } else {
                        // Masquerade, or no translation whatever. The same traffic either way --
                        // opened from inside the vpc towards what the far side advertises -- which
                        // is the point: what the expose does to it on the way is the pipeline's
                        // business, and a load that had to know would be a second copy of the
                        // translation to keep correct.
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

/// A stage that changes nothing and checks something.
///
/// The pipeline is a chain of [`NetworkFunction`]s and nothing says a stage has to *do* anything,
/// so a contract between two stages can be a stage. What that buys over asserting at the end of
/// the pipeline is three things: attribution, because a violation names the boundary it happened
/// at; reach, because facts a later stage destroys are visible here and nowhere else -- the inner
/// packet exists only between decapsulation and re-encapsulation, and `dst_vpcd` is set by
/// `FlowFilter` and consumed by `IpForwarder`; and leverage, because a contract asserted here is
/// asserted on every packet of every property in this module rather than needing a property of its
/// own.
///
/// # Two rules, both structural
///
/// **A checkpoint is lazy.** `FlowFilter::process` collects its whole input, and that barrier is
/// what decides which packets can see each other's effects -- it is the mechanism behind the
/// allocation defect in `a_burst_of_one_flow_allocates_once`. A checkpoint that collected would
/// introduce a second barrier and change the behaviour it is supposed to be observing.
///
/// **A checkpoint cannot drop or modify a packet.** Hence `inspect` rather than the `filter_map`
/// and `enforce` every real stage uses: the signature is what enforces it, not a comment. A checkpoint must also not
/// serialize a packet, because `Packet::serialize` recomputes checksums -- an observer that
/// repaired what it was watching for.
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
        // `inspect` rather than `map`: the signature is the guarantee. A checkpoint is handed a
        // shared reference and returns nothing, so it cannot modify a packet, and `inspect` cannot
        // drop one.
        input.inspect(move |packet| (self.check)(self.at, packet))
    }
}

/// The contracts every routed fabric checks at every stage boundary.
///
/// Each is a promise made by the stage before it, taken from that stage's code rather than from
/// what it would be nice for it to do -- a contract a stage does not actually make turns a working
/// pipeline into a failing test, which is worse than no contract at all.
mod contract {
    use super::*;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// How many packets each contract has actually judged, as opposed to waved past its guard.
    ///
    /// A contract is a property, and it goes vacuous the same way: every one here begins by
    /// excusing packets it does not apply to, and a guard that excuses *everything* is a contract
    /// that has never once been evaluated while looking exactly like one that always holds.
    /// [`every_contract_is_reached`] is what says otherwise.
    pub(super) static JUDGED: LazyLock<[AtomicU64; 4]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));

    pub(super) const DECAPSULATED: usize = 0;
    pub(super) const PLACED: usize = 1;
    pub(super) const READY: usize = 2;
    pub(super) const FINISHED: usize = 3;

    fn judged(which: usize) {
        JUDGED[which].fetch_add(1, Ordering::Relaxed);
    }

    /// `IpForwarder` decapsulates and annotates. A frame it has made overlay traffic knows which
    /// vpc it came from and which fib to route it in; the overlay stages downstream read both, and
    /// `arrive` in this module fakes exactly this stamp for the fabrics that skip the forwarder.
    /// So this is also what says that fake is faithful.
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

    /// `FlowFilter` is what decides where a packet goes. A packet it lets past has been given a
    /// destination; one it could not place is dropped, not forwarded.
    ///
    /// `shapes::every_shape_leaves_the_pipeline_with_a_verdict` asserts this at the *end* of the
    /// pipeline, which is weaker: a later stage setting `dst_vpcd` would satisfy it. Here it is a
    /// claim about the stage that owes it.
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

    /// What `Masquerade::process_packet` calls a bug in a `debug_assert` and then drops.
    ///
    /// **This one has no reachable violation today, and that is worth saying rather than leaving
    /// to be discovered.** Every way of removing a discriminant before masquerade is caught by a
    /// stage in between -- `StaticNat` and `PortForwarder` finish such a packet, so it arrives here
    /// already `done` and the guard correctly excuses it. Break-tested: clearing `src_vpcd` in
    /// `FlowFilter` produces `done=true, masq=true, src=None` at this boundary.
    ///
    /// Two different things get confused here and the distinction matters. It is *not vacuous* --
    /// [`super::smoke::every_contract_is_reached`] shows it judges ordinary traffic, so its guard
    /// is not excusing everything. It is *unfalsifiable*, which is a claim about the pipeline
    /// rather than about the contract: no current arrangement of stages can violate it.
    ///
    /// Kept, because what it guards is a reordering. Move masquerade ahead of the stages that
    /// currently catch this, or drop their checks, and this is what notices.
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

    /// `Egress` frames a packet and finishes it, one way or another. A packet leaving it unfinished
    /// is one nothing further will look at and nothing has sent.
    pub(super) fn finished<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        judged(FINISHED);
        assert!(
            packet.is_done(),
            "{at}: a packet left the last stage of the pipeline without a verdict"
        );
    }
}

/// The underlay the routed fabric sits on.
///
/// One uplink, carrying tunnelled traffic in both directions. The addresses are the ones
/// `net`'s vxlan fixture already uses, so that a frame built by
/// `build_test_vxlan_ipv4_packet_carrying` is addressed to this gateway without the test having to
/// rewrite the outer header -- and, more usefully, so that a test that *does* rewrite it is saying
/// something.
pub(crate) const UPLINK: u32 = 1;
/// The address the fixture's tunnelled frames are sent to: this gateway's vtep.
pub(crate) const LOCAL_VTEP: &str = "5.6.7.8";
/// The vtep on the other end, which is both where frames come from and where they go back to.
pub(crate) const PEER_VTEP: &str = "1.2.3.4";
/// This gateway's mac, used as the uplink's and as the vtep's.
pub(crate) const GATEWAY_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0xaa]);
/// The peer's mac, which is what an adjacency for [`PEER_VTEP`] resolves to.
pub(crate) const PEER_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0xbb]);

/// The vrf a tunnelled frame arrives in, before it is anybody's overlay traffic.
const UNDERLAY_VRF: u32 = 0;

pub(crate) fn uplink() -> InterfaceIndex {
    InterfaceIndex::try_new(UPLINK).unwrap_or_else(|_| unreachable!())
}

/// Build the tables the underlay stages read.
///
/// Three fibs. The underlay one has a single host route for this gateway's vtep whose instruction
/// is `Local`, which is what makes `IpForwarder` decapsulate rather than route onward -- the
/// tunnel endpoint is not a special case in the forwarding path, it is a route.
///
/// The two overlay fibs are reached by vni and are deliberately symmetric: each carries an
/// encapsulation back out towards [`PEER_VTEP`]. Both vpcs living behind one remote endpoint is a
/// simplification -- a real fabric would have a vtep per host -- but it is the simplification that
/// keeps the *asymmetry under test* in the pipeline rather than in the topology. A fixture that
/// could only encapsulate one way would make a reply fail for a reason no property is about.
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

    // One fib per vni, each numbered by it: a fib is reached by vni, so a vrf id that is the vni
    // keeps the two from having to be kept in step by hand.
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

/// Give `vrfid` a vtep and a route that tunnels everything leaving it towards [`PEER_VTEP`].
///
/// A default route rather than the peering's translated range: what a masquerading expose turns an
/// address into is the nat stages' business, and a topology that had to agree with them would be a
/// second copy of the translation to keep correct.
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

/// A next hop is only an identity here: it names the group a route resolves to, and the tests
/// install one group per route, so an address is enough to keep them apart.
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

    /// Every contract is actually evaluated by an ordinary routed fabric.
    ///
    /// Each contract begins by excusing packets it does not apply to, so each can go vacuous
    /// without saying so: a guard that excuses everything looks exactly like a contract that always
    /// holds. This runs one packet all the way through and requires all four to have judged it.
    ///
    /// It is also what caught the one that was not being reached. `ready_to_translate` guards on
    /// `requires_masquerade()`, and a fabric whose peering does not masquerade never sets it -- so
    /// the contract sat in the pipeline judging nothing.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn every_contract_is_reached() {
        use net::packet::test_utils::build_test_udp_ipv4_packet;

        let before: Vec<u64> = contract::JUDGED
            .iter()
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
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
            let after = contract::JUDGED[i].load(std::sync::atomic::Ordering::Relaxed);
            assert!(
                after > before[i],
                "the `{name}` contract judged no packet of an ordinary delivered flow: its guard \
                 excuses everything, so it holds without ever having been evaluated"
            );
        }
    }

    /// The same input twice gives the same answer.
    ///
    /// Load-bearing rather than merely reassuring, and worth a test of its own because two things
    /// we rely on quietly assume it. `bolero` diagnoses a failure by shrinking and replaying the
    /// input that produced it, so a pipeline that answered differently on the second run would
    /// shrink towards nothing and report a case that does not fail. And it is what lets diagnosis
    /// be paid for only when something breaks: a failing case can be re-run with as much
    /// instrumentation as it takes, rather than every case being recorded on the chance one of
    /// them will matter.
    ///
    /// Two fabrics rather than one, so what is compared is two *instances* -- the hash-backed
    /// tables inside them are seeded per instance, and an answer that depended on iteration order
    /// would differ here. Verified across separate processes as well, by digesting this scenario
    /// and running it four times: `3525008ad91c215a` every time.
    ///
    /// The scenario includes a burst, because that is the path with cross-packet state and so the
    /// one where an order-dependent answer would hide.
    ///
    /// Its boundary: the harness drives the pipeline from one thread. This says nothing about a
    /// pipeline fed concurrently, and `flow_entry`'s own concurrency tests are what cover that.
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

    /// Everything about a packet's fate that a comparison should notice.
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
            Verdict::Delivered { .. } => {
                unreachable!("the overlay slice has no egress stage")
            }
        }
    }
}

/// Header shapes fed through the whole pipeline.
///
/// The generator here is reused by [`super::routed`], which runs the same shapes through the full
/// pipeline inside a tunnel.
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

    /// Point a generated stack at the configuration, so it has a chance of being forwarded.
    ///
    /// Addresses drawn independently of the overlay miss every table, and a property driven by one
    /// explores the miss path and nothing else -- the argument `nat::static_nat::probe` makes about
    /// packets, applied to whole stacks.
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
            .with_max_len(MAX_INPUT_LEN)
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

    /// A UDP packet, ready to be routed.
    ///
    /// The hop count is set because `Ipv4::default()` and `Ipv6::default()` leave it at zero, and
    /// a packet with no hops left is not traffic anybody sends -- it is a packet that has already
    /// expired. The overlay slice does not care, having no forwarding stage to decrement it, which
    /// is exactly why the omission survived here: `routed`'s properties put the same packets
    /// through `IpForwarder` and every one of them died at the first decrement.
    pub(super) fn udp(
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
    ) -> Option<Packet<TestBuffer>> {
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

/// Traffic arriving on a forwarded port, which nothing else here exercises.
///
/// Every routed property above configures masquerade, so the whole port-forwarding path -- an
/// outside host reaching a service inside a vpc, and that service's replies getting back out under
/// the address the outside host used -- has no end-to-end test at all.
///
/// It is also the only direction in this harness that starts outside. Masquerade traffic
/// originates in the local vpc and is answered; this originates in the peer.
#[cfg(test)]
mod port_forward {
    use super::round_trip::udp;
    use super::routed::{inside, tunnelled_from};
    use super::*;
    use config::external::overlay::vpcpeering::VpcExpose;
    use lpm::prefix::{L4Protocol, PortRange, Prefix, PrefixWithOptionalPorts};
    use net::headers::TryVxlan;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The service range inside the vpc, and the range the outside world reaches it on.
    ///
    /// Sized so that "the right one" is a real question: sixteen hosts and eight ports is 128
    /// distinct targets, and an implementation that ignored either offset would land on the wrong
    /// one almost every time. A /32 and a single port would be satisfied by a rule that forwarded
    /// everything to the only place there is.
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

    /// Somewhere outside to reach in from.
    fn outside() -> IpAddr {
        "3.3.3.7".parse().unwrap_or_else(|_| unreachable!())
    }

    /// One attempt to reach the service.
    #[derive(Debug, Clone, Copy)]
    struct Reach {
        host: u8,
        port: u16,
        src_port: u16,
        /// Aimed at a port the expose does not declare, which must not be forwarded.
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
                        // One in four past the range, so the negative half is exercised without
                        // swamping the positive half.
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

    /// The service answers, from the tuple the request arrived on.
    ///
    /// Split out because the property that calls it is one loop making four assertions and clippy
    /// counts lines rather than claims. Returns whether a reply was checked, so the caller's
    /// coverage guard still counts what happened rather than what was attempted.
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

    /// A forwarded port reaches the host behind it, and answers from the address it was reached on.
    ///
    /// # The oracle
    ///
    /// The mapping is offset-preserving -- external host `k` port `j` is internal host `k` port
    /// `j` -- so the expected internal tuple is arithmetic on the offsets *this test chose*, not a
    /// lookup in the table the stage reads. Same move as `destination`: let the input carry the
    /// answer.
    ///
    /// # Three claims
    ///
    /// - **Forward.** A packet to a declared external address and port arrives at the internal
    ///   address and port that correspond to it. Both offsets are asserted, because a stage that
    ///   translated the address and forgot the port would satisfy either one alone.
    /// - **Back out.** The service's reply leaves under the *external* tuple the outside host
    ///   addressed. This is what makes port forwarding usable rather than merely reachable: a reply
    ///   sourced from the internal address would arrive at an outside host that never spoke to it.
    /// - **Past the range.** A packet to a port the expose does not declare is not forwarded. The
    ///   port is past the top of the range while the address is inside the prefix, so anything
    ///   matching on address alone would forward it. Refused by the *flow filter* rather than the
    ///   port forwarder -- `DoneReason::Filtered`, before nat is consulted -- which is the right
    ///   place for it and is what this half pins down: a lowering that dropped the port dimension
    ///   of a port-forwarding expose would let it through, and the two positive claims above would
    ///   not notice.
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

/// Several conversations at once, in an order the fuzzer chooses.
///
/// The first property here that is about *superposition* rather than about a stage. Every claim
/// above holds for one conversation at a time; this asks whether they still hold when several are
/// in flight together, sharing a flow table, a port pool and a burst.
///
/// It needs no new oracle, and that is the whole argument for the [`Load`] decomposition: each
/// conversation already knows what it sent and therefore what must come back, so the joint claim is
/// just "every one of them was satisfied". Nobody had to write down what N interleaved
/// conversations should do.
#[cfg(test)]
mod interleaved {
    use super::routed::{Blast, Conversation, Path, exposes};
    use super::*;
    use std::ops::Bound::Included;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const LOADS: usize = 6;
    const POLLS: usize = 10;

    /// What kind of sender a slot holds.
    ///
    /// Two kinds rather than one because they stress different things about a burst. A
    /// conversation can only ever offer one packet, so a poll of conversations is a poll of
    /// singletons; a blast offers as many as asked for, which is what makes several packets of one
    /// flow share a burst with somebody else's traffic.
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
        /// How many packets a blast sends. Ignored by a conversation.
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
                    // One to three loads per poll. More than one is the point; the fuzzer still
                    // gets to choose single-load polls, which are the degenerate case and worth
                    // reaching.
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

    /// Interleaving traffic does not stop any of it working.
    ///
    /// What could break it, none of which a single-sender property can reach: state one sender
    /// creates being found by another; two of them given public tuples that collide, so a reply
    /// cannot be attributed; several packets of one flow sharing a burst with somebody else's,
    /// which is the region the allocation defect lived in.
    ///
    /// The guards below are unusually load-bearing, and they count what the run *did* rather than
    /// what its schedule asked for. A poll naming three loads that all had nothing to offer is not
    /// an interleaving; a run of single-load polls is the properties we already had, in a costlier
    /// harness; and a run in which every sender gave up has checked nothing. All three would pass
    /// unguarded.
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
                    // Position decides the host, so distinct senders stay distinct and a collision
                    // between two of them is the pipeline's doing rather than the generator's.
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

/// Whatever a configuration offers, working, and working all at once.
///
/// The step where the traffic stops being hand-aimed. Every property above names its addresses;
/// this one is handed an overlay and asks [`derive::loads_for`] what traffic that overlay claims to
/// carry, then runs all of it interleaved. Nothing in the property names an address, so a change to
/// the configuration changes what is tested without anybody editing the test.
///
/// The configuration here is still fixed. Generating it is the next step and the one this exists to
/// make possible: hand-aimed traffic against a generated config would miss every prefix and explore
/// the drop path forever.
#[cfg(test)]
mod offers {
    use super::derive::{Vary, loads_for};
    use super::*;
    use config::external::overlay::vpcpeering::VpcExpose;
    use config::external::overlay::vpcpeering::contract::overlay_with_exposes;
    use lpm::prefix::{L4Protocol, PortRange, Prefix, PrefixWithOptionalPorts};
    use std::ops::Bound::Included;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const SENDERS: usize = 6;
    const POLLS: usize = 10;

    /// A configuration offering two different things, so the derivation has to tell them apart.
    ///
    /// One masquerade expose -- traffic that opens from inside and is answered -- and one port
    /// forwarding expose -- a service reached from outside. A configuration offering only one kind
    /// would let `loads_for` be right by accident.
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

    /// Everything a configuration offers works, and goes on working when run together.
    ///
    /// The guards are what stop this being weaker than the properties it generalises. A derivation
    /// that produced no loads would pass; one that produced only masquerade loads would pass while
    /// silently dropping the port-forwarding half; and a schedule that never mixed would be the
    /// single-sender properties in a costlier harness. All three are counted.
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
                // Which kinds the derivation actually produced. Counting only the total would let
                // a derivation that silently skipped an entire expose flavour pass, which is the
                // most likely way for `loads_for` to be quietly wrong.
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

/// Traffic derived from a configuration that was itself generated.
///
/// The last link. Everything above starts from a configuration somebody wrote down; here the
/// configuration is drawn as a sequence of operations -- add a vpc, peer two, add an expose, change
/// what it does, remove any of them -- folded into a draft and lowered. Nothing in this module names
/// an address, a vni or a vpc, so the whole thing is a claim about the *mapping* from configuration
/// to behaviour rather than about any configuration in particular.
///
/// What that reaches which a fixture cannot: vpcs with several peerings, peerings whose exposes were
/// added and removed rather than declared, configurations that arrived at their shape by a route
/// including deletion, and vpc numbering that has no relationship to what the loads expect.
#[cfg(test)]
mod generated {
    use super::derive::{Vary, loads_for};
    use super::*;
    use bolero::ValueGenerator;
    use config::external::overlay::algebra::{Op, Sequence};
    use std::ops::Bound::Included;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const SENDERS: usize = 6;
    const POLLS: usize = 8;

    /// A configuration, the traffic to vary it with, and the order to run it in -- one draw.
    ///
    /// Drawn together rather than in three properties because the interesting failures are between
    /// them: an expose the derivation cannot build traffic for, or a schedule that puts two vpcs'
    /// packets in one burst, are both invisible if the configuration is fixed.
    ///
    /// Shared with `model`, which runs the same draw across two workers. One generator rather than
    /// two so that a shape reachable single-threaded is reachable concurrently by construction.
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

    /// Every configuration the algebra can build carries the traffic it says it carries.
    ///
    /// Three claims in one, and they fail in different places so they are worth naming separately:
    ///
    /// - **it lowers.** `Fabric` builds the flow filter, acl, static nat, port forwarding and
    ///   masquerade tables from the validated overlay with `expect`, deliberately: a configuration
    ///   the validator accepted and the dataplane cannot enact is the exact failure the design note
    ///   says must not exist, since there is no channel to tell an operator about it.
    /// - **the derivation finds its traffic.** Counted, because a derivation that quietly produced
    ///   nothing would make everything below vacuous.
    /// - **the traffic behaves.** Each load judges itself, against the vnis the *configuration*
    ///   gave it rather than against a constant.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_generated_configuration_carries_its_own_traffic() {
        static CHECKED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static ABANDONED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
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

                // The topology is built from the vnis the configuration names, so a fib exists for
                // every vpc it can route to. A fixture topology would refuse traffic for vpcs the
                // configuration created, and the refusal would look like a dataplane fault.
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
                    if load.checked() {
                        CHECKED.fetch_add(1, Ordering::Relaxed);
                    } else {
                        ABANDONED.fetch_add(1, Ordering::Relaxed);
                    }
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
            "checked={checked} abandoned={} derived={derived} peered-configs={peered} \
             configs-past-two-vpcs={multi} mixed-bursts={mixed}",
            ABANDONED.load(Ordering::Relaxed)
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

/// A burst, against the same packets sent one at a time.
///
/// The driver hands the pipeline one bounded rx burst per poll, and `FlowFilter::process` collects
/// that burst before doing anything so it can pool its classifications into batched `rte_acl`
/// calls. Every property above sends one packet at a time, so none of them has ever exercised the
/// shape the dataplane actually runs in.
#[cfg(test)]
mod burst {
    use super::round_trip::udp;
    use super::routed::{exposes, inside, tunnelled};
    use super::*;
    use net::headers::TryVxlan;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const BURST: usize = 8;

    /// A flow to send. Distinct by construction -- see the property.
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

    /// What a packet is treated as, in enough detail to compare two runs.
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

    /// A burst carrying several packets of one flow allocates once for it.
    ///
    /// The case [`a_burst_is_treated_the_same_as_one_packet_at_a_time`] excludes by construction,
    /// and the one that was broken. `FlowLookup` stamps each packet with the flow state it found,
    /// `FlowFilter` collects the whole burst before anything downstream runs, so every packet of a
    /// burst is stamped before any of them is masqueraded. Masquerade read only the stamp, so a
    /// burst of sixteen UDP packets of one flow took sixteen ports out of the pool, left the far
    /// side seeing sixteen sources, and put sixteen reverse entries in the flow table. A TCP SYN
    /// and its first data segment in one burst had the data dropped as "TCP without SYN".
    ///
    /// Two things are asserted rather than one, because a fix that translated consistently while
    /// still allocating each time would satisfy the first alone:
    ///
    /// - every packet of the burst leaves with the **same** public source;
    /// - the flow table holds exactly what one flow needs, whatever the size of the burst.
    ///
    /// The second is the one that says the pool is not being drained. It is stated as a
    /// *comparison with a single packet* rather than a number, so it says "a burst costs what one
    /// packet costs" without this test having to know how many entries a flow is made of.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_burst_of_one_flow_allocates_once() {
        static CHECKED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Burst)
            .for_each(|members| {
                // One flow, drawn: which flow varies, that it is one flow does not.
                let m = members[0];
                let src: IpAddr = format!("1.1.0.{}", m.host)
                    .parse()
                    .unwrap_or_else(|_| unreachable!());
                let dst: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
                let packet = || udp(src, dst, 4000, m.dport).map(|p| tunnelled(&p));

                // What one packet of this flow costs, as the baseline the burst must match.
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

    /// A burst is treated the same as the same packets sent one at a time.
    ///
    /// # Why the flows are distinct
    ///
    /// This property is about whether batching preserves *per-packet* behaviour. Several packets
    /// of one flow in a burst is a different question -- how a burst handles a flow it is itself
    /// establishing -- and it has its own property, [`a_burst_of_one_flow_allocates_once`], which
    /// is where the defect that shape hid turned up.
    ///
    /// So the members of a burst are made distinct by construction: one host and one destination
    /// port each, assigned by position rather than drawn. A generator that could draw a collision
    /// would make this property fail intermittently for a reason that is not a defect.
    ///
    /// # What it catches
    ///
    /// The batched `rte_acl` path disagreeing with the single-lookup one, which `flow_filter`'s
    /// own `batched_lookup_matches_single_lookup` checks against a reference and this checks
    /// against the assembled pipeline; a stage that indexes into a burst by position and gets the
    /// position wrong; and any stage that starts leaking state between packets that have nothing
    /// to do with each other.
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
                            // Position decides the flow, so no two members of a burst collide.
                            // The drawn values still vary which flows a run explores.
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

                // Two fabrics rather than one: a fabric that has already seen the packets is not
                // the same fabric, so reusing one would compare a cold pipeline with a warm one
                // and call the difference a batching bug.
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
        // Without this the property is satisfied by two pipelines that drop everything
        // identically, which they would agree about perfectly and say nothing.
        super::assert_covered(
            delivered > 0,
            "no packet of any burst ever reached the wire, so the comparison is between drops",
        );
    }
}

/// Where a packet goes, when there is more than one place it could.
///
/// Every property above runs against one peering, so "was this routed to the right vpc" has only
/// one answer and cannot be got wrong. This module gives the pipeline three destinations and a
/// reason to choose between them.
#[cfg(test)]
mod destination {
    use super::round_trip::udp;
    use super::routed::{inside, tunnelled};
    use super::*;
    use config::external::overlay::vpcpeering::contract::{overlay_with_peers, peer_vni};
    use lpm::prefix::Prefix;
    use net::headers::TryVxlan;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// How many peer vpcs the local one is peered with.
    ///
    /// Three rather than two, so that a stage picking the wrong peer has somewhere wrong to go
    /// that is not simply "the other one" -- an off-by-one in a table walk lands on peer 1 whether
    /// the answer was 0 or 2, and with two peers that is indistinguishable from a swap.
    const PEERS: u8 = 3;

    /// The prefix the local vpc exposes, which every packet here is sent from.
    fn local_prefix() -> Prefix {
        "1.1.0.0/16"
            .parse()
            .unwrap_or_else(|_| unreachable!("a well-formed prefix"))
    }

    /// A packet to send: which peer it is addressed to, and where from.
    #[derive(Debug, Clone, Copy)]
    struct Aim {
        /// `Some(n)` addresses peer `n`; `None` addresses a range no peering covers.
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
                        // One in four aimed nowhere, so the negative half of the claim is
                        // exercised without swamping the positive half.
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

    /// A packet leaves for the vpc that exposes its destination, and for no vpc at all otherwise.
    ///
    /// # Why the oracle is not the flow filter written twice
    ///
    /// The temptation here is to ask the configuration which peering covers the destination, and
    /// that would be worthless: it is the flow filter's own decision procedure, so a filter that
    /// consulted the wrong table would be agreed with rather than caught.
    ///
    /// Instead the answer is built into the address. Peer `n` exposes `10.<n+1>.0.0/16`, so a
    /// destination _names_ the vpc it belongs to, and the expected vni is read off the address the
    /// test itself chose before the pipeline saw it. Nothing here looks at a peering table.
    ///
    /// # What each half catches
    ///
    /// The positive half -- addressed to peer `n`, leaves under peer `n`'s vni -- catches a filter
    /// that finds *a* peering rather than the right one: prefixes loaded into the wrong peering's
    /// table, a lookup returning the first match instead of the longest, a table walk off by one.
    ///
    /// The negative half -- addressed outside every peering, reaches no vpc -- is what stops the
    /// positive half being satisfied by a filter that says yes to everything. Together they are
    /// the claim; either alone is much weaker than it looks.
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
                    // Addressed either inside one peer's advertised /16 or into 172.16/12, which
                    // no peering here covers.
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
                        // The destination must survive too: leaving for the right vpc with a
                        // rewritten address would be a different packet arriving correctly.
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

        // Per peer rather than in total: a run that only ever reached peer 0 would satisfy a total
        // and say nothing about choosing between destinations, which is the whole property.
        for (n, count) in reached.iter().enumerate() {
            super::assert_covered(*count > 0, &format!("peer {n} was never reached"));
        }
        super::assert_covered(
            refused > 0,
            "no packet was ever aimed outside every peering, so the negative half is vacuous",
        );
    }
}

/// The whole pipeline, over a tunnel.
///
/// Everything above this point hands the overlay slice a bare packet and stamps the metadata that
/// decapsulation would have produced. That is the right trade for a property about the overlay
/// stages -- it makes them cheap to run and keeps the failure attributable -- but it means the
/// stamp is an assumption, and the two stages that produce it in production are untested by it.
///
/// This module removes the assumption. A frame arrives on an interface, addressed to this
/// gateway's vtep, and every annotation the overlay stages read is one that `Ingress` and
/// `IpForwarder` actually made.
#[cfg(test)]
mod routed {
    use super::round_trip::udp;
    use super::shapes::{Batch, Shape, aim, wire};
    use super::*;
    use super::{Load, drive};
    use net::buffer::TestBuffer;
    use net::headers::{TryEth, TryHeaders, TryHeadersMut, TryIpv4, TryVxlan};
    use net::ip::dscp::Dscp;
    use net::ip::ecn::Ecn;
    use net::packet::test_utils::{
        build_test_udp_ipv4_packet, build_test_vxlan_ipv4_packet_carrying_vni,
    };
    use net::parse::DeParse;
    use net::vlan::Vid;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A flow to try, as a host in the private range and the ports it uses.
    #[derive(Debug, Clone, Copy)]
    struct Flow {
        host: u8,
        sport: u16,
        dport: u16,
    }

    /// A batch of flows to run against one fabric.
    ///
    /// One configuration rather than a generated one: this property is about the journey, and a
    /// generated peering mostly varies which translation is applied -- which
    /// `round_trip::a_translated_flow_comes_back_to_where_it_started` already explores far more
    /// cheaply at the overlay slice. What is scarce here is executions, so they are spent on flows.
    struct Flows;

    const FLOWS_PER_FABRIC: usize = 8;

    impl bolero::ValueGenerator for Flows {
        type Output = Vec<Flow>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Flow>> {
            (0..FLOWS_PER_FABRIC)
                .map(|_| {
                    Some(Flow {
                        host: driver.produce()?,
                        // Port 0 is not a port; masquerade would refuse it for reasons that have
                        // nothing to do with whether a translation reverses.
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

    /// The one peering every test here uses: a private range masqueraded into a public one.
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

    /// Wrap `inner` in a vxlan frame addressed to this gateway, arriving on the uplink from the
    /// vpc named by `from`.
    ///
    /// The outer addresses come from the fixture rather than from here, and the topology was
    /// chosen to match them. Deliberately: a helper that rewrote the outer header to whatever the
    /// topology wanted could not be used to build a frame the topology should *refuse*.
    /// Which vpc a load's traffic comes from and which it is aimed at.
    ///
    /// Carried rather than assumed because a load derived from a generated configuration has no
    /// reason to be between the two vpcs the hand-written fixtures use. Every assertion about
    /// where a packet went is stated against this pair, so a load that was given the wrong one
    /// fails loudly rather than testing a different question than it claims.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Path {
        pub(crate) from: Vni,
        pub(crate) to: Vni,
    }

    impl Path {
        pub(crate) fn new(from: Vni, to: Vni) -> Self {
            Self { from, to }
        }

        /// The pair the hand-written fixtures use.
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
        // Kept so a drop can be attributed rather than swallowed by `enforce`, as elsewhere here.
        packet.meta_mut().set_keep(true);
        packet
    }

    /// [`tunnelled_from`] for traffic originating in the local vpc, which is most of it.
    pub(super) fn tunnelled(inner: &Packet<TestBuffer>) -> Packet<TestBuffer> {
        tunnelled_from(vni(LOCAL_VNI), inner)
    }

    /// Peel the tunnel off a delivered frame to see the tenant packet inside it.
    ///
    /// Everything a property here wants to say is about the inner packet, and everything the
    /// gateway hands to the wire is an outer one. Returns `None` if what came back was not
    /// tunnelled at all, which is a finding rather than a filter -- callers say so.
    pub(super) fn inside(delivered: &Packet<TestBuffer>) -> Option<Packet<TestBuffer>> {
        let mut copy = delivered.clone();
        matches!(copy.vxlan_decap(), Some(Ok(_))).then_some(copy)
    }

    /// A tenant packet from the private range to somewhere outside it.
    pub(super) fn inner() -> Packet<TestBuffer> {
        build_test_udp_ipv4_packet("1.1.0.1", "3.3.3.1", 1234, 80)
    }

    /// The fixture: the topology forwards, so a test that expects a drop is saying something.
    ///
    /// Every negative test in this module is only as good as this one. A topology with a wrong
    /// route, a missing adjacency or an unattached interface drops *everything*, and each of those
    /// failures reads exactly like the refusal the tests below are looking for.
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

    /// A VLAN tag inside the tunnel is refused at decapsulation, by `IpForwarder`.
    ///
    /// Two stages down to the boundary, so that the refusal is attributed. Reading the code says
    /// the guard is there; what this says is that it is *reached* -- that `Ingress` accepts the
    /// frame, that decapsulation gets far enough to see the inner headers, and that no earlier
    /// stage has already made the decision.
    ///
    /// Break test: removing the `vlan().is_empty()` guard fails this.
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

    /// And, whatever refuses it, it does not leave the gateway.
    ///
    /// Deliberately weaker than the test above and kept anyway, because it is the claim that
    /// matters: the concern was a tag chosen by whoever built the inner frame being carried out
    /// onto whatever segment it names. The two tests differ in what they would survive -- removing
    /// the guard in `IpForwarder` fails the one above and *not* this one, because the overlay
    /// stages match with `Headers::pat` and refuse a shape they were not taught. That redundancy
    /// is the design working (see `development/code/header-chain-matching.md`), and it is also
    /// exactly why a single end-to-end assertion could not have told anyone the guard was gone.
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

    /// [`inner`], with a VLAN tag on it.
    ///
    /// Read back through a serialise/parse round trip rather than trusting `push_vlan`'s effect on
    /// the header struct: what reaches the pipeline is bytes, and a tag that the builder recorded
    /// but did not write would make both tests above pass for the wrong reason.
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

    /// No shape carrying a VLAN tag ever reaches the wire, whatever the configuration.
    ///
    /// The two tests above are one tag, one peering, one route. This is the class: every shape the
    /// [`shapes`] generator produces, tunnelled, over a generated set of exposes. It is the claim
    /// the VLAN work was actually making -- not "this frame is refused" but "a tag chosen by
    /// whoever built the inner frame does not get carried out onto a segment nobody chose".
    ///
    /// What it would take to fail this is losing the class defence entirely, not losing one layer
    /// of it: with the `IpForwarder` guard removed a tagged frame still dies in the filters, with
    /// `DoneReason::Unhandled`, because their patterns do not name a VLAN. The realistic way to
    /// fail it is somebody naming one there to make a drop go away -- step five of the checklist in
    /// `development/code/header-chain-matching.md` without steps two through four.
    ///
    /// [`shapes`]: super::shapes
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_tagged_shape_never_reaches_the_wire() {
        static DELIVERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
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
                    // The tag is read off the shape rather than off the packet that comes back:
                    // a delivered packet has been re-encapsulated, so its headers are the outer
                    // ones and any inner tag is no longer visible from here. Asking the output
                    // would be asking the wrong packet.
                    let tagged = *shape == Shape::VlanV4Tcp;
                    if tagged {
                        TAGGED.fetch_add(1, Ordering::Relaxed);
                    }

                    let out = fabric.send(tunnelled(&frame));
                    if matches!(verdict(&out), Verdict::Delivered { .. }) {
                        assert!(!tagged, "a tagged frame was sent out onto the wire");
                        DELIVERED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let delivered = DELIVERED.load(Ordering::Relaxed);
        let tagged = TAGGED.load(Ordering::Relaxed);
        eprintln!("delivered={delivered} tagged={tagged}");

        // Both guards, because either alone can be satisfied by the pipeline doing nothing: a
        // fabric that refused everything would never deliver, and a generator that never drew a
        // tag would make the assertion above unreachable.
        super::assert_covered(delivered > 0, "nothing ever reached the wire");
        super::assert_covered(tagged > 0, "no tagged shape was ever generated");
    }

    /// A tunnelled flow comes back through the tunnel to where it started.
    ///
    /// The same claim as `round_trip::a_translated_flow_comes_back_to_where_it_started`, made where
    /// the packet has to earn every step. There, both directions had their arrival stamped by
    /// hand; here the request is decapsulated, translated, re-encapsulated and framed, and the
    /// reply arrives as a real tunnelled frame carrying the *peer's* vni and has to make the whole
    /// journey back. The reply-side decapsulation has no other test at all.
    ///
    /// The oracle costs nothing, which is why this is the property worth having: the reply is built
    /// from what came out rather than from what went in, so nothing here knows or computes what the
    /// translation should have been -- only that whatever it was has to reverse. Every address and
    /// port asserted below is one the test itself chose before the pipeline saw it.
    ///
    /// Three riders come free once a packet is followed end to end, and each is a separate claim:
    ///
    /// - **The tenant payload survives.** Decapsulate, translate, re-encapsulate -- the bytes
    ///   behind the headers must be the bytes that arrived. This is the class the doubled VXLAN
    ///   header in the fixtures belonged to, and byte comparison is the only thing that sees it.
    /// - **The tenant packet is charged exactly one hop.** Narrower than it first looks, and worth
    ///   stating precisely: the two `IpForwarder` passes act on *different* headers -- the first on
    ///   the outer frame, which decapsulation then discards, the second on the inner one -- so this
    ///   does not catch the first pass decrementing when it should not. Break-tested both ways.
    ///   What it does catch is a forwarder that stops decrementing at all, and decapsulation moving
    ///   to where the inner packet would be charged twice.
    /// - **It leaves tunnelled to the right vpc.** A reply is only correct if it went back into the
    ///   vni it came from.
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

    /// One masqueraded conversation: a request out through the tunnel, and its reply back.
    ///
    /// The first [`Load`], and written against the most demanding of the existing properties on
    /// purpose -- if the trait could not express this one it could not express any of them. What
    /// makes it demanding is that the reply is not knowable in advance: it has to be addressed to
    /// the public tuple the request was given, which the load reads out of what came back.
    pub(super) struct Conversation {
        /// What the test chose, and therefore what the reply has to restore.
        /// Which vpc this conversation is between, so the assertions about where a packet went
        /// are stated against the configuration rather than against a fixture's constants.
        path: Path,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        /// The request as it was sent, kept so the riders can compare against it.
        sent: Option<Packet<TestBuffer>>,
        state: State,
        log: Vec<String>,
    }

    /// A request/response load has four states, not two, and the difference is the whole of the
    /// `next` contract.
    ///
    /// Collapsing `Opening` into `Awaiting` -- advancing only when an answer arrives -- looks
    /// harmless and is not. `next` is then willing to produce a *second* request while the first is
    /// still in flight, so a scheduler asking for two packets gets the same request twice, and the
    /// second answer is judged as though it were the reply. That is not hypothetical: it is what
    /// this load did when the scheduler first ran it, and it read as a dataplane fault -- "the
    /// reply went back into the wrong vpc" -- rather than as a test one.
    #[derive(Debug, PartialEq, Eq)]
    enum State {
        /// About to send the request.
        Opening,
        /// The request is in flight. Nothing more to send until it comes back.
        AwaitingRequest,
        /// The request came back; the reply is built from `public`.
        Replying { public: (IpAddr, u16) },
        /// The reply is in flight.
        AwaitingReply,
        /// Checked, both ways.
        Closed,
        /// Gave up, for a reason that is not a defect. See [`Load::checked`].
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

        /// What the far side saw, and so what it would answer.
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

        /// The reply has to arrive at the host that opened the conversation, unchanged.
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
                // An answer this load is not waiting for means the scheduler handed it somebody
                // else's packet. Loud, because silently ignoring it is what made the same mistake
                // read as a dataplane fault the first time.
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

    /// One flow, several packets, sent without waiting for any of them.
    ///
    /// The counterpart to [`Conversation`], and the reason for having a second load kind at all: a
    /// conversation can never give a scheduler more than one packet, because it has to see its
    /// request come back before it can build anything else. A load that never waits is what makes
    /// `take` mean something, and what puts several packets of one flow into a single burst --
    /// which is the shape the allocation defect lived in.
    ///
    /// Its claim is that one flow gets one translation, stated across the whole blast rather than
    /// within a burst. That is the stronger form and it holds for the same reason: the first packet
    /// establishes the flow and every later one finds it. It assumes nothing invalidates the flow
    /// underneath -- no icmp error for it, no configuration change -- which is true of every
    /// property that runs this load and would not be true of one that generated either.
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
            // One delivered packet says nothing: the claim is about agreement between two.
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

    /// A service reached from outside on a forwarded port, and its answer getting back out.
    ///
    /// The third load kind, and the only one whose traffic starts outside the fabric. Everything
    /// else here opens from within a vpc and is answered; this arrives from the peer, is translated
    /// inwards, and has to leave again under the address the outside host used.
    pub(super) struct Inbound {
        /// Which vpc holds the service, and which the request arrives from.
        path: Path,
        /// Where outside.
        from: IpAddr,
        /// The advertised address and port, which is what the outside host knows.
        external: IpAddr,
        external_port: u16,
        /// Where it must land, which the test derives from the configuration's own offsets.
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

    /// The tenant payload: what is left once every header has been accounted for.
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

    /// Push one packet through a bare pipeline and take back the one that comes out.
    fn one(
        pipeline: &mut DynPipeline<TestBuffer>,
        packet: Packet<TestBuffer>,
    ) -> Packet<TestBuffer> {
        let mut out: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
        assert_eq!(out.len(), 1, "the pipeline did not return the packet");
        out.pop().unwrap_or_else(|| unreachable!())
    }
}

/// The pipeline under a model checker, with more than one worker.
///
/// Production builds **one pipeline per worker** -- `start_router` hands each worker a pipeline
/// from the same builder closure, each taking its own reader from a factory -- and what they share
/// is the `Arc<FlowTable>` and the read handles behind those factories. Every property above drives
/// a single pipeline on one thread, so none of them has ever seen two workers at once.
///
/// That matters here more than it would in most harnesses. The allocation defect in
/// `burst::a_burst_of_one_flow_allocates_once` was two packets of one flow racing through a stale
/// flow stamp *within a burst*; two workers allocating for the same flow simultaneously is the same
/// class of fault by a different mechanism, and nothing tests it.
///
/// bolero is the outer loop and picks the shape; the backend is the inner loop and explores
/// interleavings of that shape. `#[concurrency::model_test]` dispatches to whichever is built: real
/// OS threads by default (run under `just test sanitize=thread`), or shuttle's portfolio under
/// `--features shuttle`. The layout to copy is `flow-entry/src/flow_table/concurrent_fuzz.rs`.
///
/// # Two constraints that shape everything here
///
/// **A model-checked lock cannot live in a `static`.** It belongs to the execution that created it,
/// and `concurrency::stress` runs many executions, so the second one to take it locks a primitive
/// registered with a scheduler that has finished -- shuttle aborts inside `batch_semaphore` with a
/// non-unwinding panic, which kills the process rather than failing a test. This blocked the whole
/// module until `dpdk::acl::context`'s registry lock was made backend-dependent, because both
/// `FlowFilter` and `AclFilter` create ACL contexts and so every `Fabric` took it.
/// [`a_lock_that_outlives_its_execution_is_not_model_checkable`] keeps the evidence, since the raw
/// symptom is a panic ten frames deep in shuttle that names nothing in this workspace.
///
/// **`DynPipeline` is not `Send`.** The fib readers cache `Rc<UnsafeCell<FibGroup>>` per thread, and
/// are themselves neither `Send` nor `Sync`; so is `RouterTables`. A worker cannot be handed a
/// pipeline, or a reader, or the tables -- only a *factory*, on which it calls `handle()` itself.
/// That is exactly why `start_router` gives each worker a builder closure, and it is what
/// [`Fleet`], [`Blueprint`] and [`Worker`] are the harness's version of.
///
/// # What a green run here does and does not say
///
/// `rte_acl` is opaque to shuttle -- a model checker cannot see inside an FFI call -- so nothing
/// here speaks to races *within* `FlowFilter` or `AclFilter`. That is the sanitizer build's job, and
/// it is why the std backend of [`a_pipeline_can_be_driven_inside_a_stress_run`], which runs on real
/// OS threads under `just test sanitize=thread`, is not redundant with the shuttle one.
///
/// Shuttle also treats every atomic as `SeqCst` and says so on every run. The masquerade allocator
/// uses `Relaxed` in a dozen places and carries a standing question about it -- see the `TODO` on
/// `PortBlockList::deallocate_block` -- so a green run here is not an answer to that question.
///
/// # Reading a failure
///
/// Do not trust the first panic. The portfolio runs its schedulers in parallel, each reports
/// independently, and a panic inside a task tends to draw a second one after it: unwinding drops
/// the burst it was holding, every `Packet` carries an `Arc`, and `concurrency::sync::Arc` under
/// shuttle is `shuttle::sync::Arc`, so the drop touches an instrumented atomic while shuttle
/// already has its `ExecutionState` borrowed. That reads as `RefCell already borrowed` from inside
/// shuttle and says nothing at all.
///
/// Capture the whole run and search it. The sentence that explains the failure is often several
/// screens below the first panic -- the `table_name` defect that
/// [`generated_traffic_survives_being_split_across_two_workers`] found was reported as `RefCell
/// already borrowed` at the top and `An ACL context named 'flow_filter_remote_v4_7499' already
/// exists` a hundred and fifty lines further down.
///
/// The properties here take out `tracectl::evidence` recordings, which dump the pipeline's own
/// trace for a failing worker. Under shuttle those are **inert by design** -- see that module's
/// docs -- and the replayable schedule the backend prints is the artefact to use instead, because
/// it reproduces the failure rather than describing one run of it. The recordings are for the
/// backends with no such thing: the plain one, and the sanitizer builds.
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

    /// The public tuple a translated packet left with.
    type Tuple = (Option<IpAddr>, Option<u16>);

    /// What one worker produced, and the trace that would explain it.
    type Reported = (Vec<Tuple>, tracectl::evidence::Evidence);

    /// Run `body` on two threads inside one execution, which is the least shuttle's PCT scheduler
    /// will accept -- it panics outright on a body that never has two threads runnable at once.
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

    /// Which locks a model checker can see, stated as three cases that differ in one thing.
    ///
    /// The two that pass are here so the third is attributable. A lock created inside the execution
    /// is fine, and a `static` lock is fine for as long as one execution lasts -- so the fault is
    /// neither "statics" nor "locks", it is *reuse across executions*, and that is the sentence a
    /// reader needs. The failing case is written out rather than run, because shuttle aborts the
    /// process rather than failing a test:
    ///
    /// ```ignore
    /// static LOCK: OnceLock<Mutex<u32>> = OnceLock::new();
    /// concurrency::stress(|| on_two_threads(|| *LOCK.get_or_init(|| Mutex::new(0)).lock() += 1));
    /// // execution 2 panics in shuttle's batch_semaphore: the Mutex belongs to execution 1
    /// ```
    #[concurrency::model_test]
    fn a_lock_that_outlives_its_execution_is_not_model_checkable() {
        static LOCK: OnceLock<Mutex<u32>> = OnceLock::new();
        // `RUNS` is a real `std::sync` atomic, which shuttle does not instrument, so it counts
        // executions rather than taking part in one.
        static RUNS: AtomicUsize = AtomicUsize::new(0);

        // Created inside the execution: seen, and fine.
        concurrency::stress(|| {
            let lock = concurrency::sync::Arc::new(Mutex::new(0u32));
            let inner = lock.clone();
            let bump = move || *inner.lock() += 1;
            on_two_threads(&bump);
            assert_eq!(*lock.lock(), 2);
        });

        // A `static` lock, touched only while the execution that created it is still running.
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

    /// The pipeline can be assembled and driven while another thread reads its flow table.
    ///
    /// A foundation rather than a property: it asserts almost nothing about the traffic, and exists
    /// to establish that a real pipeline survives a model-checked execution at all -- the flow
    /// table's tokio timers, the EAL, the ACL registry lock and `concurrency::sync` primitives all
    /// have to tolerate it. It is kept beside the two-worker property below because when that one
    /// fails, this is what says whether the fault is in the sharing or in the machinery.
    ///
    /// The reader asserts nothing about *how many* entries it sees. That depends on the
    /// interleaving, and asserting it would make the test a claim about the scheduler.
    #[concurrency::model_test]
    fn a_pipeline_can_be_driven_inside_a_stress_run() {
        let _eal = dpdk::test_support::start_eal();

        // `FlowTable::insert` schedules its expiry timer with `tokio::task::spawn`, which panics
        // outside a runtime. Under shuttle that path is compiled out and no runtime is wanted; on
        // the std backend one has to exist for the spawn to succeed, though the timer never fires.
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
            // Entered inside the sender rather than out here: tokio's context is thread-local, so a
            // guard held by the spawning thread does nothing for the spawned one, and
            // `FlowTable::insert`'s `tokio::task::spawn` panics on the thread that actually runs it.
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

                // Reads the table the sender is writing. It asserts nothing about *how many*
                // entries it sees -- that depends on the interleaving and is not the question --
                // only that every read returns something coherent, which is what a torn write or a
                // use-after-free would break.
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
    /// The claim the whole arrangement rests on, put to the compiler rather than left in a comment.
    ///
    /// If a field is ever added to [`Blueprint`] that is not shareable, this is the error that says
    /// so, in one line, instead of a page about a closure capture in the property below.
    fn _a_blueprint_crosses_a_thread_boundary(blueprint: &Blueprint) {
        fn shareable<T: Sync>(_: &T) {}
        shareable(blueprint);
    }

    /// Two workers over one configuration are not given the same public tuple for two flows.
    ///
    /// This is the shape production runs in and that nothing above has ever been in. `start_router`
    /// builds the writers once and gives each worker a pipeline of its own from the same factories,
    /// so the masquerade allocator and the flow table are shared while the pipelines are not. Every
    /// property above drives one pipeline on one thread, which is the one arrangement in which an
    /// allocator race cannot happen.
    ///
    /// Two distinct flows given one public tuple is a defect however the threads interleave: the
    /// reverse lookup then has a single key and two answers, and the reply reaches at most one of
    /// them. `burst::a_burst_of_one_flow_allocates_once` is this property's single-threaded
    /// neighbour and says the opposite thing -- one flow, one tuple. Both are needed, and only this
    /// one can fail for a reason that involves two workers.
    ///
    /// It can fail, which is worth saying because a property about several allocations is worthless
    /// if the answers were fixed in advance. Measured on this fixture the pool is a *single* public
    /// address -- `1.1.0.0/16` masqueraded into `2.2.0.0/16` gives out `2.2.0.0` whichever host the
    /// flow came from -- so every tuple here differs in the port alone, and the port allocator is
    /// the one thing both workers reach into.
    ///
    /// It is contended at two levels, and the burst is sized to reach both. Ports come in blocks of
    /// 256 handed out per thread (`ThreadPortMap` and `usable_blocks` in `nat::masquerade::apalloc`,
    /// both `concurrency::sync` primitives and so both visible to shuttle), so the flows within one
    /// worker share a block while the two workers must be given different ones -- observed as
    /// `2.2.0.0:1024` and `2.2.0.0:1280`. A lost update to the block handout collides every port of
    /// both workers at once; a lost update inside a block collides two of one worker's.
    ///
    /// That the ports are consecutive rather than arbitrary is `set_randomize(false)` in
    /// [`Fleet::lowering`], and is the reason the observation above is stable enough to rely on.
    ///
    /// # Break-tested, and only shuttle catches it
    ///
    /// Replacing the `compare_exchange` in `PortBlockList::pick_available_block` with a
    /// test-then-set -- load `free`, then store `false`, the classic lost update -- lets two threads
    /// claim one block. Under shuttle this fails on the first run in 0.16s, reporting
    /// `2.2.0.0:1024` handed to two flows and a replayable schedule. Under the std backend the same
    /// break passed **twenty runs out of twenty**: two threads doing a few hundred microseconds of
    /// work each simply do not land in that window on real hardware.
    ///
    /// That gap is the argument for the backend existing. It is also the limit of it: shuttle sees
    /// `concurrency::sync` primitives and nothing else, so what it explores here is the allocator's
    /// own synchronisation, not `rte_acl`'s.
    #[concurrency::model_test]
    fn two_workers_are_not_given_the_same_public_tuple() {
        /// Flows per worker: more than one, so a collision *within* a worker's block can happen
        /// too, and few enough that a burst is still one block rather than an exhaustion test.
        const FLOWS: u16 = 3;

        let _eal = dpdk::test_support::start_eal();

        // See `a_pipeline_can_be_driven_inside_a_stress_run` for why the runtime is conditional.
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
            // Lowered once, outside the threads, exactly as `start_router` lowers it once. The ACL
            // contexts are built here too, which keeps the registry lock out of the interleaving
            // under test rather than making every execution race on it.
            let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
            let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
            let blueprint = fleet.blueprint();

            // A host and a first source port each, far enough apart that no two flows in the run
            // are the same flow. Two workers rather than more because shuttle's cost is in the
            // interleavings, and two threads is where the sharing already exists.
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
                                // Recorded per thread because that is the only granularity there
                                // is, and handed back because the assertion that judges this
                                // worker is made after it has exited.
                                let recording =
                                    tracectl::evidence::capture(format!("worker-{host}"));
                                // Built on this thread, not handed to it: the readers it takes out
                                // are thread-local caches, and this is the `factory().handle()`
                                // path production uses.
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
            // Held across the assertions below, so a collision arrives with both workers' traces
            // attached and a pass prints nothing at all.
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

    /// A generated configuration's own traffic, split across two workers.
    ///
    /// The properties above this one fix the configuration and vary the schedule. This varies both:
    /// bolero is the outer loop and draws a configuration together with the traffic it implies --
    /// the same [`generated::Generated`] draw that
    /// `generated::a_generated_configuration_carries_its_own_traffic` runs single-threaded -- and
    /// the backend is the inner loop and explores the interleavings of each draw.
    ///
    /// Nothing new is asserted here. Every load judges itself exactly as it does single-threaded,
    /// which is the point: the claim is that *splitting the traffic changes no answer*. A load that
    /// passes on one thread and fails when its neighbour runs beside it has found something that
    /// neither the configuration nor the packet shape explains.
    ///
    /// # What it has and has not caught
    ///
    /// It found the `table_name` defect in `flow_filter::context::tables`: an instrumented counter
    /// in a `static`, restarting every execution while the process-global `rte_acl` registry it
    /// names into did not. That is the kind of fault this shape is good for -- one that needs many
    /// configurations, each lowered more than once.
    ///
    /// It is **not** sensitive to the allocator race that
    /// [`two_workers_are_not_given_the_same_public_tuple`] catches. Measured: with that same
    /// deliberate lost update in the port-block claim, this property passed 256 drawn
    /// configurations while the targeted one failed on its first. A round trip survives a duplicate
    /// public tuple more often than not, so judging by round trip is simply a blunter instrument
    /// than reading the tuples out and comparing them. Breadth does not subsume a sharp assertion,
    /// and the two are kept for different reasons.
    ///
    /// # Why each thread derives every load and keeps a share
    ///
    /// A `Load` owns packets, and `Packet<TestBuffer>` is not `Send`, so loads cannot be built on
    /// one thread and dealt out to others. Deriving all of them on each worker and keeping the ones
    /// whose index matches is the cheap way to get a deterministic disjoint split without sending
    /// anything. Disjoint on purpose: two workers driving the *same* flow is a sharper question
    /// than this one and cannot reuse a load's self-judging, because two identical 5-tuples are
    /// genuinely ambiguous and a real gateway could not tell their replies apart either.
    #[concurrency::model_test]
    fn generated_traffic_survives_being_split_across_two_workers() {
        /// Configurations drawn. Small on purpose: under shuttle each one costs 32 executions and
        /// each execution lowers a configuration into `rte_acl` tables and builds two pipelines
        /// from them, so the budget here buys schedules.
        /// `generated::a_generated_configuration_carries_its_own_traffic` is where the
        /// configuration space itself gets explored, at a thousand cases for the same money.
        const CASES: usize = 64;

        /// Draws that reached two loaded workers, which is the only shape that tests anything.
        static SPLIT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        /// Draws that did not, kept so the guard below can say how close it came.
        static THIN: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let _eal = dpdk::test_support::start_eal();

        // See `a_pipeline_can_be_driven_inside_a_stress_run` for why the runtime is conditional.
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
                // Validated out here rather than in the body: validation is not cheap, it is the
                // same answer every execution, and a `ValidatedOverlay` is plain data. The tables
                // lowered *from* it are not -- their write handles are `concurrency::sync`
                // primitives, and a primitive that outlives its execution is the fault
                // `a_lock_that_outlives_its_execution_is_not_model_checkable` is about -- so
                // `Fleet::lowering` stays inside.
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
                // Both workers need traffic. A draw that leaves one idle is not a weaker test, it
                // is a rejected one: shuttle's PCT scheduler panics outright on a body that never
                // has two threads runnable at once.
                if vnis.is_empty() || loads_for(&validated, vary).len() < 2 {
                    THIN.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                SPLIT.fetch_add(1, Ordering::Relaxed);

                // One allocation for the whole draw, shared by every execution: `stress` wants a
                // `Fn`, so nothing here may be consumed.
                let drawn = std::sync::Arc::new((validated, vnis, vary.clone(), schedule.clone()));
                let entering = handle.clone();

                concurrency::stress(move || {
                    let (validated, vnis, vary, schedule) = &*drawn;
                    // The topology is built from the vnis the configuration names, so a fib exists
                    // for every vpc it can route to.
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
                                        // Every assertion in this property is made *on this
                                        // thread* -- a load panics where it is driven -- so the
                                        // recording's own drop-while-panicking is enough and no
                                        // handle has to leave.
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
                                        // Every assertion is inside here: a load panics on an
                                        // answer it did not accept, and `run_schedule` panics on a
                                        // load that will neither finish nor send.
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

    /// Advance one load by exactly one packet: offer, send, judge.
    ///
    /// [`drive`] runs a load to completion, which is the wrong granularity here -- the whole point
    /// is to stop halfway and change worker.
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

    /// A flow's reply is translated correctly by a worker that never saw its request.
    ///
    /// This is the arrangement production is *usually* in, not an unusual one. Receive-side
    /// steering hashes the tuple, and a reply has the tuple reversed, so the return traffic of a
    /// flow opened on one worker routinely lands on another. Everything the reverse path needs --
    /// the flow table entry `FlowLookup` attaches, and the allocation `Masquerade` recovers from it
    /// -- is therefore read by a thread that did not write it.
    ///
    /// Nothing above tests that. `round_trip::a_translated_flow_comes_back_to_where_it_started` and
    /// `routed::a_tunnelled_flow_comes_back_through_the_tunnel` both drive request and reply through
    /// one pipeline on one thread, which is the one arrangement in which the hand-off cannot fail.
    ///
    /// The oracle is [`Conversation::judge_reply`], unchanged: the reply must be delivered, go back
    /// into the vpc that opened the flow, arrive at the host that opened it, keep the far side's
    /// address, and get the original source port back. Reusing it rather than restating it is
    /// deliberate -- if the single-threaded claim and this one ever disagree, it should be because
    /// the dataplane behaved differently and not because two tests said different things.
    ///
    /// # What the break test does and does not establish
    ///
    /// Dropping the line in `flow_entry`'s `FlowLookup` that attaches flow state fails this on both
    /// answering threads, with `the reply of a delivered flow did not reach the wire:
    /// Dropped(Filtered)` and the conversation's own history attached. So the oracle does fire in
    /// this arrangement, which is worth knowing and is not free -- a reply crafted from a public
    /// tuple the answering worker was handed could easily have been wrong in a way that dropped
    /// silently.
    ///
    /// It does not isolate the *cross-worker* part: that same break fails the single-threaded
    /// `round_trip::a_translated_flow_comes_back_to_where_it_started` too. There is no break to hand
    /// that would fail only here, because the fault this guards against -- a per-thread cache in
    /// front of the flow table, a reverse translation that consulted `ThreadPortMap` -- is one
    /// nobody has written yet. That is the honest description of the property: it exercises an
    /// arrangement nothing else does, so that such a change cannot be made quietly.
    ///
    /// # Why the conversations are swapped rather than shared
    ///
    /// Each worker opens its own flows and then answers *the other's*. That keeps both threads
    /// doing real work in both phases, which shuttle's PCT scheduler requires, and it means every
    /// reply in the run crosses a worker boundary rather than only half of them.
    ///
    /// A `Conversation` can make that trip because it holds a `Packet<TestBuffer>` and nothing
    /// thread-bound; the pipeline it is driven through cannot, which is why each phase builds its
    /// own [`Worker`] from the shared [`Blueprint`].
    #[concurrency::model_test]
    fn a_reply_is_translated_by_a_worker_that_never_saw_the_request() {
        /// Flows opened per worker. Two, so the answering phase has more than one thing to do and
        /// an interleaving between them exists at all.
        const FLOWS: u8 = 2;

        /// Conversations that completed both legs. Counts executions rather than cases -- the
        /// stress body runs many times per test -- so it is a vacuity guard and not a measurement.
        static CLOSED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        /// Conversations whose request was not delivered, so there was never a reply to split.
        static ABANDONED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let _eal = dpdk::test_support::start_eal();

        // See `a_pipeline_can_be_driven_inside_a_stress_run` for why the runtime is conditional.
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

            // Phase one: each worker opens its own flows and stops with the reply outstanding.
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
                                        // A private host per worker per flow, so no two
                                        // conversations in the run are the same flow.
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

            // Phase two: swap. Neither worker answers a flow it opened.
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
                                // A pipeline of its own, from the same tables: the flow state and
                                // the allocation this thread is about to read were written through
                                // a different one.
                                let mut worker = blueprint.worker();
                                for convo in &mut theirs {
                                    // A request the configuration refused never reached the state
                                    // that has a reply, and that is not a defect. See
                                    // `Load::checked`.
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

    /// An ICMP Destination Unreachable from the far vpc, reporting on a datagram we masqueraded.
    ///
    /// The embedded datagram is the packet *as it left us* -- public source, real destination --
    /// because that is what the far side saw and therefore what it quotes back. `IcmpErrorHandler`
    /// builds a flow key from it and reverses it, which is how it finds the flow masquerade
    /// inserted. Getting this backwards produces an error that matches nothing, and a property
    /// resting on it would pass while tearing nothing down.
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

    /// Tearing one flow down does not disturb a flow another worker is using.
    ///
    /// `IcmpErrorHandler` is the pipeline's first stage, ahead of the barrier `FlowFilter` imposes,
    /// and it is the only place the ICMP path deletes a session. Under masquerade the deletion also
    /// releases the port allocation. So an ICMP error is a *write* to shared state -- the flow table
    /// and the allocator both -- performed by whichever worker the error happens to land on, while
    /// every other worker is reading the same two structures.
    ///
    /// This is the frame condition from `development/code/config-algebra-testing.md` applied to the
    /// flow table: an operation changes nothing outside its write set. Both halves are asserted,
    /// which is what makes it a frame condition rather than half of one:
    ///
    /// - the flow the error **names** is gone, so its own reply is refused;
    /// - the flow it does **not** name, being answered on another worker at the same moment,
    ///   completes exactly as it would have.
    ///
    /// The reasoning `Translations` relies on is explicitly single-threaded -- "within a burst
    /// nothing invalidates: `IcmpErrorHandler` runs ahead of the barrier, so any invalidation it
    /// causes has happened before the first allocation of that burst". That holds for one worker and
    /// says nothing about two, because the other worker's burst is not ordered against this one's.
    ///
    /// # Why both codes are run
    ///
    /// `Network` tears down and `FragmentationNeeded` must not: the latter is Path MTU Discovery,
    /// where the sender is about to retry the same flow with a smaller packet. Running both means
    /// the claim is about the *teardown* rather than about ICMP errors in general -- without the
    /// recoverable case, "the doomed reply was refused" would pass just as well if the error had
    /// broken the flow for some reason having nothing to do with invalidation.
    ///
    /// `nat::masquerade::test::path_mtu_discovery_does_not_tear_down_the_flow_that_triggered_it`
    /// makes the same distinction single-threaded, by reading the flow's own `is_active`. Here it
    /// is stated over what the pipeline does with a packet instead, because that survives the flow
    /// being torn down and re-established, and because it is the projection the rest of this module
    /// judges by.
    #[concurrency::model_test]
    fn an_icmp_teardown_leaves_another_workers_flow_alone() {
        /// Errors that found their flow and were translated, so a teardown was possible at all.
        static REPORTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        /// Conversations that survived a concurrent teardown of their neighbour.
        static SURVIVED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let _eal = dpdk::test_support::start_eal();

        // See `a_pipeline_can_be_driven_inside_a_stress_run` for why the runtime is conditional.
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
                // A fleet per case, so the second case cannot inherit the first's flows.
                let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
                let fleet =
                    Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
                let blueprint = fleet.blueprint();
                let entering = handle.clone();

                // Phase one: two flows, opened on different workers, both live and both one-way.
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

                // Phase two: one worker reports the error while the other answers the flow it kept.
                let tearing = entering.clone();
                let keeping = entering.clone();
                // Named for the message below, which outlives the closure that consumes the code.
                let named = format!("{code:?}");
                let spared = thread::scope(|scope| {
                    let teardown = thread::Builder::new()
                        .name("teardown".to_owned())
                        .spawn_scoped(scope, move || {
                            let _guard = tearing.as_ref().map(tokio::runtime::Handle::enter);
                            let _evidence = tracectl::evidence::capture("teardown");
                            let mut worker = blueprint.worker();
                            let out = worker.send(unreachable(code, doomed, target));
                            // Delivery is a real vacuity guard: an error whose embedded datagram
                            // matches no flow is *let through* rather than refused, so a mis-built
                            // one would sail past every assertion here having done nothing.
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

                // And the other half of the frame condition: the flow the error *did* name.
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

    /// Forwarding is not disturbed by a route being republished underneath it.
    ///
    /// Production has a third kind of thread that nothing here has ever modelled. Workers read the
    /// fibs; the config-apply path *writes* them, and it does so while traffic is flowing. Every
    /// property above builds its tables, freezes them, and then sends packets -- so the left-right
    /// machinery under `FibTableReader` has never once been asked to publish while a reader was
    /// mid-lookup.
    ///
    /// That machinery is not a plain lock. `FibTableReader` caches an `Rc<UnsafeCell<FibGroup>>`
    /// per thread (`left-right-tlcache`), which is exactly why a reader is neither `Send` nor
    /// `Sync`, and a publish has to interact with every one of those caches. This is the first
    /// property that puts a publish and a lookup in the same execution.
    ///
    /// # The claim
    ///
    /// The frame condition again, now on the fib: republishing a route the traffic does not use
    /// changes nothing about the traffic that uses a different one. The churn installs prefixes in
    /// `9.9.0.0/16`, which no packet here is addressed to; the conversations resolve `LOCAL_VTEP/32`
    /// in the underlay fib and the default route in each vni fib, and must complete exactly as they
    /// would against frozen tables.
    ///
    /// Stated over an untouched prefix rather than over the churned one on purpose. Left-right is
    /// *eventually* consistent by design -- a reader may legitimately serve the old table until it
    /// next refreshes -- so "the new route takes effect" is not a property that can be asserted
    /// without inventing a barrier the dataplane does not have. What can be asserted is that
    /// publishing does not corrupt what is already there.
    ///
    /// # Why the barrier
    ///
    /// Without it the workers can finish before the churn begins, and the property passes having
    /// overlapped nothing. The barrier makes all three threads start together, which is the
    /// cheapest way to make the overlap structural rather than lucky. It does not guarantee an
    /// interleaving *within* the run -- that is shuttle's job, and on the plain backend it is the
    /// scheduler's.
    ///
    /// # It can see a route change
    ///
    /// Worth establishing, because a property about publishing that could not notice a publish
    /// would pass forever. Aiming the churn at `3.3.3.1/32` in the remote vni's fib -- a prefix the
    /// conversations *do* resolve -- fails it immediately with `request not delivered:
    /// Dropped(Local)`, the packet having been delivered locally instead of encapsulated.
    ///
    /// So the silence in the passing case is the fib being republished without disturbing a lookup,
    /// rather than the property being blind to fibs.
    #[concurrency::model_test]
    fn forwarding_survives_a_route_being_republished_underneath_it() {
        /// Conversations each worker completes while the tables move.
        const FLOWS: u8 = 2;
        /// Routes installed, and therefore fibs published, during the run.
        const CHURN: u8 = 6;

        /// Conversations that completed against moving tables.
        static COMPLETED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        /// Routes published while they ran.
        static PUBLISHED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let _eal = dpdk::test_support::start_eal();

        // See `a_pipeline_can_be_driven_inside_a_stress_run` for why the runtime is conditional.
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
            // Owned here rather than by the fleet, so this thread can still borrow it mutably while
            // the workers hold a shared reference to what was derived from it.
            let mut tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
            let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
            let blueprint = fleet.blueprint();
            let entering = handle.clone();
            // Two workers and this thread.
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

                // This thread is the config-apply path: it owns the writers and republishes.
                let peer: IpAddr = PEER_VTEP.parse().unwrap_or_else(|_| unreachable!());
                let landing =
                    FibGroup::with_entry(FibEntry::with_inst(PktInstruction::Local(uplink())));
                start.wait();
                for nth in 0..CHURN {
                    // Somewhere no packet in this property is addressed, so the only thing under
                    // test is the act of publishing.
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

    /// A next hop that moves under live traffic is only ever seen at one of its published values.
    ///
    /// The property above churns a prefix nobody is addressed to, and so states a frame condition:
    /// publishing does not corrupt what is already there. This one aims the churn at the route
    /// every packet in it uses, which needs a different claim -- and gets a much sharper one.
    ///
    /// # A different mechanism, not just a different target
    ///
    /// The fib does not re-point routes when a next hop moves. Routes hold
    /// `Rc<UnsafeCell<FibGroup>>` into a per-fib store, and `FibGroupStore::add_mod_group` writes
    /// **through** that cell, so one publish moves every route resolving to that next hop at once.
    /// That is the point -- it makes a next-hop change `O(nexthops)` rather than `O(routes)` -- and
    /// it is also the sharpest edge in the fib: an `UnsafeCell` mutated in place while readers are
    /// looking at the table. Its safety argument rests entirely on left-right handing the writer a
    /// copy nobody is reading, and on the two copies never sharing an `Rc`.
    ///
    /// Nothing exercised that argument before this. `route_via` installs a *new* key each time, so
    /// the churn property above only ever takes the `else` branch that allocates a fresh cell. This
    /// one re-registers the key the default route already resolves to, which is the branch that
    /// writes through.
    ///
    /// # The claim
    ///
    /// Each version encapsulates towards a waypoint of its own, so the outer destination of a
    /// delivered frame names the version that forwarded it. Two things are asserted, and the second
    /// is the one worth having:
    ///
    /// - **Whole.** The waypoint must be one that was published, *and* the frame's ethernet
    ///   destination must name the same version. A packet carrying one version's tunnel and another
    ///   version's framing is a half-applied change, which is exactly what writing through a cell
    ///   under a live reader risks.
    /// - **Fresh.** A probe sent in round `r` sees version `r-1` or version `r`, and nothing else.
    ///   The lower bound is the interesting half: `publish` for version `r-1` *returned* before the
    ///   barrier that opened this round, so a reader entering afterwards may not still be serving
    ///   anything older. That is a liveness claim about the thread-local reader caches, and no
    ///   frame condition can state it.
    ///
    /// # Why rounds rather than one free-running race
    ///
    /// A single publish racing a burst of probes is a race whose outcome nobody can bound: the
    /// property would have to accept every version, which reduces it to the frame condition again.
    /// Rebarriering each round costs the race nothing -- the publish and that round's probes are
    /// still unsynchronised with each other -- and it buys the two-sided bound, because at a
    /// barrier every earlier publish has provably returned.
    ///
    /// # It can see each failure it claims to
    ///
    /// Three break tests, one per assertion, each reverted:
    ///
    /// - Publishing version `n`'s encapsulation with version `n-1`'s egress interface fails it in
    ///   round 1, naming both halves. That one also earned the adjacency cross product below: the
    ///   first attempt failed with `Dropped(MissL2resolution)` instead, because a mixed pair had no
    ///   adjacency -- a symptom indistinguishable from a topology mistake.
    /// - Publishing one version behind fails only the settled probe. Worth knowing: a reader a
    ///   single version stale is *within* the round bound and invisible to it, so the probe after
    ///   the last barrier is not a formality, it is the only thing that catches a lag of one.
    /// - Publishing two versions behind fails the round bound in round 2.
    ///
    /// The mac is not among the observables for the same reason: publishing every version framed to
    /// its predecessor's mac changed nothing at all.
    #[concurrency::model_test]
    fn a_next_hop_that_moves_is_never_seen_half_moved() {
        /// Versions published after the fixture's own.
        const CHURN: u8 = 3;
        /// Probes each worker sends per round, alongside that round's publish.
        const PER_ROUND: u8 = 2;

        /// Probes served by the version published in their own round.
        static FRESH: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        /// Probes served by the version published in the round before.
        static STALE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        /// Which version forwarded one probe, or why it could not be attributed to one.
        ///
        /// Carried back rather than asserted on the spot; see the judging loop for why.
        type Seen = Result<u8, String>;

        /// Where version `nth` sends traffic, and the interface it leaves by.
        ///
        /// Two observables rather than one, and deliberately ones written by *different
        /// instructions* of the same fib entry: the address is what `Encap` puts in the outer
        /// header, the interface is what `Egress` frames on. A group read while it was being
        /// written can disagree with itself, and this pair is what would show it.
        ///
        /// The outer mac would not. It comes from the adjacency table, which this property does not
        /// churn, and it is looked up by the very address `Encap` used -- so it agrees with the
        /// address by construction and could never be the thing that disagreed. Establishing that
        /// took a break test: publishing every version with its predecessor's mac changed nothing.
        ///
        /// Version 0 is the fixture's own next hop, so the run starts from the topology every other
        /// property here uses rather than from something this one arranged.
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

        /// The mac of version `nth`'s interface, which is also what its waypoint resolves to.
        fn framing(nth: u8) -> Mac {
            Mac([0x02, 0, 0, 0, 0x11, nth])
        }

        /// The group that tunnels the remote vpc's traffic out to `nth`'s waypoint.
        ///
        /// The same shape `encapsulate_out_of` builds, which is deliberate: a version that differed
        /// from the fixture in any way other than where it points would make a mismatch attributable
        /// to the difference rather than to the churn.
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

        // See `a_pipeline_can_be_driven_inside_a_stress_run` for why the runtime is conditional.
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
            // Every waypoint is resolvable before anything moves. The adjacency table is not what
            // is under test, and a version whose mac had not been learned yet would be dropped for
            // a reason that has nothing to do with the fib.
            for nth in 1..=CHURN {
                let (_, oif) = waypoint(nth);
                tables.interface(
                    oif,
                    &format!("uplink-{nth}"),
                    SourceMac::new(framing(nth)).unwrap_or_else(|_| unreachable!()),
                );
                tables.attach(oif, UNDERLAY_VRF);
            }
            // Every waypoint address is resolvable on every waypoint interface, which is more than
            // any version needs: a version only ever uses its own pair. The cross product is here
            // so that a group mixing two versions would be *delivered* -- and so caught by the
            // check below, which names both halves -- rather than dropped for want of an
            // adjacency. A drop reads identically to a topology mistake, so leaving the mixed pairs
            // unresolvable would turn the sharpest failure this property can have into its most
            // ambiguous one. Established by break test; see the doc comment.
            for to in 0..=CHURN {
                for over in 0..=CHURN {
                    tables.adjacency(waypoint(to).0, waypoint(over).1, framing(to));
                }
            }
            let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
            let blueprint = fleet.blueprint();
            let entering = handle.clone();
            // Two workers and this thread, rendezvousing once per round.
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

                                // A fresh five-tuple per probe, so every one of them is a new flow
                                // and has to consult the fib. Probes that shared a flow would say
                                // nothing about a route published after the first of them.
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
                                // Nothing is moving now: every publish returned before the last
                                // barrier, so there is no version but the last one left to serve.
                                seen.push(send(&mut worker, &mut port));
                                seen
                            })
                            .expect("spawn prober")
                    })
                    .collect();

                // This thread is the config-apply path: it owns the writers and moves the next hop
                // the default route in the remote vpc's fib already resolves to. No route is
                // touched -- re-registering the key is the whole change.
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

            // Judged here rather than in the probers, and that is not a stylistic choice. A prober
            // that panicked mid-round would never reach the next barrier, so its two peers would
            // wait on it forever: the property would hang instead of failing, which is the worst
            // way for a test to be wrong. A prober therefore only observes.
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
