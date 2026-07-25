// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reconfiguration of the masquerade allocator, raced against the data path.
//!
//! Everything else in this crate's test suite either exercises the allocator on one thread or
//! exercises concurrent allocation against a *fixed* allocator (`apalloc::test_alloc`'s
//! `concurrency_tests`).  Neither covers the operation this module is about: replacing the
//! allocator underneath a running data path.
//!
//! [`NatAllocatorWriter::update_nat_allocator`] is not a table swap.  It walks the *live* flow
//! table, re-reserving each active flow's `(ip, port)` in a freshly built allocator, and only then
//! publishes it.  Two structures are therefore read-modify-written with no single atomic step
//! covering both, so the question is whether the lock discipline around that window is airtight.
//!
//! It is tighter than it first looks.  The migration walk holds a [`FlowTableReadGuard`] across the
//! publish, and flow *insertion* takes the same lock exclusively, so no flow can appear between the
//! walk and the store.  What that guard does *not* cover is an already-present flow acquiring its
//! allocation late: per-flow NAT state sits behind the flow's own lock, not the table's.  A flow the
//! walk skipped for having no allocation yet could take one from the outgoing allocator afterwards,
//! and the incoming allocator would never have reserved it.
//!
//! Whether the data path can actually reach that ordering is what these tests are for.  The
//! invariant is the one that matters either way, and does not depend on the answer: **no two active
//! flows may hold the same masquerading allocation.** Two flows translated to the same address and
//! port are indistinguishable on the wire, so the reply to one can be delivered to the other.
//!
//! Configs come from `k8s-intf`'s generators rather than being hand-written, so the shapes fed to
//! the allocator are the shapes the CRD can actually express.  `bolero` supplies the shape axis.
//!
//! # Why this is not a shuttle test
//!
//! The intent was `bolero` for shapes and shuttle for interleavings, as
//! `concurrency/tests/quiescent_shuttle.rs` does.  That is not reachable here: `FlowTable::insert`
//! starts a per-flow expiry timer with `tokio::task::spawn`, so every path that creates a flow needs
//! a live tokio runtime.  Shuttle replaces the primitives behind `concurrency::sync` and
//! `concurrency::thread` with cooperatively scheduled ones; it has no view into tokio's scheduler or
//! timer wheel, and a tokio runtime inside a shuttle execution is not a supported combination.
//!
//! So anything downstream of flow insertion is currently outside what a model checker can drive, and
//! that is a property of the flow table rather than of this test.  What is left is real threads on a
//! tokio runtime: the OS picks the interleaving, so a narrow window is reached by luck rather than by
//! construction.  That still earns its keep -- it is a regression test for the invariant, and under
//! `ThreadSanitizer` it becomes a race detector over generated config shapes -- but it does not *prove*
//! the window is closed, and should not be read as doing so.
//!
//! Making this model-checkable means giving the flow table a way to insert without arming a timer
//! (injecting the timer as a dependency, or a `cfg` seam), at which point this test can move to the
//! shuttle pattern unchanged.

#![cfg(test)]

use ahash::HashMap;
use concurrency::sync::Arc;
use concurrency::thread;
use config::external::overlay::ValidatedOverlay;
use config::{ExternalConfig, GenId};
use flow_entry::flow_table::{FlowLookup, FlowTable};
use k8s_intf::bolero::LegalValue;
use k8s_intf::gateway_agent_crd::GatewayAgent;
use net::buffer::TestBuffer;
use net::flows::flow_info_item::ExtractRef;
use net::packet::test_utils::build_test_tcp_ipv4_packet;
use net::packet::{Packet, VpcDiscriminant};
use pipeline::{DynPipeline, NetworkFunction};
use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::masquerade::allocator_writer::{NatAllocatorReader, NatAllocatorReaderFactory};
use crate::masquerade::state::MasqueradeState;
use crate::masquerade::{MasqueradeConfig, NatAllocatorWriter};
use crate::{IcmpErrorHandler, Masquerade};

/// Stand-in for the flow-filter stage, which is not what is under test here.
///
/// Mirrors `masquerade::test::TestFlowFilter`; duplicated rather than shared because that module is
/// `#![cfg(test)]` and its helper is private to it.
#[derive(Default)]
struct TestFlowFilter(HashMap<VpcDiscriminant, VpcDiscriminant>);

impl TestFlowFilter {
    fn with_peerings(peerings: Vec<(VpcDiscriminant, VpcDiscriminant)>) -> Self {
        let mut new = TestFlowFilter::default();
        for (src_vpcd, dst_vpcd) in peerings {
            new.0.insert(src_vpcd, dst_vpcd);
            new.0.insert(dst_vpcd, src_vpcd);
        }
        new
    }
}

impl NetworkFunction<TestBuffer> for TestFlowFilter {
    fn process<'a, Input: Iterator<Item = Packet<TestBuffer>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<TestBuffer>> + 'a {
        input.filter_map(|mut packet| {
            let src_vpcd = packet.meta().src_vpcd?;
            // Unpeered source: drop rather than panic.  A generated config need not peer every VPC,
            // and an unroutable packet is not what this test is about.
            let dst_vpcd = *self.0.get(&src_vpcd)?;
            packet.meta_mut().dst_vpcd = Some(dst_vpcd);
            Some(packet)
        })
    }
}

/// One masquerading peering drawn from a config, with an address inside its private range.
struct MasqTarget {
    src_vpcd: VpcDiscriminant,
    src_ip: IpAddr,
}

/// Whether `config` contains an IPv6 masquerade range, which cannot be given to the allocator.
///
/// `NatAllocator::new` builds a bitmap over every masquerading peering's public range and indexes it
/// with a `u32`, so a range wider than 2^32 addresses -- any IPv6 prefix shorter than a /96, and the
/// pool hands out /64s -- panics during construction, before a single packet.  That is independent of
/// concurrency; see `test_ipv6_masquerade_range_wider_than_u32_panics`.  Skip such configs here so
/// this test reports on the race it is about rather than aborting in the allocator.
fn has_ipv6_masquerade_range(config: &MasqueradeConfig) -> bool {
    config.iter().any(|peering| {
        peering.peering.local().valexp().iter().any(|expose| {
            expose.nat().is_some_and(|nat| {
                nat.is_masquerade() && nat.as_range.iter().any(|pfx| !pfx.prefix().is_ipv4())
            })
        })
    })
}

/// Every masquerading peering in `config`, paired with a source address it will translate.
///
/// Returns an empty vector when the config masquerades nothing, in which case there is no allocator
/// to race against and the caller should skip.
fn masquerading_targets(config: &MasqueradeConfig) -> Vec<MasqTarget> {
    let mut targets = Vec::new();
    for peering in config.iter() {
        for expose in peering.peering.local().valexp() {
            let Some(nat) = expose.nat() else { continue };
            if !nat.is_masquerade() {
                continue;
            }
            // The first address of the first exposed prefix is inside what this peering translates,
            // which is all the data path needs to take an allocation.
            //
            // IPv4 only, deliberately: allocating from an IPv6 masquerade range wider than a /96
            // panics in `apalloc::alloc::map_address`, which indexes the range with a `u32`.  See
            // `test_ipv6_masquerade_range_wider_than_u32_panics`.  Until that is resolved, an IPv6
            // target would abort this test in the allocator rather than exercising the race.
            let Some(prefix) = expose.ips().iter().next() else {
                continue;
            };
            let address = prefix.prefix().as_address();
            if address.is_ipv4() {
                targets.push(MasqTarget {
                    src_vpcd: peering.src_vpcd,
                    src_ip: address,
                });
                break;
            }
        }
    }
    targets
}

/// A `DynPipeline` holds boxed stages without a `Send` bound, so it cannot cross a thread
/// boundary.  Each thread therefore builds its own; the state that matters -- the flow table and the
/// published allocator -- is shared, and a pipeline holds none of it.
fn make_pipeline(
    flow_table: &Arc<FlowTable>,
    alloc_reader: NatAllocatorReader,
    peerings: Vec<(VpcDiscriminant, VpcDiscriminant)>,
) -> DynPipeline<TestBuffer> {
    DynPipeline::new()
        .add_stage(IcmpErrorHandler::new(flow_table.clone()))
        .add_stage(FlowLookup::new("flow-lookup", flow_table.clone()))
        .add_stage(TestFlowFilter::with_peerings(peerings))
        .add_stage(Masquerade::new("masq", flow_table.clone(), alloc_reader))
}

/// The peerings a generated config masquerades, in the form the flow filter wants.
fn peering_pairs(config: &MasqueradeConfig) -> Vec<(VpcDiscriminant, VpcDiscriminant)> {
    config.iter().map(|p| (p.src_vpcd, p.dst_vpcd)).collect()
}

/// Install the initial allocator and hand back what both threads need.
fn setup(
    overlay: &ValidatedOverlay,
    genid: GenId,
) -> (
    Arc<FlowTable>,
    NatAllocatorWriter,
    NatAllocatorReaderFactory,
    MasqueradeConfig,
) {
    let nat_config = MasqueradeConfig::new(overlay.vpc_table(), genid);
    let mut alloc_writer = NatAllocatorWriter::new();
    let reader_factory = alloc_writer.get_reader_factory();
    let flow_table = Arc::new(FlowTable::default());

    alloc_writer.update_nat_allocator(nat_config.clone(), &flow_table);
    (flow_table, alloc_writer, reader_factory, nat_config)
}

/// Push one TCP packet per target through the pipeline, taking an allocation for each.
fn drive_data_path(
    pipeline: &mut DynPipeline<TestBuffer>,
    targets: &[MasqTarget],
    sport_base: u16,
) {
    for (index, target) in targets.iter().enumerate() {
        // Distinct source ports so each packet is a distinct flow rather than a hit on the
        // previous one.
        let sport = sport_base.wrapping_add(u16::try_from(index).unwrap_or(0)) | 1;
        let mut packet = build_test_tcp_ipv4_packet(
            &target.src_ip.to_string(),
            // Any destination: the flow filter decides the peer, not the address.
            "203.0.113.9",
            sport,
            443,
        );
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().set_masquerade(true);
        packet.meta_mut().src_vpcd = Some(target.src_vpcd);
        let _out: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
    }
}

/// The invariant: no two active flows may hold the same masquerading allocation.
///
/// A duplicate means two distinct flows translate to the same address and port, so replies cannot
/// be attributed to the right one.
fn assert_no_duplicate_allocations(flow_table: &FlowTable) {
    let mut seen: BTreeSet<(IpAddr, u16)> = BTreeSet::new();
    let mut duplicates = Vec::new();

    let guard = flow_table.for_each_flow_filtered(
        |_key, flow_info| flow_info.is_active(),
        |key, flow_info| {
            let locked = flow_info.locked.read();
            let Some(state) = locked.nat_state.extract_ref::<MasqueradeState>() else {
                return;
            };
            let Some(alloc) = state.allocation() else {
                return;
            };
            let entry = (alloc.ip(), alloc.port().as_u16());
            if !seen.insert(entry) {
                duplicates.push(format!("{key} -> {}:{}", entry.0, entry.1));
            }
        },
    );
    drop(guard);

    assert!(
        duplicates.is_empty(),
        "two active flows share a masquerading allocation: {duplicates:?}"
    );
}

/// Race a reconfiguration against the data path, then check the invariant.
///
/// The second config reuses the first's peerings under a fresh generation id.  That is deliberate:
/// an unchanged config takes `update_nat_allocator`'s early-return path and a wholly different one
/// invalidates every flow, so neither reaches the re-reservation walk.  Bumping only the generation
/// makes every live flow a migration candidate, which is the widest form of the walk.
fn run_reconfiguration_race(agent: &GatewayAgent) {
    let Ok(external) = ExternalConfig::try_from(agent) else {
        return;
    };
    let Ok(validated) = external.validate() else {
        return;
    };
    let overlay = validated.external().overlay();

    let genid = validated.genid();

    // Decide before touching the allocator: `setup` installs one, which is where the IPv6 panic
    // happens.
    let probe = MasqueradeConfig::new(overlay.vpc_table(), genid);
    if has_ipv6_masquerade_range(&probe) {
        return;
    }
    drop(probe);

    let (flow_table, mut alloc_writer, reader_factory, config) = setup(overlay, genid);
    let targets = masquerading_targets(&config);
    if targets.is_empty() {
        // Nothing masquerades, so there is no allocator to migrate and no second thread's worth of
        // work.  Shuttle's PCT scheduler panics on a body without real concurrency, so skip.
        return;
    }
    let pairs = peering_pairs(&config);

    // Seed flows *before* the race so the migration walk has something to re-reserve.
    {
        let mut pipeline = make_pipeline(&flow_table, reader_factory.handle(), pairs.clone());
        drive_data_path(&mut pipeline, &targets, 1000);
    }

    let next_config = MasqueradeConfig::new(overlay.vpc_table(), genid + 1);
    let flow_table_for_writer = flow_table.clone();
    let flow_table_for_data_path = flow_table.clone();

    // Both threads touch the flow table, whose insert path arms a tokio timer, so both need the
    // runtime in scope.
    let handle = tokio::runtime::Handle::current();
    let writer_handle = handle.clone();

    let reconfigure = thread::spawn(move || {
        let _guard = writer_handle.enter();
        alloc_writer.update_nat_allocator(next_config, &flow_table_for_writer);
    });
    let data_path = thread::spawn(move || {
        let _guard = handle.enter();
        // Fresh source ports: these flows are created while the swap is in flight, which is the
        // window the guard does not obviously cover.
        let mut pipeline = make_pipeline(&flow_table_for_data_path, reader_factory.handle(), pairs);
        drive_data_path(&mut pipeline, &targets, 2000);
    });

    reconfigure.join().expect("reconfigure thread panicked");
    data_path.join().expect("data path thread panicked");

    assert_no_duplicate_allocations(&flow_table);
}

/// Race a reconfiguration against the data path across many generated config shapes.
///
/// Not gated on `shuttle`: see the module docs for why a model checker cannot drive this path.  A
/// `shuttle` build compiles and runs this as ordinary threads, which is harmless but proves nothing
/// extra, so there is no separate shuttle entry point to imply otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconfiguration_race_preserves_allocation_uniqueness() {
    bolero::check!()
        .with_type::<LegalValue<GatewayAgent>>()
        .for_each(|agent| run_reconfiguration_race(agent.as_ref()));
}

/// A validated config with a wide IPv6 masquerade range panics the allocator.
///
/// `apalloc::alloc::map_address` indexes a masquerade range's addresses with a `u32`:
///
/// ```text
/// prefix_offset + u32::try_from(address.to_bits() - prefix_start_bits).unwrap()
/// ```
///
/// An IPv6 prefix shorter than a `/96` holds more than `u32::MAX` addresses, so that `unwrap`
/// fails.  Config validation does not reject such a range -- `VpcExpose::validate` checks family
/// consistency, sizes for static NAT, and reserved blocks, but never that a masquerade range is
/// narrow enough for the allocator to index -- so this is reachable from operator input: a
/// `GatewayAgent` with an IPv6 masquerade `as` range validates, and then aborts the dataplane when
/// the allocator is built.  Under the `panic = "abort"` used in shipped builds, that is the whole
/// process.
///
/// No concurrency and no packets are involved; building the allocator is enough.
///
/// Ignored because it documents a defect rather than asserting intended behaviour.  Two candidate
/// fixes, and the choice is a design decision: reject over-wide masquerade ranges during validation
/// (which makes it an operator-visible config error), or have the allocator index only the first
/// `u32::MAX` addresses of a range (which silently caps capacity).  When one lands, drop the
/// `ignore` and invert the assertion.
#[test]
#[ignore = "documents a live defect: wide IPv6 masquerade ranges panic the allocator"]
fn test_ipv6_masquerade_range_wider_than_u32_panics() {
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };

    // A /64 on each side: same family, no port ranges, no exclusions -- everything
    // `VpcExpose::validate` asks of a masquerading expose.
    let masq = VpcExpose::empty()
        .make_masquerade(None)
        .expect("masquerade is a legal mode")
        .ip("2001:db8:1::/64".into())
        .as_range("2001:db8:2::/64".into())
        .expect("as_range is legal with NAT configured");
    let plain = VpcExpose::empty().ip("2001:db8:3::/64".into());

    let mut left = VpcManifest::new("VPC-1");
    left.add_expose(masq);
    let mut right = VpcManifest::new("VPC-2");
    right.add_expose(plain);

    let mut vpcs = VpcTable::new();
    vpcs.add(Vpc::new("VPC-1", "aaaaa", 100).expect("legal vpc"))
        .expect("first vpc");
    vpcs.add(Vpc::new("VPC-2", "bbbbb", 200).expect("legal vpc"))
        .expect("second vpc");

    let mut peerings = VpcPeeringTable::new();
    peerings
        .add(VpcPeering::with_default_group("peering-1", left, right))
        .expect("first peering");

    let overlay = Overlay::new(vpcs, peerings)
        .validate()
        .expect("a v6 masquerade expose is accepted by validation -- that is the point");

    // Panics in `map_address` while building the bitmap.
    let (_flow_table, _writer, _factory, _config) = setup(&overlay, 1);
}
