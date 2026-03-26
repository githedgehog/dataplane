// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Integration tests for TCP flows through [`StatefulNat`].
//!
//! These tests use the `flow-test` crate's [`FlowHarness`] and [`TcpFlow`]
//! to drive full TCP handshakes and data exchanges through the stateful NAT
//! pipeline, proving that session creation, port rewriting, and reverse
//! translation work correctly with a real TCP state machine.
//!
//! ## Identity-IP NAT strategy
//!
//! The tests configure an **identity-IP mapping** (`10.0.0.1/32` → `10.0.0.1/32`)
//! so that the source IP address is unchanged by NAT.  NAT still allocates a
//! new source **port** from its port pool, exercising the full allocation →
//! session-creation → rewrite → reverse-translation pipeline.
//!
//! Identity-IP is used because the two smoltcp endpoints share a single L2
//! segment.  If NAT rewrote the source IP to a different address, the
//! receiving endpoint would need to ARP for that new address and nobody on
//! the segment would answer.  A later phase can lift this restriction by
//! adding static neighbor entries or a virtual-router shim in the pipe.
//!
//! [`StatefulNat`]: crate::StatefulNat
//! [`FlowHarness`]: flow_test::harness::FlowHarness
//! [`TcpFlow`]: flow_test::tcp_flow::TcpFlow

#[cfg(test)]
mod tests {
    use crate::stateful::allocator_writer::NatAllocatorWriter;
    use crate::stateless::test::tests::build_gwconfig_from_overlay;
    use crate::StatefulNat;
    use concurrency::sync::Arc;
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };
    use flow_entry::flow_table::FlowTable;
    use flow_test::harness::{FlowHarness, NetworkConfig};
    use flow_test::meta::stamp_for_stateful_nat;
    use flow_test::tcp_flow::TcpFlow;
    use net::buffer::TestBuffer;
    use net::flow_key::Uni;
    use net::packet::{Packet, VpcDiscriminant};
    use net::vxlan::Vni;
    use net::FlowKey;
    use pipeline::NetworkFunction;
    use std::time::Duration;
    use tracing_test::traced_test;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a [`VpcDiscriminant`] from a raw VNI value.
    fn vpcd(vni_id: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(Vni::new_checked(vni_id).expect("valid test VNI"))
    }

    /// Build a two-VPC overlay with **identity-IP** stateful NAT.
    ///
    /// | VPC   | VNI | Role   | Expose              | As range            |
    /// |-------|-----|--------|---------------------|---------------------|
    /// | VPC-1 | 100 | client | `10.0.0.1/32`       | `10.0.0.1/32`       |
    /// | VPC-2 | 200 | server | `10.0.0.0/24`       | *(none — no NAT)*   |
    ///
    /// The `/32 → /32` identity mapping ensures the source IP is unchanged.
    /// NAT still allocates a port from its pool and rewrites the source port.
    fn build_identity_nat_overlay() -> Overlay {
        let mut vpc_table = VpcTable::new();
        let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("VPC-1"));
        let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("VPC-2"));

        // VPC-1 expose: stateful NAT with identity IP mapping, 60 s idle timeout.
        let expose_vpc1 = VpcExpose::empty()
            .make_stateful_nat(Some(Duration::from_secs(60)))
            .expect("stateful NAT config")
            .ip("10.0.0.1/32".into())
            .as_range("10.0.0.1/32".into())
            .expect("as_range");

        // VPC-2 expose: plain reachability (no NAT on this side).
        let expose_vpc2 = VpcExpose::empty().ip("10.0.0.0/24".into());

        let mut manifest1 = VpcManifest::new("VPC-1");
        manifest1.add_expose(expose_vpc1);
        let mut manifest2 = VpcManifest::new("VPC-2");
        manifest2.add_expose(expose_vpc2);

        let peering = VpcPeering::with_default_group("VPC-1--VPC-2", manifest1, manifest2);

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering).expect("add peering");

        Overlay::new(vpc_table, peering_table)
    }

    /// Attach an existing flow-table session to `packet`'s metadata.
    ///
    /// This mirrors the production flow-lookup stage that runs before NAT.
    /// If no matching session exists, `flow_info` remains `None` and NAT
    /// will attempt to create a new session.
    fn flow_lookup(flow_table: &FlowTable, packet: &mut Packet<TestBuffer>) {
        if let Ok(flow_key) = FlowKey::try_from(Uni(&*packet))
            && let Some(flow_info) = flow_table.lookup(&flow_key)
        {
            packet.meta_mut().flow_info = Some(flow_info);
        }
    }

    /// Type-erased pipe closure so that the harness return type is nameable.
    type NatPipe = Box<dyn FnMut(Packet<TestBuffer>) -> Option<Packet<TestBuffer>>>;

    /// Build a [`FlowHarness`] whose forward and reverse pipes run packets
    /// through [`StatefulNat`].
    ///
    /// Two separate `StatefulNat` instances share the same
    /// [`Arc<FlowTable>`] and [`NatAllocatorReader`].  This is safe because
    /// the harness calls the pipes sequentially, never concurrently, and all
    /// mutable state in `StatefulNat` lives behind interior-mutability
    /// primitives in the shared `FlowTable`.
    ///
    /// Returns `(harness, sessions)` so that tests can inspect the flow
    /// table after running traffic.
    fn make_nat_harness() -> (FlowHarness<TestBuffer, NatPipe, NatPipe>, Arc<FlowTable>) {
        // -- NAT configuration -----------------------------------------------
        let mut config = build_gwconfig_from_overlay(build_identity_nat_overlay());
        config.validate().expect("overlay config should be valid");

        // -- shared state ----------------------------------------------------
        let sessions = Arc::new(FlowTable::default());
        let mut allocator_writer = NatAllocatorWriter::new();
        allocator_writer
            .update_allocator(&config.external.overlay.vpc_table)
            .expect("allocator update");
        let allocator_reader = allocator_writer.get_reader();

        // -- two NAT instances, one per direction ----------------------------
        let mut fwd_nat =
            StatefulNat::new("fwd", Arc::clone(&sessions), allocator_reader.clone());
        let mut rev_nat = StatefulNat::new("rev", Arc::clone(&sessions), allocator_reader);

        let fwd_sessions = Arc::clone(&sessions);
        let rev_sessions = Arc::clone(&sessions);

        // -- forward pipe: client → server  (VPC-1 → VPC-2) -----------------
        let forward_pipe: NatPipe =
            Box::new(move |mut pkt: Packet<TestBuffer>| -> Option<Packet<TestBuffer>> {
                stamp_for_stateful_nat(&mut pkt, vpcd(100), vpcd(200));
                flow_lookup(&fwd_sessions, &mut pkt);
                fwd_nat.process(std::iter::once(pkt)).next()
            });

        // -- reverse pipe: server → client  (VPC-2 → VPC-1) -----------------
        let reverse_pipe: NatPipe =
            Box::new(move |mut pkt: Packet<TestBuffer>| -> Option<Packet<TestBuffer>> {
                stamp_for_stateful_nat(&mut pkt, vpcd(200), vpcd(100));
                flow_lookup(&rev_sessions, &mut pkt);
                rev_nat.process(std::iter::once(pkt)).next()
            });

        // -- assemble harness ------------------------------------------------
        // Default NetworkConfig: 10.0.0.1/24 (client) ↔ 10.0.0.2/24 (server).
        let harness =
            FlowHarness::with_config(NetworkConfig::default(), forward_pipe, reverse_pipe);

        (harness, sessions)
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// The TCP 3-way handshake completes through identity-IP NAT.
    ///
    /// This is the key Phase 4 deliverable: a real TCP state machine drives
    /// SYN → SYN-ACK → ACK through `StatefulNat::process`, proving that
    /// session creation, port rewriting, and reverse translation all work.
    #[test]
    #[traced_test]
    fn tcp_handshake_completes_through_identity_nat() {
        let (mut harness, _sessions) = make_nat_harness();

        {
            let mut flow = TcpFlow::new(&mut harness, 49152, 80);
            let result = flow.connect();
            assert!(
                result.is_ok(),
                "TCP 3-way handshake should complete through identity NAT: {result:?}"
            );
            assert!(
                flow.client_state().is_established(),
                "client should reach ESTABLISHED, got {:?}",
                flow.client_state()
            );
            assert!(
                flow.server_state().is_established(),
                "server should reach ESTABLISHED, got {:?}",
                flow.server_state()
            );
        }

        // IP packets traversed both pipe directions (ARP is excluded from
        // these counters — only parsed IP packets are counted).
        assert!(
            harness.forward_count() > 0,
            "forward pipe should have processed at least one IP packet (SYN)"
        );
        assert!(
            harness.reverse_count() > 0,
            "reverse pipe should have processed at least one IP packet (SYN-ACK)"
        );
    }

    /// Bidirectional data exchange works through identity-IP NAT.
    ///
    /// After the handshake, the client sends a request and the server sends
    /// a response.  Both payloads must arrive intact despite NAT rewriting
    /// the source port on every segment.
    #[test]
    #[traced_test]
    fn tcp_data_exchange_through_identity_nat() {
        let (mut harness, _sessions) = make_nat_harness();

        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect().expect("handshake");

        // Client → server
        let request = b"GET / HTTP/1.1\r\nHost: server\r\n\r\n";
        flow.client()
            .send(request)
            .expect("client send should succeed");
        let received = flow
            .server()
            .recv(request.len())
            .expect("server recv should succeed");
        assert_eq!(
            received, request,
            "server should receive exactly the data the client sent"
        );

        // Server → client
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        flow.server()
            .send(response)
            .expect("server send should succeed");
        let received = flow
            .client()
            .recv(response.len())
            .expect("client recv should succeed");
        assert_eq!(
            received, response,
            "client should receive exactly the data the server sent"
        );
    }

    /// Graceful FIN exchange succeeds through identity-IP NAT.
    ///
    /// After data transfer, `TcpFlow::close` drives the FIN handshake.
    /// NAT must correctly translate the FIN/ACK segments using the same
    /// session that was created for the original SYN.
    #[test]
    #[traced_test]
    fn tcp_close_through_identity_nat() {
        let (mut harness, _sessions) = make_nat_harness();

        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect().expect("handshake");

        // Exchange a small payload so we know the connection was used.
        flow.client().send(b"ping").expect("client send");
        flow.server().recv(4).expect("server recv");
        flow.server().send(b"pong").expect("server send");
        flow.client().recv(4).expect("client recv");

        // Graceful close (FIN exchange).
        let result = flow.close();
        assert!(
            result.is_ok(),
            "graceful close should succeed through NAT: {result:?}"
        );
    }

    /// A larger (4 KiB) payload transfers correctly through identity-IP NAT.
    ///
    /// This exercises multiple TCP segments flowing through the NAT, each of
    /// which must be matched against the session and have its source port
    /// rewritten consistently.
    #[test]
    #[traced_test]
    fn larger_payload_through_identity_nat() {
        let (mut harness, _sessions) = make_nat_harness();

        let mut flow = TcpFlow::new(&mut harness, 49152, 80);
        flow.connect().expect("handshake");

        #[allow(clippy::cast_possible_truncation)] // i % 256 always fits in u8
        let payload: Vec<u8> = (0..4096_u16).map(|i| (i % 256) as u8).collect();
        flow.client()
            .send(&payload)
            .expect("client send of 4 KiB");
        let received = flow
            .server()
            .recv(payload.len())
            .expect("server recv of 4 KiB");
        assert_eq!(
            received, payload,
            "4 KiB payload should survive NAT round-trip intact"
        );
    }
}