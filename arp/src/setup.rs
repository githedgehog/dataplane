// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Setup utils for ARP/ND support

use crate::ArpNdCtl;
use crate::ArpNdError;
use crate::cache::{NeighCacheReaderFactory, NeighCacheWriter};
use crate::daemon::start_arp_nd;

use lifecycle::Subsystem;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pkt_io::{PktIo, PktQueue};
use tokio::task::JoinHandle;

#[allow(unused)]
use tracing::{debug, error, info};

/// The object needed to start ARP/ND daemon
pub struct ArpSetup<Buf: PacketBufferMut> {
    nf: PktIo<Buf>,           // network function to add to pipeline
    cachew: NeighCacheWriter, // neighbor cache writer
}

fn arpnd_trap_function<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    packet.meta().need_arp_nd()
}

impl<Buf: PacketBufferMut> ArpSetup<Buf> {
    const ARP_QUEUE_SIZE: usize = 500;

    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // create pipeline stage to punt ARP
        let nf = PktIo::new("ARP/ND-io", Self::ARP_QUEUE_SIZE, Self::ARP_QUEUE_SIZE)
            .set_trap_function(arpnd_trap_function);

        // create neighbor cache
        let (cachew, _) = NeighCacheWriter::new();

        Self { nf, cachew }
    }
    #[must_use]
    pub fn nf(&self) -> PktIo<Buf> {
        self.nf.clone()
    }
    #[must_use]
    pub fn inq(&self) -> PktQueue<Buf> {
        self.nf.get_puntq().unwrap_or_else(|| unreachable!())
    }
    #[must_use]
    pub fn outq(&self) -> PktQueue<Buf> {
        self.nf.get_injectq().unwrap_or_else(|| unreachable!())
    }

    #[must_use]
    pub fn neigh_cache_factory(&self) -> NeighCacheReaderFactory {
        self.cachew.factory()
    }

    /// Launch the ARP/ND daemon on `rt_handle`, tracked under the given `subs`. This consumes
    /// the setup: the readers of the neighbor cache must be obtained before.
    ///
    /// # Errors
    ///
    /// Fails if the daemon cannot be started.
    pub fn launch(
        self,
        rt_handle: &tokio::runtime::Handle,
        subs: &Subsystem,
    ) -> Result<(JoinHandle<()>, ArpNdCtl), ArpNdError>
    where
        Buf: Send + 'static,
    {
        start_arp_nd(rt_handle, subs, self.inq(), self.outq(), self.cachew)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cache::NeighState;
    use crate::netlink::test_netlink_utils::{create_tap, get_neigh_state, set_neigh, wait_until};
    use caps::Capability;
    use fixin::wrap;
    use lifecycle::CancellationToken;
    use lifecycle::Subsystem;
    use net::buffer::TestBuffer;
    use net::eth::mac::Mac;
    use net::interface::InterfaceIndex;
    use net::packet::DoneReason;
    use net::packet::test_utils::build_test_udp_ipv4_packet;
    use pipeline::{DynPipeline, NetworkFunction};
    use rtnetlink::packet_route::neighbour::NeighbourState;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::{Duration, Instant};
    use test_utils::with_caps;
    use tokio::runtime::Handle;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tracing_test::traced_test;

    fn test_subsystem() -> Subsystem {
        Subsystem::new("arp", CancellationToken::new())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_arp_nd_setup_and_teardown_async() {
        let arpnd: ArpSetup<TestBuffer> = ArpSetup::new();
        let subs = test_subsystem();
        let (jh, _ctl) = arpnd.launch(&Handle::current(), &subs).unwrap();
        subs.cancel_token().cancel();
        jh.await.unwrap();
    }

    /// Build a packet to `dst` over `oif` that needs ARP/ND resolution
    fn packet_to_resolve(dst: &str, oif: InterfaceIndex) -> Packet<TestBuffer> {
        let mut packet = build_test_udp_ipv4_packet("1.2.3.4", dst, 100, 80);
        packet.meta_mut().set_need_arp_nd(true); // require resolution
        packet.meta_mut().oif = Some(oif); // over this interface
        packet
    }

    /// Drive a pipeline with the ARP/ND `nf`, like a worker would, with `packet`, which must be
    /// punted to the daemon. This blocks, so it runs on a blocking thread, to not keep the daemon
    /// (on the runtime of the test) from running. Returns the packets returned by the daemon:
    /// the packet, if returned within 10 seconds.
    fn punt_packet(
        nf: PktIo<TestBuffer>,
        packet: Packet<TestBuffer>,
    ) -> JoinHandle<Vec<Packet<TestBuffer>>> {
        tokio::task::spawn_blocking(move || {
            let mut pipeline = DynPipeline::new().add_stage(nf);
            let mut burst = vec![packet];
            pipeline.process_burst(&mut burst);
            assert!(burst.is_empty(), "the packet should have been punted");

            let deadline = Instant::now() + Duration::from_secs(10);
            while burst.is_empty() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
                pipeline.process_burst(&mut burst);
            }
            burst
        })
    }

    /// End-to-end test of the ARP/ND daemon: packets that need resolution are punted from a
    /// pipeline to the daemon, which queries the kernel for their targets. A neighbor answers
    /// for one of the targets (emulated with a kernel neighbor entry): its packets come back
    /// to the pipeline resolved. Nobody answers for the rest: their packets come back given up.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_arp_nd_full() {
        // the ip that the daemon will successfully resolve, and the MAC
        const TARGET_IP: &str = "10.0.0.2";
        let target_ip = IpAddr::from_str(TARGET_IP).unwrap();
        let resolved_mac = Mac([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x01]);

        info!("Creating taps...");
        let (tap0_name, tap0_ifindex) = create_tap("tap0").await;
        let (tap1_name, tap1_ifindex) = create_tap("tap1").await;
        let (tap2_name, tap2_ifindex) = create_tap("tap2").await;

        // build Arp/nd task and NF
        let arpnd: ArpSetup<TestBuffer> = ArpSetup::new();
        let nf = arpnd.nf.clone();

        // start ARP/ND daemon/task
        let rfactory = arpnd.neigh_cache_factory();
        let subs = test_subsystem();
        let (jh, ctl) = arpnd.launch(&Handle::current(), &subs).unwrap();

        // enable ARP/ND over the taps
        ctl.enable(&[tap0_name, tap1_name, tap2_name])
            .await
            .unwrap();

        // input packets: only the packet to TARGET_IP over tap0 will be resolved
        let mut packets = vec![
            packet_to_resolve(TARGET_IP, tap0_ifindex),
            packet_to_resolve("10.0.0.3", tap0_ifindex),
            packet_to_resolve("10.0.0.4", tap0_ifindex),
            packet_to_resolve("10.0.1.2", tap1_ifindex),
            packet_to_resolve("10.0.2.2", tap2_ifindex),
        ];
        let injected = packets.len();

        // drive a pipeline with the ARP/ND NF, like a worker would. This blocks, so it runs
        // on a blocking thread, to not keep the daemon (on this runtime) from running.
        let (injected_tx, injected_rx) = oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let mut pipeline = DynPipeline::new().add_stage(nf);
            pipeline.process_burst(&mut packets);
            assert!(packets.is_empty(), "ALL packets should have been punted");
            injected_tx.send(()).unwrap();

            // collect the packets returned by the daemon, resolved or not
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut returned = vec![];
            let mut burst = vec![];
            while returned.len() < injected && Instant::now() < deadline {
                pipeline.process_burst(&mut burst);
                returned.append(&mut burst); // keep what came back, and empty burst for the next round
                std::thread::sleep(Duration::from_millis(100));
            }
            returned
        });

        // emulate a neighbor responding for TARGET_IP, once the packets are waiting for it:
        // the kernel has a reachable entry for it
        injected_rx.await.unwrap();
        set_neigh(
            tap0_ifindex.to_u32(),
            target_ip,
            Some(resolved_mac),
            NeighbourState::Reachable,
        )
        .await
        .unwrap();

        // check what worker produced. It should have returned all packets
        let returned = worker.await.unwrap();
        assert_eq!(returned.len(), injected, "not all packets were returned");

        for packet in &returned {
            let dst = packet.ip_destination().expect("Can't get Ip dst address");
            let dst_mac = packet.eth_destination().unwrap();
            if dst == target_ip {
                assert_eq!(packet.get_done(), Some(DoneReason::Delivered));
                assert!(!packet.meta().need_arp_nd());
                assert_eq!(dst_mac, resolved_mac);
            } else {
                assert!(packet.meta().need_arp_nd());
                assert_eq!(packet.get_done(), Some(DoneReason::MissL2resolution));
            }
        }

        // the resolution is in the cache visible to the pipeline
        let cacher = rfactory.handle();
        assert_eq!(
            cacher
                .get_mac(target_ip, tap0_ifindex)
                .unwrap()
                .map(|m| m.inner()),
            Some(resolved_mac)
        );

        println!("{}", *cacher.enter().unwrap());

        subs.cancel_token().cancel();
        jh.await.unwrap();
    }

    /// Test that the daemon has the kernel confirm the neighbors that become stale over the
    /// enabled interfaces, and only those. The stale mac is used meanwhile. Since nobody
    /// answers the confirmation, the neighbor fails and its mac is no longer used.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_arp_nd_confirm_stale() {
        let mac = Mac([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x01]);
        let (tap0_name, tap0_ifindex) = create_tap("tap0").await;
        let (_tap1_name, tap1_ifindex) = create_tap("tap1").await;
        let ip0 = IpAddr::from_str("10.0.0.2").unwrap();
        let ip1 = IpAddr::from_str("10.0.1.2").unwrap();

        // start the daemon, with ARP/ND enabled over tap0 only
        let arpnd: ArpSetup<TestBuffer> = ArpSetup::new();
        let rfactory = arpnd.neigh_cache_factory();
        let subs = test_subsystem();
        let (jh, ctl) = arpnd.launch(&Handle::current(), &subs).unwrap();
        ctl.enable(&[tap0_name]).await.unwrap();

        // neighbors become stale over both taps
        set_neigh(tap0_ifindex.to_u32(), ip0, Some(mac), NeighbourState::Stale)
            .await
            .unwrap();
        set_neigh(tap1_ifindex.to_u32(), ip1, Some(mac), NeighbourState::Stale)
            .await
            .unwrap();

        // the neighbor over tap0 gets confirmed: the kernel takes it out of stale, delaying
        // its unicast probes
        let confirming = wait_until(Duration::from_secs(3), async || {
            get_neigh_state(tap0_ifindex.to_u32(), ip0).await != Some(NeighbourState::Stale)
        })
        .await;
        assert!(confirming, "the stale neighbor over tap0 was not confirmed");

        // the stale mac is used while being confirmed
        let cacher = rfactory.handle();
        assert_eq!(
            cacher
                .get_mac(ip0, tap0_ifindex)
                .unwrap()
                .map(|m| m.inner()),
            Some(mac)
        );

        // the neighbor over tap1 (not enabled) is left alone
        assert_eq!(
            get_neigh_state(tap1_ifindex.to_u32(), ip1).await,
            Some(NeighbourState::Stale)
        );

        // nobody answers the probes: the neighbor fails, which the cache mirrors. This takes
        // the kernel's delay before probing and its probes (some 5 + 3 seconds by default)
        let failed = wait_until(Duration::from_secs(15), async || {
            cacher
                .get_entry(ip0, tap0_ifindex)
                .map(|entry| entry.state())
                == Some(NeighState::Failed)
        })
        .await;
        assert!(failed, "the unconfirmed neighbor did not fail in the cache");
        assert_eq!(cacher.get_mac(ip0, tap0_ifindex).unwrap(), None);
        assert_eq!(
            get_neigh_state(tap0_ifindex.to_u32(), ip0).await,
            Some(NeighbourState::Failed)
        );

        subs.cancel_token().cancel();
        jh.await.unwrap();
    }

    /// Test that the daemon resolves a target for which the kernel has a failed entry (e.g.
    /// because a former resolution failed): querying it restarts its resolution in the kernel,
    /// and the packet comes back resolved once the neighbor answers.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_arp_nd_resolve_failed() {
        const TARGET_IP: &str = "10.0.0.2";
        let target_ip = IpAddr::from_str(TARGET_IP).unwrap();
        let resolved_mac = Mac([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x01]);
        let (tap0_name, tap0_ifindex) = create_tap("tap0").await;

        // the kernel has a failed entry for the target
        set_neigh(
            tap0_ifindex.to_u32(),
            target_ip,
            None,
            NeighbourState::Failed,
        )
        .await
        .unwrap();

        // start the daemon, with ARP/ND enabled over tap0
        let arpnd: ArpSetup<TestBuffer> = ArpSetup::new();
        let nf = arpnd.nf.clone();
        let subs = test_subsystem();
        let (jh, ctl) = arpnd.launch(&Handle::current(), &subs).unwrap();
        ctl.enable(&[tap0_name]).await.unwrap();

        // punt a packet to the target to the daemon
        let worker = punt_packet(nf, packet_to_resolve(TARGET_IP, tap0_ifindex));

        // the query restarts the resolution in the kernel: the failed entry becomes incomplete
        let resolving = wait_until(Duration::from_secs(3), async || {
            get_neigh_state(tap0_ifindex.to_u32(), target_ip).await
                == Some(NeighbourState::Incomplete)
        })
        .await;
        assert!(
            resolving,
            "the kernel did not restart the resolution of the target"
        );

        // emulate the neighbor answering: the kernel has a reachable entry for it
        set_neigh(
            tap0_ifindex.to_u32(),
            target_ip,
            Some(resolved_mac),
            NeighbourState::Reachable,
        )
        .await
        .unwrap();

        // the packet comes back resolved
        let returned = worker.await.unwrap();
        assert_eq!(returned.len(), 1, "the packet was not returned");
        let packet = &returned[0];
        assert_eq!(packet.get_done(), Some(DoneReason::Delivered));
        assert!(!packet.meta().need_arp_nd());
        assert_eq!(packet.eth_destination().unwrap(), resolved_mac);

        subs.cancel_token().cancel();
        jh.await.unwrap();
    }

    /// Test that the daemon learns the neighbors that the kernel has when it starts: a packet
    /// to a static (permanent) neighbor is resolved with its MAC, and the neighbor is not
    /// queried, which would make it dynamic and fail it (see `do_probe`).
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_arp_nd_static_neighbor() {
        const TARGET_IP: &str = "10.0.0.2";
        let target_ip = IpAddr::from_str(TARGET_IP).unwrap();
        let static_mac = Mac([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x01]);
        let (tap0_name, tap0_ifindex) = create_tap("tap0").await;

        // the kernel has a static entry for the target before the daemon starts
        set_neigh(
            tap0_ifindex.to_u32(),
            target_ip,
            Some(static_mac),
            NeighbourState::Permanent,
        )
        .await
        .unwrap();

        // start the daemon, with ARP/ND enabled over tap0
        let arpnd: ArpSetup<TestBuffer> = ArpSetup::new();
        let nf = arpnd.nf.clone();
        let subs = test_subsystem();
        let (jh, ctl) = arpnd.launch(&Handle::current(), &subs).unwrap();
        ctl.enable(&[tap0_name]).await.unwrap();

        // the packet to the target comes back resolved with the static mac
        let returned = punt_packet(nf, packet_to_resolve(TARGET_IP, tap0_ifindex))
            .await
            .unwrap();
        assert_eq!(returned.len(), 1, "the packet was not returned");
        let packet = &returned[0];
        assert_eq!(packet.get_done(), Some(DoneReason::Delivered));
        assert!(!packet.meta().need_arp_nd());
        assert_eq!(packet.eth_destination().unwrap(), static_mac);

        // the static entry was not queried: it is still permanent
        assert_eq!(
            get_neigh_state(tap0_ifindex.to_u32(), target_ip).await,
            Some(NeighbourState::Permanent)
        );

        subs.cancel_token().cancel();
        jh.await.unwrap();
    }
}
