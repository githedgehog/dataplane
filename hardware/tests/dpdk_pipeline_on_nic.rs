// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The real network-function pipeline, forwarding real frames off a real wire.
//!
//! [`dpdk_on_nic`](dpdk_on_nic) proves the transport: a frame put on the wire by one port of a
//! cabled Mellanox pair is dequeued by the other. It never builds a [`Packet`], never parses a
//! header and never runs a network function. This test is the layer above it -- the first thing in
//! the tree that puts *the dataplane's own pipeline* on the DPDK datapath:
//!
//! ```text
//!   port A  --- generator: IPv4/UDP probe, ttl 64, dst mac = B --->  port B
//!                                                                      |
//!                                          Packet::new(mbuf)           |
//!                                          DynPipeline<Mbuf>           |
//!                                            DecrementTtl              |
//!                                            RewriteDstMac             |
//!                                          Packet::serialize           |
//!                                                                      v
//!   port A  <-- verifier: ttl 63, dst mac = A, checksum valid ---   port B
//! ```
//!
//! Port A is the traffic generator and the verifier; port B is the dataplane under test. A frame
//! therefore crosses the fibre twice, and every byte the verifier checks was written by production
//! code into DPDK-owned memory.
//!
//! # What this exists to catch
//!
//! `Packet<Buf>` is generic, and until now `Buf` had only ever been [`TestBuffer`] -- a `Vec`-backed
//! buffer with generous headroom and no alignment, aliasing or ownership constraints. An `Mbuf` is
//! none of those things: its bytes live in a mempool, its headroom is whatever the PMD left, and
//! the parse/mutate/serialize round trip writes back into memory the NIC DMA'd into. Nothing
//! established that the header machinery survives that substitution, because nothing had ever run
//! it against a real one.
//!
//! The oracle is deliberately arithmetic rather than "a frame came back":
//!
//! - **TTL is exactly 63.** Not `< 64`. [`DecrementTtl`] is a production NF; if the pipeline ran
//!   twice, or not at all, or the write landed at the wrong offset, the value is not 63.
//! - **The IPv4 header checksum still verifies.** Decrementing the TTL invalidates it, so a correct
//!   checksum on arrival means the serializer recomputed it *and* wrote it into mbuf memory.
//! - **The destination MAC is port A's.** Written by a network function, over an mbuf, at offset 0
//!   -- the byte most likely to be wrong if headroom accounting is off.
//! - **Payload magic, nonce and sequence survive unchanged.** The header rewrite must not have
//!   walked into the payload.
//!
//! # Why the pipeline is short
//!
//! Two stages, not the router's fourteen. The production pipeline's stages want a configured
//! router, VPC tables, NAT allocators and interface metadata; standing all that up here would test
//! configuration plumbing, not the buffer substitution this exists for. [`DecrementTtl`] is
//! production code taken unmodified from `pipeline::sample_nfs`, and it gives a checkable
//! arithmetic result. `RewriteDstMac` is local to this test -- a next-hop MAC rewrite is what a
//! forwarding dataplane does anyway, and here it is also what gets the frame past port A's receive
//! steering (see below).
//!
//! # Rig, capabilities and steering
//!
//! Identical to [`dpdk_on_nic`](dpdk_on_nic), and its module docs are the reference: two ports of
//! one Mellanox card cabled together, no root and no `vfio-pci` (mlx5 is bifurcated), and three
//! capabilities on the test binary:
//!
//! ```text
//! sudo setcap cap_ipc_lock,cap_sys_nice,cap_net_raw+ep <test-binary>
//! ```
//!
//! File capabilities live on the inode, so cargo wipes them on every relink.
//!
//! The steering gotcha applies in *both* directions here, which is why `RewriteDstMac` is not
//! optional. The kernel keeps each netdev and therefore its default receive steering, so a frame
//! matching no filter is discarded at the PHY before any DPDK queue sees it. The generator
//! addresses port B, and the pipeline must re-address the forwarded frame to port A, or the return
//! leg vanishes with nothing to show for it but a gap in `ethtool -S`.
//!
//! # Running it
//!
//! ```text
//! RUSTFLAGS="--cfg nic_loopback_tests" cargo nextest run -p dataplane-hardware --test dpdk_pipeline_on_nic
//! ```
//!
//! `N_NIC_PCI` overrides port selection (`"0000:02:00.0,0000:02:00.1"`); otherwise the two ports
//! are discovered by walking sysfs for mlx5 devices whose netdevs both report carrier.

#![cfg(nic_loopback_tests)]

use std::time::{Duration, Instant};

use dpdk::dev::{DevConfig, RxOffload, TxOffloadConfig};
use dpdk::eal;
use dpdk::mem::{Mbuf, MbufArray, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use net::buffer::{Append, PacketBufferMut};
use net::eth::mac::{DestinationMac, Mac};
use net::headers::TryEthMut;
use net::packet::Packet;
use pipeline::sample_nfs::DecrementTtl;
use pipeline::{DynPipeline, NetworkFunction};

/// UDP destination port for probes. Together with the magic and nonce it identifies our frames;
/// unlike [`dpdk_on_nic`](dpdk_on_nic)'s experimental EtherType, these have to be real IPv4/UDP
/// packets, because the pipeline only acts on packets it can parse.
const PROBE_UDP_DPORT: u16 = 47_811;

/// Marks a frame as ours. Checked together with the nonce and the UDP port.
const PROBE_MAGIC: &[u8; 8] = b"HHDPPIPE";

/// The TTL the generator stamps on every probe. One decrement below it is the whole oracle, so it
/// is chosen well away from both 0 (where [`DecrementTtl`] drops) and 255.
const PROBE_TTL: u8 = 64;

/// Probes per round. One `rte_eth_tx_burst`: [`MbufArray`]'s capacity is 64.
const PROBE_COUNT: u16 = 64;

/// How long to run the forward-and-verify loop before declaring a measured round failed.
const ROUND_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to run a warm-up round. Warm-up loss is expected and discarded.
const WARMUP_TIMEOUT: Duration = Duration::from_millis(750);

/// How many warm-up rounds to allow before giving up. In practice the path converges on the first
/// or second.
const WARMUP_MAX_ROUNDS: usize = 12;

/// Probe payload: `magic | nonce | seq`, then padding to a round number.
const PROBE_PAYLOAD_LEN: usize = 8 + 4 + 2 + 18;

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const UDP_LEN: usize = 8;
const PROBE_FRAME_LEN: usize = ETH_LEN + IPV4_LEN + UDP_LEN + PROBE_PAYLOAD_LEN;

/// Offsets into a probe frame, which is always this exact shape (no options, no VLAN).
const IPV4_OFF: usize = ETH_LEN;
const IPV4_TTL_OFF: usize = IPV4_OFF + 8;
const UDP_OFF: usize = IPV4_OFF + IPV4_LEN;
const PAYLOAD_OFF: usize = UDP_OFF + UDP_LEN;

/// Rewrites every packet's destination MAC.
///
/// Local to this test rather than taken from `sample_nfs`, whose [`BroadcastMacs`] would set the
/// broadcast address -- which the kernel's default steering on the receiving netdev consumes, so
/// the forwarded frame would never reach port A's DPDK queue. A forwarding dataplane rewrites the
/// destination MAC to the resolved next hop anyway; this is that, with the next hop known up front.
///
/// [`BroadcastMacs`]: pipeline::sample_nfs::BroadcastMacs
struct RewriteDstMac(DestinationMac);

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for RewriteDstMac {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a
    where
        Buf: 'a,
    {
        input.map(|mut packet| {
            if let Some(eth) = packet.try_eth_mut() {
                eth.set_destination(self.0);
            }
            packet
        })
    }
}

/// The one's-complement sum used by both the IPv4 header checksum and this test's verifier.
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, remainder) = bytes.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [odd] = remainder {
        sum += u32::from(u16::from_be_bytes([*odd, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build one IPv4/UDP probe frame.
///
/// UDP carries a zero checksum, which IPv4 permits and means "not computed": the pipeline does not
/// touch the L4 checksum, so verifying it would only assert that this function and the verifier
/// agree with each other.
fn build_probe(dst: Mac, src: Mac, nonce: u32, seq: u16) -> Vec<u8> {
    let mut frame = vec![0u8; PROBE_FRAME_LEN];

    frame[0..6].copy_from_slice(&dst.0);
    frame[6..12].copy_from_slice(&src.0);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    let ip_total_len = (IPV4_LEN + UDP_LEN + PROBE_PAYLOAD_LEN) as u16;
    frame[IPV4_OFF] = 0x45; // version 4, IHL 5
    frame[IPV4_OFF + 1] = 0; // DSCP/ECN
    frame[IPV4_OFF + 2..IPV4_OFF + 4].copy_from_slice(&ip_total_len.to_be_bytes());
    frame[IPV4_OFF + 4..IPV4_OFF + 6].copy_from_slice(&seq.to_be_bytes()); // identification
    frame[IPV4_OFF + 6..IPV4_OFF + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    frame[IPV4_TTL_OFF] = PROBE_TTL;
    frame[IPV4_OFF + 9] = 17; // UDP
    // checksum at +10..+12 left zero for the computation below
    frame[IPV4_OFF + 12..IPV4_OFF + 16].copy_from_slice(&[10, 0, 0, 1]); // src 10.0.0.1
    frame[IPV4_OFF + 16..IPV4_OFF + 20].copy_from_slice(&[10, 0, 0, 2]); // dst 10.0.0.2
    let ip_csum = ones_complement_sum(&frame[IPV4_OFF..IPV4_OFF + IPV4_LEN]);
    frame[IPV4_OFF + 10..IPV4_OFF + 12].copy_from_slice(&ip_csum.to_be_bytes());

    let udp_len = (UDP_LEN + PROBE_PAYLOAD_LEN) as u16;
    frame[UDP_OFF..UDP_OFF + 2].copy_from_slice(&PROBE_UDP_DPORT.to_be_bytes());
    frame[UDP_OFF + 2..UDP_OFF + 4].copy_from_slice(&PROBE_UDP_DPORT.to_be_bytes());
    frame[UDP_OFF + 4..UDP_OFF + 6].copy_from_slice(&udp_len.to_be_bytes());
    // UDP checksum at +6..+8 stays zero: "not computed".

    frame[PAYLOAD_OFF..PAYLOAD_OFF + 8].copy_from_slice(PROBE_MAGIC);
    frame[PAYLOAD_OFF + 8..PAYLOAD_OFF + 12].copy_from_slice(&nonce.to_be_bytes());
    frame[PAYLOAD_OFF + 12..PAYLOAD_OFF + 14].copy_from_slice(&seq.to_be_bytes());

    frame
}

/// Is this one of our probes, whatever state it is in? Returns its sequence number.
///
/// Matches on payload only, so it recognises a probe both on the way in (as the generator built it)
/// and on the way back (after the pipeline rewrote its headers).
fn probe_seq(frame: &[u8], nonce: u32) -> Option<u16> {
    if frame.len() < PROBE_FRAME_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
        return None;
    }
    if frame[IPV4_OFF] != 0x45 || frame[IPV4_OFF + 9] != 17 {
        return None;
    }
    if u16::from_be_bytes([frame[UDP_OFF], frame[UDP_OFF + 1]]) != PROBE_UDP_DPORT {
        return None;
    }
    if &frame[PAYLOAD_OFF..PAYLOAD_OFF + 8] != PROBE_MAGIC {
        return None;
    }
    let got_nonce = u32::from_be_bytes([
        frame[PAYLOAD_OFF + 8],
        frame[PAYLOAD_OFF + 9],
        frame[PAYLOAD_OFF + 10],
        frame[PAYLOAD_OFF + 11],
    ]);
    if got_nonce != nonce {
        return None;
    }
    Some(u16::from_be_bytes([
        frame[PAYLOAD_OFF + 12],
        frame[PAYLOAD_OFF + 13],
    ]))
}

/// Everything the verifier checks about a frame that came back through the pipeline.
///
/// Returned rather than asserted in place so the caller can report every wrong frame in a round
/// instead of dying on the first.
fn check_forwarded(frame: &[u8], expect_dst: Mac) -> Result<(), String> {
    let ttl = frame[IPV4_TTL_OFF];
    if ttl != PROBE_TTL - 1 {
        return Err(format!(
            "ttl is {ttl}, expected exactly {} (sent {PROBE_TTL}, one DecrementTtl stage)",
            PROBE_TTL - 1
        ));
    }

    // A correct IPv4 header sums to zero over its own bytes with the checksum field included.
    let csum = ones_complement_sum(&frame[IPV4_OFF..IPV4_OFF + IPV4_LEN]);
    if csum != 0 {
        return Err(format!(
            "ipv4 header checksum does not verify (residual {csum:#06x}); \
             the serializer did not recompute it after the ttl write"
        ));
    }

    if frame[0..6] != expect_dst.0 {
        return Err(format!(
            "destination mac is {:02x?}, expected {expect_dst}",
            &frame[0..6]
        ));
    }

    Ok(())
}

/// Two PCI addresses to drive, from `N_NIC_PCI` or by discovery.
///
/// Discovery looks for mlx5 devices whose netdev reports a carrier, because a port with no cable
/// cannot pass this test and should say so rather than time out.
fn select_ports() -> Result<(String, String), String> {
    if let Ok(spec) = std::env::var("N_NIC_PCI") {
        let parts: Vec<_> = spec.split(',').map(str::trim).collect();
        if parts.len() != 2 {
            return Err(format!(
                "N_NIC_PCI must name exactly two PCI addresses, got {spec:?}"
            ));
        }
        return Ok((parts[0].to_string(), parts[1].to_string()));
    }

    let mut cabled = Vec::new();
    let entries = std::fs::read_dir("/sys/class/net")
        .map_err(|e| format!("cannot enumerate /sys/class/net: {e}"))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let iface = name.to_string_lossy().to_string();
        let Ok(dev_path) = std::fs::canonicalize(entry.path().join("device")) else {
            continue;
        };
        // Only mlx5: this test's no-root story depends on the bifurcated driver.
        let driver = std::fs::canonicalize(dev_path.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
            .unwrap_or_default();
        if driver != "mlx5_core" {
            continue;
        }
        let carrier = std::fs::read_to_string(entry.path().join("carrier"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if !carrier {
            continue;
        }
        let Some(bdf) = dev_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
        else {
            continue;
        };
        cabled.push((bdf, iface));
    }
    cabled.sort();

    match cabled.len() {
        0 | 1 => Err(format!(
            "need two cabled mlx5 ports, found {}: {cabled:?}. \
             Cable two ports of one card to each other, or set N_NIC_PCI.",
            cabled.len()
        )),
        _ => Ok((cabled[0].0.clone(), cabled[1].0.clone())),
    }
}

/// A configured, started port with the pool backing its transmits.
struct Port<'eal> {
    dev: dpdk::dev::Dev<'eal, dpdk::dev::Started>,
    mac: Mac,
    tx_pool: Pool<'eal>,
}

/// Configure, queue up and start one port.
fn bring_up<'eal>(eal: &'eal eal::Eal, info: dpdk::dev::DevInfo<'eal>, tag: &str) -> Port<'eal> {
    let config = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        // Explicitly empty rather than `None`, which would request every offload the device
        // supports -- including LRO, which would coalesce the very frames we are counting.
        rx_offloads: Some(RxOffload::NONE),
        tx_offloads: Some(TxOffloadConfig::default()),
        mtu: None,
        // A single rx queue has nothing to distribute across.
        rss: None,
    };

    let mut dev = config
        .apply(info)
        .unwrap_or_else(|e| panic!("[{tag}] failed to configure device: {e:?}"));

    let rx_pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new(
                format!("pipe_rx_{tag}"),
                PoolParams {
                    size: 2048,
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("[{tag}] invalid rx PoolConfig: {e:?}")),
        )
        .unwrap_or_else(|e| panic!("[{tag}] failed to create rx mempool: {e:?}"));

    let tx_pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new(
                format!("pipe_tx_{tag}"),
                PoolParams {
                    size: 1024,
                    cache_size: 128,
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("[{tag}] invalid tx PoolConfig: {e:?}")),
        )
        .unwrap_or_else(|e| panic!("[{tag}] failed to create tx mempool: {e:?}"));

    dev.new_rx_queue(RxQueueConfig {
        dev: dev.info.index(),
        queue_index: RxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: socket::Preference::CurrentThread,
        // Explicitly empty, for the same reason `rx_offloads` above is. Asking for the device's
        // whole per-queue capability mask is not "sensible defaults": on a BlueField-3 that mask
        // is 0x18601f, and the `TCP_LRO` bit in it costs a factor of 32 in receive buffering.
        //
        // LRO has to be able to hand back a coalesced segment of up to 64 KiB, and these pools have
        // a 2048-byte data room, so the PMD reserves ceil(65536 / 2048) = 32 descriptors for every
        // packet it might have to coalesce into. A ring asked for 1024 descriptors then buffers 32
        // frames, not 1024 -- measured exactly: with the full mask a 64-frame burst arrives as 32
        // received and 32 `imissed`, and with this `NONE` it arrives as 64 and 0.
        //
        // That is invisible to a test that polls in a tight loop, because frames are consumed as
        // fast as they land. It appears the moment anything real happens between polls, which is
        // the situation every actual dataplane is in.
        offloads: RxOffload::NONE,
        pool: rx_pool,
    })
    .unwrap_or_else(|e| panic!("[{tag}] failed to set up rx queue: {e:?}"));

    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: socket::Preference::CurrentThread,
        config: (),
    })
    .unwrap_or_else(|e| panic!("[{tag}] failed to set up tx queue: {e:?}"));

    let dev = dev
        .start()
        .unwrap_or_else(|e| panic!("[{tag}] failed to start device: {e}"));

    let mac = dev
        .mac_address()
        .unwrap_or_else(|e| panic!("[{tag}] failed to read MAC: {e:?}"));

    eprintln!("[{tag}] port {} up, mac {mac}", dev.info.index());
    Port { dev, mac, tx_pool }
}

/// Fill a batch of mbufs from `pool` with freshly built probe frames.
///
/// A named `fn` rather than a closure because a closure infers one fresh lifetime per parameter and
/// cannot tie the returned batch's brand to the pool's.
fn make_probe_batch<'eal>(
    pool: &Pool<'eal>,
    dst: Mac,
    src: Mac,
    nonce: u32,
    count: u16,
) -> MbufArray<'eal> {
    let mbufs = pool
        .alloc_bulk(count as usize)
        .expect("failed to allocate probe mbufs");
    let mut batch = MbufArray::new_empty();
    for (seq, mut mbuf) in mbufs.into_iter().enumerate() {
        let frame = build_probe(dst, src, nonce, seq as u16);
        let data = mbuf
            .append(frame.len() as u16)
            .expect("failed to extend mbuf tailroom for probe frame");
        data[..frame.len()].copy_from_slice(&frame);
        assert!(
            batch.try_push(mbuf).is_ok(),
            "probe batch exceeded MbufArray capacity"
        );
    }
    batch
}

/// Drive the dataplane port for one poll: receive, run the pipeline, transmit what survives.
///
/// Returns how many packets the pipeline emitted. This is the whole datapath under test, and it is
/// deliberately the same shape a real worker's inner loop would have.
fn forward_once<'eal>(
    rx: &mut dpdk::queue::rx::RxQueue<'eal>,
    tx: &mut dpdk::queue::tx::TxQueue<'eal>,
    pipeline: &mut DynPipeline<'eal, Mbuf<'eal>>,
    tally: &mut Tally,
) -> usize {
    let burst = rx.receive();
    if burst.is_empty() {
        return 0;
    }
    tally.dp_received += burst.len();

    // Parse. A frame that is not a packet we understand is dropped here, which also disposes of the
    // background multicast both ports see.
    let packets = burst.into_iter().filter_map(|mbuf| Packet::new(mbuf).ok());

    // Serialize writes the (possibly rewritten) headers back into the mbuf's own memory and hands
    // the mbuf back, so the batch that leaves is the batch that arrived -- no copy, no second pool.
    let mut out = MbufArray::new_empty();
    let mut emitted = 0usize;
    for packet in pipeline.process(packets) {
        match packet.serialize() {
            Ok(mbuf) => {
                assert!(
                    out.try_push(mbuf).is_ok(),
                    "forwarded batch exceeded MbufArray capacity"
                );
                emitted += 1;
            }
            Err(e) => panic!("failed to serialize a forwarded packet: {e:?}"),
        }
    }

    tally.dp_emitted += emitted;
    if emitted > 0 {
        let unsent = tx.transmit(out);
        assert!(
            unsent.is_empty(),
            "tx queue refused {} of {emitted} forwarded packets -- a burst this small on a \
             1024-descriptor queue has no legitimate reason to be refused",
            unsent.len(),
        );
    }
    emitted
}

/// Where the frames of a round ended up.
///
/// A round that loses frames is far more diagnosable with these than without: they separate "the
/// dataplane port never saw it" from "the pipeline dropped it" from "it was forwarded and lost on
/// the way back", which are three completely different bugs.
#[derive(Default, Debug)]
struct Tally {
    /// Frames the dataplane port dequeued (probes and background traffic alike).
    dp_received: usize,
    /// Packets the pipeline emitted, and so were handed to the dataplane's tx queue.
    dp_emitted: usize,
    /// Frames the generator port dequeued on the return leg, of any kind.
    gen_received: usize,
    /// Of those, ones recognisable as this round's probes.
    gen_matched: usize,
}

/// One round: generate on A, forward on B, verify what comes back to A.
///
/// Returns `(sent, verified, failures)`.
struct Round<'a, 'eal> {
    gen_tx: &'a mut dpdk::queue::tx::TxQueue<'eal>,
    gen_rx: &'a mut dpdk::queue::rx::RxQueue<'eal>,
    gen_pool: &'a Pool<'eal>,
    gen_mac: Mac,
    dp_rx: &'a mut dpdk::queue::rx::RxQueue<'eal>,
    dp_tx: &'a mut dpdk::queue::tx::TxQueue<'eal>,
    pipeline: &'a mut DynPipeline<'eal, Mbuf<'eal>>,
    dp_mac: Mac,
}

fn run_round(
    r: Round<'_, '_>,
    nonce: u32,
    timeout: Duration,
) -> (usize, usize, Vec<String>, Tally) {
    let Round {
        gen_tx,
        gen_rx,
        gen_pool,
        gen_mac,
        dp_rx,
        dp_tx,
        pipeline,
        dp_mac,
    } = r;

    // Drain both rx rings: background multicast, or stragglers from an earlier round, must not be
    // able to occupy descriptors or be miscounted.
    while !gen_rx.receive().is_empty() {}
    while !dp_rx.receive().is_empty() {}

    let batch = make_probe_batch(gen_pool, dp_mac, gen_mac, nonce, PROBE_COUNT);
    let sent = batch.len();
    let unsent = gen_tx.transmit(batch);
    assert!(
        unsent.is_empty(),
        "generator tx refused {} of {sent} probes",
        unsent.len(),
    );

    let mut seen = vec![false; PROBE_COUNT as usize];
    let mut verified = 0usize;
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline && verified + failures.len() < sent {
        // Pump the dataplane. This is the code under test.
        forward_once(dp_rx, dp_tx, pipeline, &mut tally);

        // Collect and check whatever made it back round the loop.
        let returned = gen_rx.receive();
        tally.gen_received += returned.len();
        for mbuf in returned {
            let frame = mbuf.raw_data();
            let Some(seq) = probe_seq(frame, nonce) else {
                continue;
            };
            tally.gen_matched += 1;
            match seen.get_mut(seq as usize) {
                None => failures.push(format!("seq {seq} out of range")),
                Some(true) => failures.push(format!("seq {seq} arrived twice")),
                Some(slot) => {
                    *slot = true;
                    match check_forwarded(frame, gen_mac) {
                        Ok(()) => verified += 1,
                        Err(why) => failures.push(format!("seq {seq}: {why}")),
                    }
                }
            }
        }
    }

    (sent, verified, failures, tally)
}

/// Forward real frames through the real pipeline across a cabled NIC pair.
///
/// One test rather than several: `rte_eal_init` is process-global and may only run once, so
/// splitting this up would race in nextest's shared binary.
#[test]
fn the_pipeline_forwards_frames_across_a_cabled_nic_pair() {
    let (bdf_a, bdf_b) = match select_ports() {
        Ok(pair) => pair,
        Err(why) => panic!(
            "no usable NIC pair: {why}\n\
             This test needs two ports of one Mellanox card cabled to each other."
        ),
    };
    eprintln!("[nic] generator {bdf_a} <-> dataplane {bdf_b}");

    // `--in-memory` avoids needing a writable hugetlbfs directory: EAL backs its pages with memfd
    // instead of files under a mount, so the test needs no privileged setup beyond the three
    // capabilities documented at the top of this file.
    let eal = eal::init([
        "dpdk-pipeline-test",
        "--in-memory",
        "--file-prefix",
        "hh-pipe-test",
        "-a",
        bdf_a.as_str(),
        "-a",
        bdf_b.as_str(),
    ]);

    let infos: Vec<_> = eal.dev.iter().collect();
    assert_eq!(
        infos.len(),
        2,
        "expected DPDK to probe exactly 2 ports, got {}. \
         If this is 0, the usual cause is a missing capability: the mlx5 PMD reports \
         'DevX create TIS failed' / 'Cannot allocate memory' when it lacks cap_net_raw. \
         Try: sudo setcap cap_ipc_lock,cap_sys_nice,cap_net_raw+ep <this binary>",
        infos.len(),
    );

    let mut infos = infos.into_iter();
    let gen_port = bring_up(&eal, infos.next().expect("port A"), "gen");
    let dp_port = bring_up(&eal, infos.next().expect("port B"), "dataplane");

    assert_ne!(
        gen_port.mac, dp_port.mac,
        "both ports report the same MAC; they are not distinct ports"
    );

    // The pipeline under test: production `DecrementTtl`, then the next-hop MAC rewrite that gets
    // the frame past the generator port's receive steering.
    let mut pipeline: DynPipeline<Mbuf<'_>> =
        DynPipeline::new()
            .add_stage(DecrementTtl)
            .add_stage(RewriteDstMac(
                DestinationMac::new(gen_port.mac)
                    .expect("generator mac is not a valid destination"),
            ));

    let mut gen_queues = gen_port
        .dev
        .take_queues()
        .expect("generator queues already taken");
    let mut dp_queues = dp_port
        .dev
        .take_queues()
        .expect("dataplane queues already taken");
    let mut gen_tx = gen_queues
        .take_tx(TxQueueIndex(0))
        .expect("generator tx queue 0 missing after start");
    let mut gen_rx = gen_queues
        .take_rx(RxQueueIndex(0))
        .expect("generator rx queue 0 missing after start");
    let mut dp_tx = dp_queues
        .take_tx(TxQueueIndex(0))
        .expect("dataplane tx queue 0 missing after start");
    let mut dp_rx = dp_queues
        .take_rx(RxQueueIndex(0))
        .expect("dataplane rx queue 0 missing after start");

    // A per-run nonce so a probe stranded in a queue from an earlier run cannot be counted here.
    let base_nonce = std::process::id();

    // Warm-up, discarded. The mlx5 PMD installs its receive steering as part of device start, and
    // frames that reach a port before that programming lands are dropped before any queue sees
    // them. Two ports have to settle here rather than one, and a frame crosses the fibre twice, so
    // warm up until a round is clean rather than for a fixed duration -- a fixed warm-up that is
    // occasionally too short just moves the loss into the measured round.
    let mut converged = false;
    for round in 0..WARMUP_MAX_ROUNDS {
        let nonce = base_nonce.wrapping_add((round as u32 + 1) * 0x0100_0000);
        let (sent, verified, failures, tally) = run_round(
            Round {
                gen_tx: &mut gen_tx,
                gen_rx: &mut gen_rx,
                gen_pool: &gen_port.tx_pool,
                gen_mac: gen_port.mac,
                dp_rx: &mut dp_rx,
                dp_tx: &mut dp_tx,
                pipeline: &mut pipeline,
                dp_mac: dp_port.mac,
            },
            nonce,
            WARMUP_TIMEOUT,
        );
        eprintln!(
            "[warmup {round}] sent {sent}, verified {verified}, failures {}, {tally:?}",
            failures.len()
        );
        if verified == sent && failures.is_empty() {
            converged = true;
            break;
        }
    }
    assert!(
        converged,
        "the forwarding path never produced a lossless round in {WARMUP_MAX_ROUNDS} warm-up \
         attempts; it is not merely settling"
    );

    // Counters before the measured round, so the assertions below can be about that round alone
    // rather than about the warm-up's expected losses.
    let dp_before = dp_port
        .dev
        .stats()
        .expect("failed to read dataplane port stats");

    // The measured round. Exact equality: every probe generated must come back forwarded and
    // correct. Tolerating a few would blind this to the loss and corruption it exists to catch.
    let (sent, verified, failures, tally) = run_round(
        Round {
            gen_tx: &mut gen_tx,
            gen_rx: &mut gen_rx,
            gen_pool: &gen_port.tx_pool,
            gen_mac: gen_port.mac,
            dp_rx: &mut dp_rx,
            dp_tx: &mut dp_tx,
            pipeline: &mut pipeline,
            dp_mac: dp_port.mac,
        },
        base_nonce,
        ROUND_TIMEOUT,
    );

    eprintln!(
        "[measured] sent {sent}, verified {verified}, failures {}, {tally:?}",
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} of {sent} forwarded frames were wrong:\n  {}",
        failures.len(),
        failures.join("\n  "),
    );
    assert_eq!(
        verified, sent,
        "only {verified} of {sent} probes came back through the pipeline; {tally:?}"
    );

    // Assert on the port's own counters, not just on what came back.
    //
    // This is what makes the test an oracle for receive-side configuration rather than a race it
    // happens to win. `imissed` is the port saying it had a frame and had nowhere to put it, and it
    // is the *only* signal that separates that from a frame the wire never carried -- `ethtool -S`
    // cannot, because on a bifurcated driver it reports the kernel's queues, not DPDK's.
    //
    // Without this, the `TCP_LRO` misconfiguration that cost 32x the receive buffering (see the
    // offload comment in `bring_up`) is caught only when processing is slow enough between polls
    // for the shortfall to matter -- true in a debug build, and not something to rely on.
    let dp_after = dp_port
        .dev
        .stats()
        .expect("failed to read dataplane port stats");

    let imissed = dp_after.imissed - dp_before.imissed;
    assert_eq!(
        imissed, 0,
        "the dataplane port dropped {imissed} frames for want of a free receive descriptor. \
         The ring is asked for 1024; if this is non-zero with a burst of {sent}, the queue is \
         not buffering anything like that -- check the rx offloads, LRO in particular."
    );

    let nombuf = dp_after.rx_nombuf - dp_before.rx_nombuf;
    assert_eq!(
        nombuf, 0,
        "the dataplane port failed to allocate an rx mbuf {nombuf} times: its mempool is too small"
    );
}
