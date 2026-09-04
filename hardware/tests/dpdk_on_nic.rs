// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Real-hardware tx/rx validation across a cabled two-port Mellanox NIC.
//!
//! Our first-class targets are ConnectX-7/8/9 and BlueField-3. This test drives one of them
//! directly on the host -- no VM, no emulated NIC -- and asserts that a frame put on the wire by
//! one port is dequeued by the other.
//!
//! # Why this needs no root, and no vfio-pci
//!
//! mlx5 is a *bifurcated* driver. Unlike the Intel PMDs, DPDK does not take the device away from
//! the kernel: it attaches through the RDMA verbs/DevX interface (`/dev/infiniband/uverbs*`) while
//! `mlx5_core` keeps the netdev. So there is no `vfio-pci` bind, no unbind from `mlx5_core`, and no
//! IOMMU group juggling -- the steps the [`dpdk_in_vm`](dpdk_in_vm) suite needs for emulated NICs
//! are all inapplicable here.
//!
//! What it does need is three capabilities, each established by bisection against a BlueField-3
//! rather than guessed:
//!
//! | capability | what fails without it |
//! |---|---|
//! | `cap_ipc_lock` | `mlockall()` and DMA memory registration, against a default 8 MiB `RLIMIT_MEMLOCK` |
//! | `cap_sys_nice` | `set_mempolicy` during NUMA-aware hugepage allocation; EAL aborts in `rte_service_init` |
//! | `cap_net_raw`  | DevX object creation. The symptom is badly misleading: `DevX create TIS failed errno=121`, reported as `Cannot allocate memory`, which reads like a memory problem and is not one. `cap_net_admin` does *not* substitute. |
//!
//! Grant them to the test binary rather than running as root:
//!
//! ```text
//! sudo setcap cap_ipc_lock,cap_sys_nice,cap_net_raw+ep <test-binary>
//! ```
//!
//! Note that a file capability set is a property of the *inode*, so it is lost every time cargo
//! relinks the test binary. See `N_NIC_PCI` below for running against a prepared binary.
//!
//! # Why the destination MAC matters
//!
//! Because the kernel keeps the netdev, it also keeps the default receive steering. A frame that
//! matches no filter reaches the port's PHY and is then discarded before any DPDK queue sees it --
//! visible only as a gap between `rx_packets_phy` and the port's `rx_packets`. This test therefore
//! addresses each probe to the *peer port's actual MAC*, read back from the PMD, instead of relying
//! on promiscuous mode.
//!
//! # Why the payload is checked
//!
//! Both ports see background multicast (IPv6 router solicitations, LLDP) at a few tens of frames
//! per minute. A test that asserted only "some frame arrived" would pass on that noise alone --
//! during development an early version did exactly that, reporting 34 received frames when the
//! sender had emitted 32. Every probe therefore carries a unique EtherType and a magic payload
//! carrying a per-run nonce and a sequence number, and only frames matching all three are counted.
//!
//! # Why there is a warm-up round
//!
//! The mlx5 PMD installs its receive steering as part of device start, and frames that reach the
//! port before that programming lands are dropped before any queue sees them. Measured on a
//! BlueField-3 across repeated runs: the very first burst after start loses between zero and five
//! frames, always in the first direction exercised, and every burst after that is lossless. So the
//! test warms up until a round is lossless in both directions before it measures anything, which
//! lets the measured assertion stay exact equality. Loosening that assertion to tolerate a few lost
//! frames instead would have blinded it to precisely the kind of loss it exists to catch.
//!
//! Warming up *until the path proves itself clean* rather than for a fixed duration matters: the
//! settling is time-based, and an earlier fixed 500 ms warm-up was occasionally too short, so the
//! loss simply moved into the measured round.
//!
//! # Running it
//!
//! Gated behind `--cfg nic_loopback_tests`, because it needs a specific machine: two ports of one
//! card cabled to each other, and the capabilities above. It is not `#[ignore]`d, because it is a
//! perfectly valid test wherever that rig exists.
//!
//! ```text
//! RUSTFLAGS="--cfg nic_loopback_tests" cargo nextest run -p dataplane-hardware --test dpdk_on_nic
//! ```
//!
//! `N_NIC_PCI` overrides port selection (`"0000:02:00.0,0000:02:00.1"`); otherwise the two ports are
//! discovered by walking sysfs for mlx5 devices whose netdevs both report carrier.

#![cfg(nic_loopback_tests)]

use std::time::{Duration, Instant};

use dpdk::dev::{DevConfig, RxOffload, TxOffloadConfig};
use dpdk::eal;
use dpdk::mem::{MbufArray, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use net::buffer::Append;
use net::eth::mac::Mac;

/// An EtherType from the range IEEE reserves for local experimental use, so a probe can never be
/// confused with real protocol traffic sharing the wire.
const PROBE_ETHERTYPE: u16 = 0x88B5;

/// Marks a frame as ours. Checked together with the EtherType and the per-run nonce.
const PROBE_MAGIC: &[u8; 8] = b"HHDPDKTX";

/// Probes sent per direction. Exactly one burst: [`MbufArray`]'s capacity, and DPDK's
/// `PKT_BURST_SIZE`, are both 64, so this is one `rte_eth_tx_burst` and at most one
/// `rte_eth_rx_burst` to drain.
const PROBE_COUNT: u16 = 64;

/// How long to poll for probes before declaring a measured direction failed.
const RX_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to poll during a warm-up round. Warm-up loss is expected and discarded, so there is no
/// point waiting out the full [`RX_TIMEOUT`] for frames that were dropped before steering was
/// programmed.
const WARMUP_RX_TIMEOUT: Duration = Duration::from_millis(750);

/// How many warm-up rounds to allow before giving up. Each round is one burst per direction, so
/// this bounds warm-up at a few seconds while leaving plenty of headroom: in practice the path
/// converges on the first or second round.
const WARMUP_MAX_ROUNDS: usize = 12;

/// The smallest legal Ethernet payload, so probes are never runts.
const PROBE_PAYLOAD_LEN: usize = 46;

/// A probe frame: `dst | src | ethertype | magic | nonce | seq | padding`.
fn build_probe(dst: Mac, src: Mac, nonce: u32, seq: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + PROBE_PAYLOAD_LEN);
    frame.extend_from_slice(&dst.0);
    frame.extend_from_slice(&src.0);
    frame.extend_from_slice(&PROBE_ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(PROBE_MAGIC);
    frame.extend_from_slice(&nonce.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.resize(14 + PROBE_PAYLOAD_LEN, 0);
    frame
}

/// The sequence number of a frame that is one of *our* probes, or `None` for anything else.
///
/// Checks the EtherType, the magic, and the nonce, so neither background traffic nor a probe left
/// over in a queue from an earlier run can be miscounted.
fn probe_seq(frame: &[u8], nonce: u32) -> Option<u16> {
    if frame.len() < 14 + 14 {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != PROBE_ETHERTYPE {
        return None;
    }
    if &frame[14..22] != PROBE_MAGIC {
        return None;
    }
    if u32::from_be_bytes([frame[22], frame[23], frame[24], frame[25]]) != nonce {
        return None;
    }
    Some(u16::from_be_bytes([frame[26], frame[27]]))
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
        let dev_link = entry.path().join("device");
        let Ok(dev_path) = std::fs::canonicalize(&dev_link) else {
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

/// A configured, started port with its queues and the pool backing them.
struct Port<'eal> {
    dev: dpdk::dev::Dev<'eal, dpdk::dev::Started>,
    mac: Mac,
    /// The pool transmitted mbufs are drawn from. A `Pool` is a `Copy` handle branded with the
    /// EAL's lifetime; the mempool itself belongs to `mem::Manager` and is freed during `Eal`
    /// teardown, after every device has been closed. So the ordering this field used to need an
    /// explicit `drop` to get right is now structural, and unexpressible to get wrong.
    tx_pool: Pool<'eal>,
}

impl Port<'_> {
    /// Stop and close the port explicitly.
    ///
    /// `PortLifecycle`'s `Drop` would do this as a backstop, but only the explicit path can report
    /// the driver's error rather than logging it, and a port that fails to close leaks its queue
    /// rings for the rest of the process.
    fn shutdown(self, tag: &str) {
        self.dev
            .stop()
            .unwrap_or_else(|e| panic!("[{tag}] failed to stop device: {e}"))
            .close()
            .unwrap_or_else(|e| panic!("[{tag}] failed to close device: {e}"));
    }
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
                format!("rx_pool_{tag}"),
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
                format!("tx_pool_{tag}"),
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

/// Send `PROBE_COUNT` probes from `from` to `to` and count how many arrive intact.
///
/// Returns `(sent, received, out_of_order_or_duplicate)`.
/// One direction of the probe: the tx queue frames leave by, the rx queue they should arrive on,
/// and what building a frame needs.
///
/// The queues are passed in rather than looked up from the `Port`s because a queue handle is now
/// exclusively owned -- `take_queues` hands the set out once -- so they are taken up front in the
/// test body and lent to each direction in turn. That is also what makes the aliasing this
/// function used to rely on (two lookups of the same queue per round, four rounds) impossible.
struct Direction<'a, 'dev> {
    tx: &'a mut dpdk::queue::tx::TxQueue<'dev>,
    rx: &'a mut dpdk::queue::rx::RxQueue<'dev>,
    tx_pool: &'a Pool<'dev>,
    src_mac: Mac,
    dst_mac: Mac,
}

fn run_direction(
    dir: Direction<'_, '_>,
    nonce_base: u32,
    timeout: Duration,
    label: &str,
) -> (usize, usize, usize) {
    // Distinct per (round, direction): a straggler from the warm-up must never be counted as a
    // measured probe, and a late a->b frame must never be counted in b->a.
    let nonce = nonce_base
        ^ (label
            .bytes()
            .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(u32::from(b))));
    let Direction {
        tx: tx_queue,
        rx: rx_queue,
        tx_pool,
        src_mac,
        dst_mac,
    } = dir;

    // Drain anything already sitting in the rx ring (background multicast, or a straggler from the
    // other direction) so it cannot be mistaken for a probe or occupy descriptors.
    while !rx_queue.receive().is_empty() {}

    let mut sent = 0usize;
    for chunk_start in (0..PROBE_COUNT).step_by(64) {
        let chunk_end = (chunk_start + 64).min(PROBE_COUNT);
        let frames: Vec<Vec<u8>> = (chunk_start..chunk_end)
            .map(|seq| build_probe(dst_mac, src_mac, nonce, seq))
            .collect();

        let mbufs = tx_pool
            .alloc_bulk(frames.len())
            .expect("failed to allocate probe mbufs");
        let mut batch = MbufArray::new_empty();
        for (mut mbuf, frame) in mbufs.into_iter().zip(&frames) {
            let data = mbuf
                .append(frame.len() as u16)
                .expect("failed to extend mbuf tailroom for probe frame");
            data[..frame.len()].copy_from_slice(frame);
            assert!(
                batch.try_push(mbuf).is_ok(),
                "probe batch exceeded MbufArray capacity",
            );
        }

        let attempted = batch.len();
        let unsent = tx_queue.transmit(batch);
        assert!(
            unsent.is_empty(),
            "[{label}] tx queue refused {refused} of {attempted} probes -- \
             a burst this small on a 1024-descriptor queue has no legitimate reason to be refused",
            refused = unsent.len(),
        );
        sent += attempted;
    }

    // Poll until every probe is accounted for, or the deadline passes. A short poll after the last
    // arrival keeps a slow link from being reported as loss.
    let mut seen = vec![false; PROBE_COUNT as usize];
    let mut received = 0usize;
    let mut anomalies = 0usize;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && received < sent {
        for mbuf in rx_queue.receive() {
            let Some(seq) = probe_seq(mbuf.raw_data(), nonce) else {
                continue;
            };
            match seen.get_mut(seq as usize) {
                // A sequence number we never sent, or one seen twice.
                None => anomalies += 1,
                Some(true) => anomalies += 1,
                Some(slot) => {
                    *slot = true;
                    received += 1;
                }
            }
        }
    }

    let missing: Vec<u16> = seen
        .iter()
        .enumerate()
        .filter_map(|(i, got)| (!got).then_some(i as u16))
        .collect();
    eprintln!("[{label}] sent {sent}, received {received}, anomalies {anomalies}");
    if !missing.is_empty() {
        eprintln!("[{label}] missing seqs: {missing:?}");
    }
    (sent, received, anomalies)
}

/// Put frames on the wire from each port of a cabled pair and confirm the other one dequeues them.
///
/// One test rather than several: `rte_eal_init` is process-global and may only run once, so
/// splitting the directions across test functions would race in nextest's shared binary.
#[test]
fn tx_and_rx_across_a_cabled_nic_pair() {
    let (bdf_a, bdf_b) = match select_ports() {
        Ok(pair) => pair,
        Err(why) => panic!(
            "no usable NIC pair: {why}\n\
             This test needs two ports of one Mellanox card cabled to each other."
        ),
    };
    eprintln!("[nic] driving {bdf_a} <-> {bdf_b}");

    // `--in-memory` avoids needing a writable hugetlbfs directory: EAL backs its pages with memfd
    // instead of files under a mount, so the test needs no privileged setup beyond the three
    // capabilities documented at the top of this file.
    let eal = eal::init([
        "dpdk-nic-test",
        "--in-memory",
        "--file-prefix",
        "hh-nic-test",
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
    let port_a = bring_up(&eal, infos.next().expect("port A"), "a");
    let port_b = bring_up(&eal, infos.next().expect("port B"), "b");

    assert_ne!(
        port_a.mac, port_b.mac,
        "both ports report the same MAC; they are not distinct ports"
    );

    // Take each port's queues once, up front. `take_queues` hands the set out exactly once per
    // device, and each queue leaves the set by value, so these handles are the only way to drive
    // those queues for the rest of the test.
    let mut queues_a = port_a
        .dev
        .take_queues()
        .expect("port A queues already taken");
    let mut queues_b = port_b
        .dev
        .take_queues()
        .expect("port B queues already taken");
    let mut tx_a = queues_a
        .take_tx(TxQueueIndex(0))
        .expect("port A tx queue 0 missing after start");
    let mut rx_a = queues_a
        .take_rx(RxQueueIndex(0))
        .expect("port A rx queue 0 missing after start");
    let mut tx_b = queues_b
        .take_tx(TxQueueIndex(0))
        .expect("port B tx queue 0 missing after start");
    let mut rx_b = queues_b
        .take_rx(RxQueueIndex(0))
        .expect("port B rx queue 0 missing after start");

    // A per-run nonce so a probe stranded in a queue from an earlier run cannot be counted here.
    let nonce = std::process::id();

    // Warm-up, discarded. The mlx5 PMD installs its receive steering as part of device start, and
    // frames that reach the port before that programming lands are dropped before any queue sees
    // them. Measured on a BlueField-3: the very first burst after start loses a handful of frames
    // in the first direction exercised, while every subsequent burst is lossless. Rather than
    // loosen the assertion to tolerate that -- which would blind the test to real loss -- absorb it
    // in a round whose result is thrown away.
    let mut converged = false;
    for round in 0..WARMUP_MAX_ROUNDS {
        let nonce = nonce.wrapping_add(round as u32 * 0x0100_0000);
        let (sent_ab, recv_ab, _) = run_direction(
            Direction {
                tx: &mut tx_a,
                rx: &mut rx_b,
                tx_pool: &port_a.tx_pool,
                src_mac: port_a.mac,
                dst_mac: port_b.mac,
            },
            nonce,
            WARMUP_RX_TIMEOUT,
            "warmup a->b",
        );
        let (sent_ba, recv_ba, _) = run_direction(
            Direction {
                tx: &mut tx_b,
                rx: &mut rx_a,
                tx_pool: &port_b.tx_pool,
                src_mac: port_b.mac,
                dst_mac: port_a.mac,
            },
            nonce,
            WARMUP_RX_TIMEOUT,
            "warmup b->a",
        );
        if recv_ab == sent_ab && recv_ba == sent_ba {
            eprintln!("[warmup] path converged after {} round(s)", round + 1);
            converged = true;
            break;
        }
    }
    assert!(
        converged,
        "the path never became lossless across {WARMUP_MAX_ROUNDS} warm-up rounds --          this is not start-up settling, it is persistent loss on a direct cable"
    );

    let (sent_ab, recv_ab, anom_ab) = run_direction(
        Direction {
            tx: &mut tx_a,
            rx: &mut rx_b,
            tx_pool: &port_a.tx_pool,
            src_mac: port_a.mac,
            dst_mac: port_b.mac,
        },
        nonce,
        RX_TIMEOUT,
        "a->b",
    );
    let (sent_ba, recv_ba, anom_ba) = run_direction(
        Direction {
            tx: &mut tx_b,
            rx: &mut rx_a,
            tx_pool: &port_b.tx_pool,
            src_mac: port_b.mac,
            dst_mac: port_a.mac,
        },
        nonce,
        RX_TIMEOUT,
        "b->a",
    );

    port_a.shutdown("a");
    port_b.shutdown("b");
    drop(eal);

    // Every probe must arrive. This is a direct cable with no contention, a 64-frame burst against
    // a 1024-descriptor queue: loss here is a real defect, not a capacity limit.
    assert_eq!(
        recv_ab,
        sent_ab,
        "a->b lost {} of {sent_ab} probes",
        sent_ab - recv_ab
    );
    assert_eq!(
        recv_ba,
        sent_ba,
        "b->a lost {} of {sent_ba} probes",
        sent_ba - recv_ba
    );
    assert_eq!(anom_ab, 0, "a->b saw duplicate or unsent sequence numbers");
    assert_eq!(anom_ba, 0, "b->a saw duplicate or unsent sequence numbers");

    eprintln!("=== tx/rx validated on real hardware in both directions ===");
}
