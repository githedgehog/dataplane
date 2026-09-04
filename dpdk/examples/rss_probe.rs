// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! RSS-hash faithfulness probe (trust-ladder primitive).
//!
//! Brings up one mlx5 port with RSS over a *known* key and IPv4 (src+dst address) hashing, then for
//! every received packet recomputes the Toeplitz hash in software over that packet's own addresses
//! and compares it to the hash the NIC reported in the mbuf (`mbuf.hash.rss`).  A match proves the
//! NIC's RSS hash is faithful to our software model -- the basis for `owner_core(flow)` being a
//! reproducible source of truth (see the RSS design).
//!
//! It reads the key back from the device after setting it, so the software side uses whatever the
//! NIC actually adopted (not just what we asked for).  No MARK/FDIR rule is installed: those
//! overwrite the hash union in the mbuf, which is exactly why the MARK probe saw `rss_hash=None`.
//!
//! Inject *varied* IPv4 from the cabled peer (so hashes differ):
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count> 0800 vary
//!
//! Run as root:
//!   sudo ./rss_probe 0000:e1:00.1 [seconds=10]

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RssConf, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{RTE_ETH_RSS_IPV4, rte_eth_dev_rss_hash_conf_get, rte_eth_rss_conf};

type Err = Box<dyn std::error::Error>;

/// The standard 40-byte Microsoft/Toeplitz RSS key (what we ask the NIC to adopt).
const RSS_KEY: [u8; 40] = [
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
];

/// Standard Toeplitz RSS hash: slide a 32-bit window along the (big-endian) key bit-stream, XOR the
/// window into the result for every set input bit (MSB-first).  `key` must hold at least
/// `data.len()*8 + 32` bits.
fn toeplitz(key: &[u8], data: &[u8]) -> u32 {
    let key_bit = |p: usize| -> u32 { u32::from((key[p / 8] >> (7 - (p % 8))) & 1) };
    let window = |p: usize| -> u32 {
        let mut w = 0u32;
        for b in 0..32 {
            w = (w << 1) | key_bit(p + b);
        }
        w
    };
    let mut result = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        for b in 0..8 {
            if (byte >> (7 - b)) & 1 == 1 {
                result ^= window(i * 8 + b);
            }
        }
    }
    result
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;
    const N_RXQ: u16 = 4;

    let eal = eal::init([
        "-a",
        bdf.as_str(),
        "-n",
        "4",
        "--in-memory",
        "--iova-mode=va",
        "-l",
        "0-1",
        "--no-telemetry",
    ]);

    let info = eal
        .dev
        .iter()
        .next()
        .ok_or("no DPDK port probed -- check the BDF / run as root")?;

    let cfg = DevConfig {
        num_rx_queues: N_RXQ,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: None,
        rx_offloads: None, // None => all supported, which includes RTE_ETH_RX_OFFLOAD_RSS_HASH
        mtu: None,
        rss: Some(RssConf {
            key: RSS_KEY,
            hf: u64::from(RTE_ETH_RSS_IPV4),
        }),
    };
    let mut dev = cfg
        .apply(info)
        .map_err(|e| format!("dev configure: {e:?}"))?;
    let idx = dev.info.index();
    let port = idx.as_u16();
    println!("port {bdf} probed as dpdk index {port}; bringing up {N_RXQ} rx + 1 tx queue");

    for q in 0..N_RXQ {
        let pool = eal
            .mem
            .new_pkt_pool(
                PoolConfig::new(format!("rss_pool_{q}"), PoolParams::default())
                    .map_err(|e| format!("pool config: {e:?}"))?,
            )
            .map_err(|e| format!("pool create: {e:?}"))?;
        dev.new_rx_queue(RxQueueConfig {
            dev: idx,
            queue_index: RxQueueIndex(q),
            num_descriptors: 1024,
            socket_preference: Preference::CurrentThread,
            offloads: RxOffload::from(0u64),
            pool,
        })?;
    }
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::CurrentThread,
        config: (),
    })?;
    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;

    // RSS was configured at configure time (DevConfig.rss, above).  Read back what the NIC actually
    // adopted so the software side hashes with the NIC's real key/hf.
    let mut got_key = [0u8; 64];
    let mut got = unsafe { core::mem::zeroed::<rte_eth_rss_conf>() };
    got.rss_key = got_key.as_mut_ptr();
    got.rss_key_len = got_key.len() as u8;
    let rc2 = unsafe { rte_eth_dev_rss_hash_conf_get(port, &mut got) };
    let klen = got.rss_key_len as usize;
    println!(
        "rss_hash_conf_get -> {rc2}; actual hf=0x{:x}, key_len={klen}, key[0..8]={:02x?}",
        got.rss_hf,
        &got_key[..klen.min(8)],
    );
    let key = &got_key[..klen.min(got_key.len())];

    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut hashed, mut no_hash, mut matched, mut mismatched) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut samples = 0u32;
    println!("polling {N_RXQ} rx queues for {secs}s -- inject varied IPv4 now...");

    // Each queue is owned for the duration of the poll loop.  Previously this looked the queue up
    // from the device on every iteration, which handed out an alias per lookup -- exactly what
    // `take_rx` now prevents.
    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxqs: Vec<_> = (0..N_RXQ)
        .filter_map(|q| queues.take_rx(RxQueueIndex(q)))
        .collect();

    while Instant::now() < deadline {
        let mut idle = true;
        for rxq in &mut rxqs {
            let burst = rxq.receive();
            if burst.is_empty() {
                continue;
            }
            idle = false;
            for m in &burst {
                let frame: &[u8] = m.as_ref();
                // only our injected IPv4 frames: src MAC = port0, ethertype 0x0800
                if frame.len() < 34
                    || frame[6..12] != [0x58, 0xa2, 0xe1, 0x04, 0x31, 0xa8]
                    || frame[12..14] != [0x08, 0x00]
                {
                    continue;
                }
                total += 1;
                if total == 1 {
                    println!("  first frame ol_flags=0x{:016x}", m.ol_flags());
                }
                match m.rss_hash() {
                    None => no_hash += 1,
                    Some(nic) => {
                        hashed += 1;
                        let tuple = &frame[26..34]; // src IPv4 (4) || dst IPv4 (4)
                        let sw = toeplitz(key, tuple);
                        if sw == nic {
                            matched += 1;
                        } else {
                            mismatched += 1;
                        }
                        if samples < 6 {
                            println!(
                                "  src={:?} dst={:?}  nic=0x{nic:08x}  sw=0x{sw:08x}  {}",
                                &frame[26..30],
                                &frame[30..34],
                                if sw == nic { "match" } else { "MISMATCH" },
                            );
                            samples += 1;
                        }
                    }
                }
            }
        }
        if idle {
            std::hint::spin_loop();
        }
    }

    println!("=== summary ===");
    println!("our IPv4 frames : {total}");
    println!("nic-hashed      : {hashed}   (no-hash: {no_hash})");
    println!("matched         : {matched}");
    println!("mismatched      : {mismatched}");
    let pass = hashed > 0 && mismatched == 0 && matched == hashed;
    println!(
        "VERDICT         : {}",
        if pass {
            "PASS -- NIC RSS hash is faithful to the software Toeplitz model"
        } else if hashed == 0 {
            "INCONCLUSIVE -- NIC reported no RSS hash (hf not applied / single-queue TIR?)"
        } else {
            "FAIL -- NIC hash disagrees with software model (wrong field set / endianness / key?)"
        }
    );
    Ok(())
}
