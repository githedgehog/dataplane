// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! RSS capability probe: what a real device will and will not accept at configure time.
//!
//! The driver's RSS configuration rests on three claims read out of the DPDK source. Each one is
//! the kind that is cheap to get wrong and expensive to debug, because `rte_eth_dev_configure`
//! reports every one of them as a bare `-EINVAL`. This probe checks all three against a live
//! device rather than against `rte_ethdev.c`:
//!
//! 1. `dev_info.rss_algo_capa` advertises **only** `RTE_ETH_HASH_FUNCTION_DEFAULT` on mlx5, because
//!    the ethdev layer initialises it to that and mlx5's `dev_infos_get` never widens it. So
//!    symmetric Toeplitz cannot be requested here at all -- it is reachable only through the
//!    `rte_flow` RSS action.
//! 2. `dev_info.hash_key_size` is 40, which is the *exact* key length configure will accept.
//! 3. `dev_info.flow_type_rss_offloads` covers the L3 and L4 hash types
//!    [`RssConf::supported_on`] asks for, so the intersection does not silently narrow.
//!
//! It then does the two things that actually matter: configures the port the way the dataplane
//! driver configures it (RSS on, `RSS_HASH` offload on) and confirms that succeeds, and asks for
//! `RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ` and confirms that it is *rejected*. A claim that
//! something is impossible is worth nothing until the failure has been seen.
//!
//! Needs no traffic and no cabled peer -- it never starts the port.
//!
//! Run (see `dpdk-driver-spike` for the container recipe; needs `IPC_LOCK`):
//!   ./rss_capability_probe 0000:02:00.1

use dataplane_dpdk::dev::{DevConfig, RssConf, RxOffload, TxOffloadConfig};
use dataplane_dpdk::eal;

use dpdk_sys::{
    rte_eth_dev_configure, rte_eth_dev_info, rte_eth_dev_info_get, rte_eth_hash_function,
    rte_eth_rss_conf,
};

type Err = Box<dyn std::error::Error>;

/// Names for the `rte_eth_hash_function` values, for reporting the capability mask readably.
const ALGO_NAMES: [(u32, &str); 5] = [
    (0, "DEFAULT"),
    (1, "TOEPLITZ"),
    (2, "SIMPLE_XOR"),
    (3, "SYMMETRIC_TOEPLITZ"),
    (4, "SYMMETRIC_TOEPLITZ_SORT"),
];

fn describe_algo_capa(capa: u32) -> String {
    let named: Vec<&str> = ALGO_NAMES
        .iter()
        .filter(|(bit, _)| capa & (1u32 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();
    if named.is_empty() {
        "(none)".to_string()
    } else {
        named.join(" | ")
    }
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:02:00.1".to_string());

    let eal = eal::init([
        "-a",
        bdf.as_str(),
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--iova-mode=va",
    ]);

    let info = eal
        .dev
        .iter()
        .next()
        .ok_or("no DPDK port probed -- check the BDF and that the device is bound")?;
    let port = info.index().as_u16();

    // Read the raw dev_info too: `rss_algo_capa` is the field the whole question turns on and the
    // safe wrapper deliberately does not expose it (nothing may usefully ask for a non-default
    // algorithm, so exposing it would only invite trying).
    let mut raw: rte_eth_dev_info = unsafe { core::mem::zeroed() };
    let rc = unsafe { rte_eth_dev_info_get(port, &raw mut raw) };
    if rc != 0 {
        return Err(format!("rte_eth_dev_info_get failed: {rc}").into());
    }

    println!("port {port} ({bdf}), driver {}", info.driver_name());
    println!("  hash_key_size           = {}", raw.hash_key_size);
    println!(
        "  flow_type_rss_offloads  = {:#x}",
        raw.flow_type_rss_offloads
    );
    println!(
        "  rss_algo_capa           = {:#x}  [{}]",
        raw.rss_algo_capa,
        describe_algo_capa(raw.rss_algo_capa)
    );

    let mut failures: Vec<String> = Vec::new();

    // Claim 1: only the default hash function is advertised.
    // `RTE_ETH_HASH_ALGO_TO_CAPA(x)` is `RTE_BIT32(x)`; a function-like macro, so bindgen does not
    // emit it.
    let symmetric_bit = 1u32 << rte_eth_hash_function::RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ;
    if raw.rss_algo_capa & symmetric_bit == 0 {
        println!("[ok]   symmetric Toeplitz is NOT advertised, as expected");
    } else {
        println!("[NOTE] symmetric Toeplitz IS advertised -- the driver could use it after all");
        failures.push("rss_algo_capa advertises SYMMETRIC_TOEPLITZ; revisit RssConf".to_string());
    }

    // Claim 2: the key length the crate hard-codes is the one the device demands.
    if usize::from(raw.hash_key_size) == RssConf::DEFAULT_KEY.len() {
        println!(
            "[ok]   hash_key_size matches RssConf::DEFAULT_KEY ({} bytes)",
            RssConf::DEFAULT_KEY.len()
        );
    } else {
        failures.push(format!(
            "hash_key_size is {} but RssConf::DEFAULT_KEY is {}; configure would reject it",
            raw.hash_key_size,
            RssConf::DEFAULT_KEY.len()
        ));
    }

    // Claim 3: nothing we ask to hash on gets dropped by the intersection.
    let Some(rss) = RssConf::supported_on(&info) else {
        return Err("device advertises no RSS hash functions at all".into());
    };
    if rss.hf == RssConf::DEFAULT_HASH_TYPES {
        println!(
            "  hash types requested     = {:#x} (nothing narrowed)",
            rss.hf
        );
    } else {
        println!(
            "[NOTE] hash types narrowed: wanted {:#x}, device supports {:#x}, using {:#x}",
            RssConf::DEFAULT_HASH_TYPES,
            raw.flow_type_rss_offloads,
            rss.hf
        );
    }

    // The negative control, and it runs FIRST. `DevConfig::apply` hands back a `Dev` whose `Drop`
    // stops and closes the port, so doing this after a successful configure would attempt it on a
    // closed port and get `-ENODEV` -- which is non-zero, and would read as the rejection this is
    // looking for while proving nothing at all. Order is load-bearing here.
    //
    // Raw FFI because the safe API has no way to ask for a non-default hash function, which is the
    // whole point; the impossibility has to be demonstrated at the level where someone would
    // otherwise try it.
    let mut key = RssConf::DEFAULT_KEY;
    let mut eth_conf: dpdk_sys::rte_eth_conf = unsafe { core::mem::zeroed() };
    eth_conf.rxmode.mq_mode = dpdk_sys::rte_eth_rx_mq_mode::RTE_ETH_MQ_RX_RSS;
    eth_conf.rxmode.mtu = 1500;
    eth_conf.txmode.mq_mode = dpdk_sys::rte_eth_tx_mq_mode::RTE_ETH_MQ_TX_NONE;
    eth_conf.rx_adv_conf.rss_conf = rte_eth_rss_conf {
        rss_key: key.as_mut_ptr(),
        rss_key_len: key.len() as u8,
        rss_hf: rss.hf,
        algorithm: rte_eth_hash_function::RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ,
    };
    // `-EINVAL` specifically, not merely non-zero: that is what says the *algorithm* was refused.
    // `-ENODEV` would mean the port was gone and the check was vacuous.
    const NEG_EINVAL: i32 = -22;
    let rc = unsafe { rte_eth_dev_configure(port, 2, 2, &eth_conf) };
    if rc == 0 {
        failures.push(
            "configure ACCEPTED symmetric Toeplitz -- the central claim in RssConf's docs is wrong"
                .to_string(),
        );
    } else if rc == NEG_EINVAL {
        println!("[ok]   configure rejected symmetric Toeplitz with -EINVAL, as expected");
    } else {
        failures.push(format!(
            "configure refused symmetric Toeplitz with {rc}, not -EINVAL ({NEG_EINVAL}). \
             Something other than the hash algorithm was wrong, so this proved nothing."
        ));
    }

    // Now configure exactly as the dataplane driver does. Last, because the `Dev` it returns closes
    // the port when it drops.
    let cfg = DevConfig {
        num_rx_queues: 2,
        num_tx_queues: 2,
        num_hairpin_queues: 0,
        rx_offloads: Some(RxOffload::RSS_HASH),
        tx_offloads: Some(TxOffloadConfig::default()),
        mtu: None,
        rss: Some(rss),
    };
    match cfg.apply(info) {
        Ok(_dev) => println!("[ok]   configure with RSS + RSS_HASH offload succeeded"),
        Err(e) => failures.push(format!(
            "configure with RSS + RSS_HASH offload FAILED: {e:?}"
        )),
    }

    if failures.is_empty() {
        println!("\nall RSS capability claims hold on this device");
        Ok(())
    } else {
        for f in &failures {
            println!("[FAIL] {f}");
        }
        Err(format!("{} claim(s) did not hold", failures.len()).into())
    }
}
