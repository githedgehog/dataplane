// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bench proof of concept: VXLAN encapsulation in the NIC (`DP_BENCH_NIC_ENCAP=1`).
//!
//! Encap contexts are learned from software: a packet software encapsulated reports its outer
//! headers at transmit ([`learn`]); a thread per port installs an egress rule for each new
//! (VNI, remote VTEP), matching the transmit metadata `FLAG | id` and encapsulating with those
//! headers (UDP source port 0: the NIC hashes the inner flow into it), and publishes the context.
//! Later packets for it skip building outer headers ([`lookup`]): the IP forwarder only rewrites
//! the inner MACs and tags the packet, the egress stage leaves its MACs alone, and the worker sets
//! the transmit metadata. Not handled: underlay MAC changes, outer DSCP/ECN, IPv6 underlay.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use concurrency::sync::{Mutex, RwLock};

use dpdk::dev::{Dev, Started};
use dpdk::flow::{EthMatch, Flow, FlowGroup, FlowRule, Priority, VxlanEncap};
use net::eth::mac::Mac;
use net::vxlan::Vni;
use tracing::{info, warn};

/// The transmit metadata bit that sends a packet to the encap group.
pub(crate) const FLAG: u32 = 1 << 31;
const ENCAP_GROUP: FlowGroup = FlowGroup(1);

/// An encap context: what the outer headers depend on that varies.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub vni: u32,
    pub remote: Ipv4Addr,
}

/// The outer headers software built for a context.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Outer {
    pub key: Key,
    pub eth_src: Mac,
    pub eth_dst: Mac,
    pub ip_src: Ipv4Addr,
}

struct Shared {
    version: AtomicU64,
    contexts: RwLock<Arc<HashMap<Key, u16>>>,
    requests: Mutex<Vec<Outer>>,
}

static SHARED: OnceLock<Shared> = OnceLock::new();

fn shared() -> &'static Shared {
    SHARED.get_or_init(|| Shared {
        version: AtomicU64::new(0),
        contexts: RwLock::new(Arc::default()),
        requests: Mutex::new(Vec::new()),
    })
}

/// Whether the proof of concept is on.
pub(crate) fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("DP_BENCH_NIC_ENCAP").is_ok_and(|v| v == "1"))
}

thread_local! {
    static SNAPSHOT: RefCell<(u64, Arc<HashMap<Key, u16>>)> = RefCell::new((0, Arc::default()));
    static ASKED: RefCell<HashSet<Key>> = RefCell::new(HashSet::new());
}

/// Take this thread's view of the contexts up to date: once a burst.
pub(crate) fn refresh() {
    let shared = shared();
    let version = shared.version.load(Ordering::Acquire);
    SNAPSHOT.with_borrow_mut(|(seen, contexts)| {
        if *seen != version {
            *contexts = Arc::clone(&shared.contexts.read());
            *seen = version;
        }
    });
}

/// The installed context for `key`, as of the last [`refresh`].
pub(crate) fn lookup(key: Key) -> Option<u16> {
    SNAPSHOT.with_borrow(|(_, contexts)| contexts.get(&key).copied())
}

/// Report the outer headers software built, once per context and thread.
pub(crate) fn learn(outer: Outer) {
    if ASKED.with_borrow_mut(|asked| asked.insert(outer.key)) {
        shared().requests.lock().push(outer);
    }
}

/// Install encap rules on `dev` for what workers learn, until `stop`.
pub(crate) fn run(dev: &Dev<'_, Started>, port: &str, stop: &dyn Fn() -> bool) {
    let root = Flow::egress(dev)
        .match_meta(FLAG, FLAG)
        .match_eth(EthMatch::default())
        .jump(ENCAP_GROUP)
        .create();
    // A flagged packet with no context must not leave unencapsulated onto the underlay.
    let catch_all = Flow::egress(dev)
        .group(ENCAP_GROUP)
        .priority(Priority(1))
        .match_eth(EthMatch::default())
        .drop()
        .create();
    let (root, catch_all) = match (root, catch_all) {
        (Ok(root), Ok(catch_all)) => (root, catch_all),
        (r, c) => {
            warn!(
                "port {port}: no NIC encap: root {:?}, catch-all {:?}",
                r.err(),
                c.err()
            );
            return;
        }
    };
    let mut rules: Vec<FlowRule<'_>> = Vec::new();
    let mut contexts: HashMap<Key, u16> = HashMap::new();
    while !stop() {
        let requests = std::mem::take(&mut *shared().requests.lock());
        let mut changed = false;
        for outer in requests {
            if contexts.contains_key(&outer.key) {
                continue;
            }
            let Ok(vni) = Vni::new_checked(outer.key.vni) else {
                continue;
            };
            let Ok(id) = u16::try_from(contexts.len() + 1) else {
                continue;
            };
            let rule = Flow::egress(dev)
                .group(ENCAP_GROUP)
                .priority(Priority(0))
                .match_meta(FLAG | u32::from(id), u32::MAX)
                .match_eth(EthMatch::default())
                .vxlan_encap(VxlanEncap {
                    eth_src: outer.eth_src,
                    eth_dst: outer.eth_dst,
                    ip_src: outer.ip_src,
                    ip_dst: outer.key.remote,
                    udp_src: 0,
                    vni,
                })
                .create();
            match rule {
                Ok(rule) => {
                    info!("port {port}: NIC encap context {id}: {outer:?}");
                    rules.push(rule);
                    contexts.insert(outer.key, id);
                    changed = true;
                }
                Err(e) => warn!("port {port}: NIC encap context for {outer:?} refused: {e}"),
            }
        }
        if changed {
            let shared = shared();
            *shared.contexts.write() = Arc::new(contexts.clone());
            shared.version.fetch_add(1, Ordering::Release);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    drop(rules);
    drop(catch_all);
    drop(root);
}
