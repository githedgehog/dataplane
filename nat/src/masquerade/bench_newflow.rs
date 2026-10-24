// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! BENCH ONLY (bench/nat-newflow-microbench, never to be merged): multi-threaded microbenchmark of
//! the masquerade new-flow path and of steady-state lookups, without DPDK.
//!
//! Every bench thread owns a `Masquerade` NF over one shared `FlowTable` (1024 shards, as in
//! production) and one shared allocator, as DPDK workers do. Packets are built before the start
//! barrier; the timed region is `Masquerade::process_packet` only: lookup miss(es), allocation,
//! pair install, translation. There is no flow-lookup stage in front, so the NF does its own
//! lookup, as it does for a packet the flow-lookup stage did not stamp.
//!
//! Run with `DATAPLANE_BENCH_FLOW_TASKS=0` (no per-flow tokio tasks, no runtime on bench threads).
//! Variant switches: see `flow_entry::bench`. Parameters (environment):
//!
//! - `BENCH_THREADS` (default `1,2,4,8,16,32`), `BENCH_REPS` (3), `BENCH_PIN` (1: thread t on CPU t)
//! - new flows: `BENCH_FLOWS` per thread (20000), `BENCH_PRIVATE` = `perthread` (one private IP per
//!   thread, many ports), `shared` (16 private IPs shared by all threads, disjoint ports) or `many`
//!   (one private IP per flow)
//! - steady state: `BENCH_K` flows (10000), `BENCH_OPS` lookups per thread (200000),
//!   `BENCH_HIT_OPS` NF hits per thread (50000), `BENCH_STEADY_MODES` (`lookup,dashmap,hit`)
//! - `BENCH_TAG`: free-form label copied to every result line

#![cfg(not(any(feature = "shuttle", feature = "loom")))]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "bench-only"
)]

use crate::Masquerade;
use crate::masquerade::probe::{masquerade_expose, outbound_probe};
use crate::masquerade::{MasqueradeConfig, NatAllocatorWriter};
use config::external::overlay::vpcpeering::contract::overlay_with_exposes;
use flow_entry::flow_table::FlowTable;
use net::FlowKey;
use net::buffer::TestBuffer;
use net::flows::FlowInfo;
use net::packet::Packet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Barrier};
use std::time::Instant;

const PRIVATE: &str = "10.0.0.0/8";
const PUBLIC: &str = "172.16.0.0/16";
const SHARED_IPS: u32 = 16;
const FIRST_PORT: u32 = 1024;

fn env<T: FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_str(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn threads_list() -> Vec<usize> {
    env_str("BENCH_THREADS", "1,2,4,8,16,32")
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

fn pin(cpu: usize) {
    if env("BENCH_PIN", 1u8) == 0 {
        return;
    }
    let mut set = nix::sched::CpuSet::new();
    if set.set(cpu).is_ok() {
        let _ = nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &set);
    }
}

fn variant_line() -> String {
    use flow_entry::bench as b;
    format!(
        "tag={} cleanup_lazy={} tls_block={} port_cache={} pair_read_lock={} flow_tasks={:?}",
        env_str("BENCH_TAG", "-"),
        b::alloc_cleanup_lazy(),
        b::alloc_tls_block(),
        b::port_cache_batch(),
        b::pair_read_lock(),
        b::flow_tasks(),
    )
}

fn require_no_tasks() {
    assert_eq!(
        flow_entry::bench::flow_tasks(),
        flow_entry::bench::FlowTasks::Off,
        "run with DATAPLANE_BENCH_FLOW_TASKS=0: bench threads have no tokio runtime"
    );
}

struct Fixture {
    table: Arc<FlowTable>,
    writer: NatAllocatorWriter,
}

impl Fixture {
    fn new() -> Self {
        let overlay = overlay_with_exposes(vec![masquerade_expose(PRIVATE, PUBLIC)])
            .unwrap_or_else(|e| unreachable!("{e}"));
        let validated = overlay.validate().unwrap_or_else(|e| unreachable!("{e}"));
        // As production: FlowTable::default() (1024 shards), randomized port blocks.
        let table = Arc::new(FlowTable::default());
        let mut writer = NatAllocatorWriter::new();
        writer.update_nat_allocator(MasqueradeConfig::new(validated.vpc_table()), 1, &table);
        Self { table, writer }
    }

    fn masquerade(&self) -> Masquerade {
        Masquerade::new("masquerade", self.table.clone(), self.writer.get_reader())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    PerThread,
    Shared,
    Many,
}

impl Layout {
    fn from_env() -> Self {
        match env_str("BENCH_PRIVATE", "perthread").as_str() {
            "shared" => Self::Shared,
            "many" => Self::Many,
            _ => Self::PerThread,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::PerThread => "perthread",
            Self::Shared => "shared16",
            Self::Many => "many",
        }
    }

    /// The `i`-th new flow of thread `t` out of `n`, each doing `flows`: (src, dst, sport, dport).
    /// Distinct across all threads.
    fn tuple(self, t: usize, n: usize, flows: usize, i: usize) -> (IpAddr, IpAddr, u16, u16) {
        let (t32, i32, f32) = (t as u32, i as u32, flows as u32);
        let base = u32::from(Ipv4Addr::new(10, 0, 0, 0));
        let dst = IpAddr::V4(Ipv4Addr::new(3, 3, 3, (1 + i % 250) as u8));
        let (src, sport) = match self {
            Self::PerThread => {
                assert!(flows <= 64_000, "perthread: at most 64000 flows per thread");
                (base + (t32 << 8) + 1, FIRST_PORT + i32)
            }
            Self::Shared => {
                let slice = f32.div_ceil(SHARED_IPS);
                assert!(
                    FIRST_PORT + slice * n as u32 <= 65_535,
                    "shared: too many flows for 16 private addresses"
                );
                (
                    u32::from(Ipv4Addr::new(10, 200, 0, 1)) + i32 % SHARED_IPS,
                    FIRST_PORT + t32 * slice + i32 / SHARED_IPS,
                )
            }
            Self::Many => (base + 0x1_0000 + t32 * f32 + i32, 40_000),
        };
        (IpAddr::V4(Ipv4Addr::from(src)), dst, sport as u16, 80)
    }
}

struct ThreadOut {
    start: Instant,
    end: Instant,
    ops: usize,
    misses: usize,
    lat: Vec<u32>,
}

struct Summary {
    wall_s: f64,
    total_ops: usize,
    misses: usize,
    per_thread_min: f64,
    per_thread_med: f64,
    per_thread_max: f64,
    p50: u32,
    p99: u32,
    p999: u32,
}

fn summarize(outs: &[ThreadOut]) -> Summary {
    let start = outs.iter().map(|o| o.start).min().unwrap_or_else(|| unreachable!());
    let end = outs.iter().map(|o| o.end).max().unwrap_or_else(|| unreachable!());
    let wall_s = (end - start).as_secs_f64();
    let mut rates: Vec<f64> = outs
        .iter()
        .map(|o| o.ops as f64 / (o.end - o.start).as_secs_f64())
        .collect();
    rates.sort_by(f64::total_cmp);
    let mut lat: Vec<u32> = outs.iter().flat_map(|o| o.lat.iter().copied()).collect();
    lat.sort_unstable();
    let pct = |p: f64| {
        if lat.is_empty() {
            0
        } else {
            lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)]
        }
    };
    Summary {
        wall_s,
        total_ops: outs.iter().map(|o| o.ops).sum(),
        misses: outs.iter().map(|o| o.misses).sum(),
        per_thread_min: rates[0],
        per_thread_med: rates[rates.len() / 2],
        per_thread_max: rates[rates.len() - 1],
        p50: pct(0.50),
        p99: pct(0.99),
        p999: pct(0.999),
    }
}

/// `BENCH_WARMUP` (default 1): discarded repetitions before the measured ones, per thread count, so
/// the heap is warm (a fresh process pays page faults on its first table) as in a running dataplane.
fn warmup() -> usize {
    env("BENCH_WARMUP", 1)
}

fn report(mode: &str, extra: &str, n: usize, rep: usize, s: &Summary) {
    let (label, rep) = match rep.checked_sub(warmup()) {
        Some(rep) => ("RESULT", rep),
        None => ("WARMUP", rep),
    };
    println!(
        "{label} mode={mode} {extra} threads={n} rep={rep} ops={} wall_s={:.4} mops_s={:.4} \
         per_thread_kops_s_med={:.1} min={:.1} max={:.1} p50_ns={} p99_ns={} p999_ns={} misses={} {}",
        s.total_ops,
        s.wall_s,
        s.total_ops as f64 / s.wall_s / 1e6,
        s.per_thread_med / 1e3,
        s.per_thread_min / 1e3,
        s.per_thread_max / 1e3,
        s.p50,
        s.p99,
        s.p999,
        s.misses,
        variant_line(),
    );
}

/// Run `n` pinned threads: `prepare(t)` builds the thread's input before the barrier, `work`
/// processes it (timed), returning (ops, misses, per-op latencies). Inputs are dropped after every
/// thread has finished.
fn run_threads<In: Send + 'static>(
    n: usize,
    prepare: impl Fn(usize) -> In + Send + Sync + 'static,
    work: impl Fn(usize, &mut In) -> (usize, usize, Vec<u32>) + Send + Sync + 'static,
) -> Vec<ThreadOut> {
    let barrier = Arc::new(Barrier::new(n));
    let prepare = Arc::new(prepare);
    let work = Arc::new(work);
    let handles: Vec<_> = (0..n)
        .map(|t| {
            let (barrier, prepare, work) = (barrier.clone(), prepare.clone(), work.clone());
            std::thread::spawn(move || {
                pin(t);
                let mut input = prepare(t);
                barrier.wait();
                let start = Instant::now();
                let (ops, misses, lat) = work(t, &mut input);
                let end = Instant::now();
                (
                    ThreadOut {
                        start,
                        end,
                        ops,
                        misses,
                        lat,
                    },
                    input,
                )
            })
        })
        .collect();
    let joined: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap_or_else(|_| panic!("bench thread panicked")))
        .collect();
    let (outs, inputs): (Vec<_>, Vec<_>) = joined.into_iter().unzip();
    drop(inputs);
    outs
}

fn process_all(masq: &Masquerade, packets: &mut [Packet<TestBuffer>]) -> (usize, usize, Vec<u32>) {
    let mut lat = Vec::with_capacity(packets.len());
    for packet in packets.iter_mut() {
        let t0 = Instant::now();
        masq.process_packet(packet);
        lat.push(t0.elapsed().as_nanos() as u32);
    }
    let misses = packets.iter().filter(|p| p.is_done()).count();
    (packets.len(), misses, lat)
}

#[test]
#[ignore = "benchmark: run explicitly, in release, with DATAPLANE_BENCH_FLOW_TASKS=0"]
fn bench_newflow() {
    require_no_tasks();
    let flows: usize = env("BENCH_FLOWS", 20_000);
    let reps: usize = env("BENCH_REPS", 3);
    let layout = Layout::from_env();
    println!(
        "BENCH newflow: size_of::<Packet<TestBuffer>>()={} flows/thread={flows} private={}",
        size_of::<Packet<TestBuffer>>(),
        layout.name()
    );
    for n in threads_list() {
        for rep in 0..warmup() + reps {
            let fixture = Fixture::new();
            let masqs: Arc<Vec<Masquerade>> = Arc::new((0..n).map(|_| fixture.masquerade()).collect());
            let prepare_masqs = masqs.clone();
            let outs = run_threads(
                n,
                move |t| {
                    let _ = &prepare_masqs;
                    (0..flows)
                        .map(|i| {
                            let (s, d, sp, dp) = layout.tuple(t, n, flows, i);
                            outbound_probe(s, d, sp, dp)
                        })
                        .collect::<Vec<_>>()
                },
                move |t, packets| process_all(&masqs[t], packets),
            );
            let summary = summarize(&outs);
            let live = fixture.table.live_len();
            let extra = format!(
                "private={} flows_per_thread={flows} table_live={live}",
                layout.name()
            );
            report("newflow", &extra, n, rep, &summary);
            assert_eq!(summary.misses, 0, "some new flows were dropped");
            assert_eq!(live, 2 * n * flows, "flow pairs missing from the table");
        }
    }
}

struct Steady {
    fixture: Fixture,
    keys: Vec<FlowKey>,
    tuples: Vec<(IpAddr, IpAddr, u16, u16)>,
    raw: dashmap::DashMap<FlowKey, Arc<FlowInfo>, ahash::RandomState>,
}

fn build_steady(k: usize) -> Steady {
    const CREATORS: usize = 32;
    let per = k.div_ceil(CREATORS);
    let fixture = Fixture::new();
    let mut tuples = Vec::with_capacity(k);
    for t in 0..CREATORS {
        for i in 0..per {
            if tuples.len() < k {
                tuples.push(Layout::PerThread.tuple(t, CREATORS, per, i));
            }
        }
    }
    let tuples = Arc::new(tuples);
    let masqs: Arc<Vec<Masquerade>> =
        Arc::new((0..CREATORS).map(|_| fixture.masquerade()).collect());
    let prep_tuples = tuples.clone();
    let start = Instant::now();
    let outs = run_threads(
        CREATORS,
        move |t| {
            prep_tuples
                .iter()
                .skip(t * per)
                .take(per)
                .map(|&(s, d, sp, dp)| outbound_probe(s, d, sp, dp))
                .collect::<Vec<_>>()
        },
        move |t, packets| process_all(&masqs[t], packets),
    );
    let s = summarize(&outs);
    println!(
        "BENCH steady: created {} flows in {:.2}s ({} misses), table_live={}",
        s.total_ops,
        start.elapsed().as_secs_f64(),
        s.misses,
        fixture.table.live_len()
    );
    assert_eq!(s.misses, 0);
    assert_eq!(fixture.table.live_len(), 2 * k);

    let keys: Vec<FlowKey> = tuples
        .iter()
        .map(|&(s, d, sp, dp)| {
            FlowKey::try_from(&outbound_probe(s, d, sp, dp)).unwrap_or_else(|e| unreachable!("{e:?}"))
        })
        .collect();
    let raw = dashmap::DashMap::with_hasher_and_shard_amount(
        ahash::RandomState::with_seeds(0, 0, 0, 0),
        1024,
    );
    // Same entries (forward and reverse) as the flow table, same hasher and shard count.
    let mut all_keys = Vec::with_capacity(2 * k);
    drop(fixture.table.for_each_flow(|key, _| all_keys.push(*key)));
    for key in all_keys {
        if let Some(flow) = fixture.table.lookup(&key) {
            raw.insert(key, flow);
        }
    }
    Steady {
        fixture,
        keys,
        tuples: Arc::try_unwrap(tuples).unwrap_or_else(|t| (*t).clone()),
        raw,
    }
}

// xorshift64*, deterministic per (thread, rep)
fn picks(seed: u64, k: usize, count: usize) -> Vec<usize> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..count)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) % k as u64) as usize
        })
        .collect()
}

#[test]
#[ignore = "benchmark: run explicitly, in release, with DATAPLANE_BENCH_FLOW_TASKS=0"]
fn bench_steady() {
    require_no_tasks();
    let k: usize = env("BENCH_K", 10_000);
    let ops: usize = env("BENCH_OPS", 200_000);
    let hit_ops: usize = env("BENCH_HIT_OPS", 50_000);
    let reps: usize = env("BENCH_REPS", 3);
    let modes = env_str("BENCH_STEADY_MODES", "lookup,dashmap,hit");
    let steady = Arc::new(build_steady(k));
    println!("BENCH steady: raw dashmap holds {} entries", steady.raw.len());
    for n in threads_list() {
        for rep in 0..warmup() + reps {
            for mode in modes.split(',') {
                let st = steady.clone();
                let extra = format!("k={k}");
                let outs = match mode {
                    "lookup" | "dashmap" => {
                        let raw = mode == "dashmap";
                        let prep = steady.clone();
                        run_threads(
                            n,
                            move |t| {
                                picks((t * 1000 + rep) as u64 + 1, k, ops)
                                    .into_iter()
                                    .map(|i| prep.keys[i])
                                    .collect::<Vec<FlowKey>>()
                            },
                            move |_, keys| {
                                let mut misses = 0;
                                if raw {
                                    for key in keys.iter() {
                                        if st.raw.get(key).map(|e| e.value().clone()).is_none() {
                                            misses += 1;
                                        }
                                    }
                                } else {
                                    for key in keys.iter() {
                                        if st.fixture.table.lookup(key).is_none() {
                                            misses += 1;
                                        }
                                    }
                                }
                                (keys.len(), misses, Vec::new())
                            },
                        )
                    }
                    "hit" => {
                        let prep = steady.clone();
                        let masqs: Arc<Vec<Masquerade>> =
                            Arc::new((0..n).map(|_| steady.fixture.masquerade()).collect());
                        run_threads(
                            n,
                            move |t| {
                                picks((t * 1000 + rep) as u64 + 7, k, hit_ops)
                                    .into_iter()
                                    .map(|i| {
                                        let (s, d, sp, dp) = prep.tuples[i];
                                        outbound_probe(s, d, sp, dp)
                                    })
                                    .collect::<Vec<_>>()
                            },
                            move |t, packets| process_all(&masqs[t], packets),
                        )
                    }
                    other => panic!("unknown steady mode {other}"),
                };
                let summary = summarize(&outs);
                report(mode, &extra, n, rep, &summary);
                assert_eq!(summary.misses, 0, "steady-state misses in mode {mode}");
            }
        }
    }
}
