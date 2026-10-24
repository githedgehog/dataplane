// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! BENCH PROTOTYPE (bench/flow-scaling-20261023, B2): a per-worker, approximate, synchronous timer
//! wheel that replaces the per-flow tokio tasks. No async and no tokio on the worker.
//!
//! - One wheel per worker thread, installed with [`install`]. Threads without a wheel keep the
//!   tokio path, so nothing changes for tests, the kernel driver or control-plane inserts.
//! - Single level, `SLOTS` buckets of `TICK` each. A bucket is a plain `Vec` of small entries.
//! - Insert: push onto the bucket of the entry's deadline tick. Amortised O(1), no lock.
//! - Update: nothing. The packet path only stores the new deadline in the flow; when the old bucket
//!   comes due, the sweep sees the later deadline and moves the entry. Deadlines past the wheel's
//!   span wrap around and get the same treatment.
//! - Cancel: nothing. A flow that is no longer `Active` is removed when its bucket comes due.
//! - Expire: [`sweep`] handles at most `budget` entries per call, so a burst of expiring timers
//!   cannot stall the rx loop; the rest carry over to the next call (bounded overrun). Flows that
//!   die in one call are removed grouped by flow-table shard, one shard write lock per group.
//!
//! Timers fire up to a tick late (plus whatever the budget defers), never early: the deadline in
//! the flow is always checked before acting.

#![allow(clippy::disallowed_types, reason = "bench-only")]

use crate::flow_table::table::Table;
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use concurrency::sync::{Arc, RwLock};
use net::flows::{FlowInfo, FlowStatus};
use std::cell::RefCell;
use std::time::{Duration, Instant};

/// Wheel resolution.
pub const TICK: Duration = Duration::from_millis(10);
/// Buckets in the wheel: span = `SLOTS * TICK` (~82 s). Longer deadlines wrap and are revisited.
pub const SLOTS: usize = 8192;
/// A drained bucket buffer up to this many entries is reused for the slot it came from.
const RECYCLE_CAPACITY: usize = 64;

/// Something other than a flow-table entry that expires on the wheel (e.g. a NAT mapping).
pub trait Expiring: Send {
    /// When to look at this entry next.
    fn deadline(&self) -> Instant;
    /// The deadline has passed. Return `Some(next)` to stay on the wheel, `None` when finished.
    fn expire(&mut self, now: Instant) -> Option<Instant>;
}

enum Entry {
    /// A flow-table entry; `owner` indexes the wheel's table registry (16 bytes total).
    Flow {
        flow: Arc<FlowInfo>,
        owner: u32,
    },
    Other(Box<dyn Expiring>),
}

struct Owner {
    table: Arc<RwLock<Table>>,
    live: Arc<AtomicUsize>,
}

struct Wheel {
    base: Instant,
    /// Next tick to sweep.
    cursor: u64,
    buckets: Vec<Vec<Entry>>,
    /// Entries taken from due buckets but not yet looked at (the budget ran out).
    pending: Vec<Entry>,
    owners: Vec<Owner>,
    /// Reused per sweep: flows to remove, with their shard index.
    dead: Vec<(usize, Arc<FlowInfo>, u32)>,
    stats: Stats,
}

/// Per-wheel counters, for the bench log.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub inserted: u64,
    pub moved: u64,
    pub removed: u64,
    pub others_done: u64,
    pub deferred_sweeps: u64,
    pub entries: u64,
}

thread_local! {
    static WHEEL: RefCell<Option<Wheel>> = const { RefCell::new(None) };
}

/// Install a wheel on this thread (a DPDK worker).
pub fn install() {
    WHEEL.with_borrow_mut(|w| {
        *w = Some(Wheel {
            base: Instant::now(),
            cursor: 0,
            buckets: (0..SLOTS).map(|_| Vec::new()).collect(),
            pending: Vec::new(),
            owners: Vec::new(),
            dead: Vec::new(),
            stats: Stats::default(),
        });
    });
}

/// Whether this thread has a wheel.
#[must_use]
pub fn installed() -> bool {
    WHEEL.with_borrow(Option::is_some)
}

impl Wheel {
    fn tick_of(&self, at: Instant) -> u64 {
        let ticks = at.saturating_duration_since(self.base).as_nanos() / TICK.as_nanos();
        // Never schedule into the past: the earliest is the bucket being swept next.
        u64::try_from(ticks).unwrap_or(u64::MAX).max(self.cursor)
    }

    fn push(&mut self, at: Instant, entry: Entry) {
        let tick = self.tick_of(at);
        #[allow(clippy::cast_possible_truncation)]
        self.buckets[(tick % SLOTS as u64) as usize].push(entry);
    }

    fn owner(&mut self, table: &Arc<RwLock<Table>>, live: &Arc<AtomicUsize>) -> u32 {
        let found = self
            .owners
            .iter()
            .position(|o| Arc::ptr_eq(&o.table, table));
        let idx = found.unwrap_or_else(|| {
            self.owners.push(Owner {
                table: table.clone(),
                live: live.clone(),
            });
            self.owners.len() - 1
        });
        u32::try_from(idx).unwrap_or(u32::MAX)
    }
}

/// Put a flow on this thread's wheel. Returns the flow back if the thread has no wheel.
pub(crate) fn insert_flow(
    table: &Arc<RwLock<Table>>,
    live: &Arc<AtomicUsize>,
    flow: Arc<FlowInfo>,
) -> Result<(), Arc<FlowInfo>> {
    WHEEL.with_borrow_mut(|w| {
        let Some(w) = w.as_mut() else {
            return Err(flow);
        };
        let owner = w.owner(table, live);
        let at = flow.expires_at();
        w.push(at, Entry::Flow { flow, owner });
        w.stats.inserted += 1;
        w.stats.entries += 1;
        Ok(())
    })
}

/// Put something else on this thread's wheel. Returns it back if the thread has no wheel.
///
/// # Errors
///
/// Returns the entry if this thread has no wheel.
pub fn insert_other(other: Box<dyn Expiring>) -> Result<(), Box<dyn Expiring>> {
    WHEEL.with_borrow_mut(|w| {
        let Some(w) = w.as_mut() else {
            return Err(other);
        };
        let at = other.deadline();
        w.push(at, Entry::Other(other));
        w.stats.inserted += 1;
        w.stats.entries += 1;
        Ok(())
    })
}

/// Look at up to `budget` due entries. Call once per rx burst (or idle poll) from the worker loop.
///
/// Returns how many entries were looked at.
#[allow(clippy::must_use_candidate, reason = "the count is for tests")]
pub fn sweep(budget: usize) -> usize {
    WHEEL.with_borrow_mut(|w| w.as_mut().map_or(0, |w| w.sweep(Instant::now(), budget)))
}

/// This thread's wheel counters.
#[must_use]
pub fn stats() -> Option<Stats> {
    WHEEL.with_borrow(|w| w.as_ref().map(|w| w.stats))
}

impl Wheel {
    fn sweep(&mut self, now: Instant, budget: usize) -> usize {
        let now_tick =
            u64::try_from(now.saturating_duration_since(self.base).as_nanos() / TICK.as_nanos())
                .unwrap_or(u64::MAX);
        let mut seen = 0;
        while seen < budget {
            if self.pending.is_empty() {
                if self.cursor > now_tick {
                    break;
                }
                #[allow(clippy::cast_possible_truncation)]
                let slot = (self.cursor % SLOTS as u64) as usize;
                // Take the due bucket and leave an unallocated one behind. Swapping the drained
                // buffer back in instead (as the first cut did) left every bucket holding the
                // capacity of a busy tick once the cursor had gone round: ~16x the live entries.
                // The drained buffer is kept for reuse only while it is small.
                let due = std::mem::take(&mut self.buckets[slot]);
                let drained = std::mem::replace(&mut self.pending, due);
                if drained.capacity() <= RECYCLE_CAPACITY {
                    self.buckets[slot] = drained;
                }
                self.cursor += 1;
                continue;
            }
            let Some(entry) = self.pending.pop() else {
                continue;
            };
            seen += 1;
            match entry {
                Entry::Flow { flow, owner } => {
                    let status = flow.status();
                    if status == FlowStatus::Detached {
                        // Displaced or removed elsewhere: nothing to do.
                        self.stats.entries -= 1;
                        continue;
                    }
                    if status == FlowStatus::Active {
                        let at = flow.expires_at();
                        if at > now {
                            // Extended (or a wrapped long deadline): look again later.
                            self.push(at, Entry::Flow { flow, owner });
                            self.stats.moved += 1;
                            continue;
                        }
                        flow.update_status(FlowStatus::Expired);
                    }
                    let o = &self.owners[owner as usize];
                    let shard = o
                        .table
                        .try_read()
                        .map_or(usize::MAX, |t| t.determine_map(flow.flowkey()));
                    self.dead.push((shard, flow, owner));
                }
                Entry::Other(mut other) => {
                    if let Some(at) = other.expire(now) {
                        self.push(at, Entry::Other(other));
                        self.stats.moved += 1;
                    } else {
                        self.stats.others_done += 1;
                        self.stats.entries -= 1;
                    }
                }
            }
        }
        if !self.pending.is_empty() || self.cursor <= now_tick {
            self.stats.deferred_sweeps += 1;
        }
        self.remove_dead();
        seen
    }

    /// Remove the flows that died in this sweep, one shard write lock per (owner, shard) group.
    fn remove_dead(&mut self) {
        if self.dead.is_empty() {
            return;
        }
        self.dead
            .sort_unstable_by_key(|(shard, _, owner)| (*owner, *shard));
        let mut dead = std::mem::take(&mut self.dead);
        let mut i = 0;
        while i < dead.len() {
            let (shard, _, owner) = dead[i];
            let mut j = i;
            while j < dead.len() && dead[j].0 == shard && dead[j].2 == owner {
                j += 1;
            }
            let o = &self.owners[owner as usize];
            // Pair admission and resharding hold the outer write lock; if so, retry next tick.
            let retry = match o.table.try_read() {
                Some(table) if shard != usize::MAX => {
                    let removed = remove_group(&table, shard, &dead[i..j]);
                    o.live.fetch_sub(removed, Ordering::Relaxed);
                    self.stats.removed += removed as u64;
                    self.stats.entries -= (j - i) as u64;
                    false
                }
                _ => true,
            };
            if retry {
                let at = Instant::now() + TICK;
                for (_, flow, owner) in dead.drain(i..j).collect::<Vec<_>>() {
                    self.push(at, Entry::Flow { flow, owner });
                }
                // `dead` shrank; continue at the same index.
                continue;
            }
            i = j;
        }
        dead.clear();
        self.dead = dead;
    }
}

/// Remove a group of flows that all hash to `shard`, under one write lock of that shard.
/// A concurrently-inserted replacement under the same key is left alone (pointer identity).
fn remove_group(table: &Table, shard: usize, group: &[(usize, Arc<FlowInfo>, u32)]) -> usize {
    let mut removed = 0;
    let mut guard = table.shards()[shard].write();
    for (_, flow, _) in group {
        let key = flow.flowkey();
        #[allow(clippy::cast_possible_truncation)]
        let hash = table.hash_usize(key) as u64;
        if let Some(bucket) = guard.find(hash, |(k, v)| k == key && Arc::ptr_eq(v.get(), flow)) {
            // SAFETY: the bucket was just found in this table, under its write lock.
            drop(unsafe { guard.remove(bucket) });
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_table::FlowTable;
    use net::FlowKey;
    use net::flows::FlowInfo;

    use net::flows::flow_key::FlowAddrs;
    use net::ipv4::UnicastIpv4Addr;
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;
    use net::{IpProtoKey, TcpProtoKey};

    fn key(n: u16) -> FlowKey {
        FlowKey::new(
            Some(VpcDiscriminant::VNI(Vni::new_checked(1).unwrap())),
            FlowAddrs::V4 {
                src: UnicastIpv4Addr::new("1.2.3.4".parse().unwrap()).unwrap(),
                dst: UnicastIpv4Addr::new("4.5.6.7".parse().unwrap()).unwrap(),
            },
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(1000 + n).unwrap(),
                dst_port: TcpPort::new_checked(2048).unwrap(),
            }),
        )
    }

    /// Re-arms forever, `period` after each expiry.
    struct Rearm {
        at: Instant,
        period: Duration,
    }

    impl Expiring for Rearm {
        fn deadline(&self) -> Instant {
            self.at
        }
        fn expire(&mut self, now: Instant) -> Option<Instant> {
            self.at = now + self.period;
            Some(self.at)
        }
    }

    #[test]
    fn bucket_capacity_follows_live_entries_not_the_busiest_tick() {
        let base = Instant::now();
        let mut w = Wheel {
            base,
            cursor: 0,
            buckets: (0..SLOTS).map(|_| Vec::new()).collect(),
            pending: Vec::new(),
            owners: Vec::new(),
            dead: Vec::new(),
            stats: Stats::default(),
        };
        let live = 200_000;
        let period = Duration::from_secs(5);
        for n in 0..live {
            let at = base + period + TICK * (n % 500);
            w.push(at, Entry::Other(Box::new(Rearm { at, period })));
        }
        // Two full revolutions of the wheel on a synthetic clock.
        for tick in 1..=u32::try_from(2 * SLOTS).unwrap() {
            w.sweep(base + TICK * tick, usize::MAX);
        }
        let capacity: usize =
            w.buckets.iter().map(Vec::capacity).sum::<usize>() + w.pending.capacity();
        let entries: usize = w.buckets.iter().map(Vec::len).sum::<usize>() + w.pending.len();
        assert_eq!(entries, live as usize);
        assert!(
            capacity <= 2 * entries + SLOTS * RECYCLE_CAPACITY,
            "capacity {capacity} for {entries} live entries"
        );
    }

    #[test]
    fn expires_in_budgeted_batches_and_keeps_extended_flows() {
        // SAFETY: nextest runs each test in its own process; nothing else reads the environment.
        unsafe { std::env::set_var("DATAPLANE_BENCH_FLOW_TASKS", "wheel") };
        install();
        let table = FlowTable::default();
        let now = Instant::now();
        for n in 0..100 {
            table
                .insert(FlowInfo::new(key(n), now + Duration::from_millis(20)))
                .unwrap();
        }
        // Extend one flow far beyond the others.
        let kept = table.lookup(&key(7)).unwrap();
        kept.extend_expiry(Duration::from_secs(60)).unwrap();
        assert_eq!(table.live_len(), 100);
        std::thread::sleep(Duration::from_millis(50));
        // Budget 16: needs several calls; every call looks at no more than 16.
        let mut calls = 0;
        while table.live_len() > 1 {
            assert!(sweep(16) <= 16);
            calls += 1;
            assert!(calls < 100, "sweep made no progress");
        }
        assert!(calls >= 99 / 16);
        assert_eq!(table.live_len(), 1);
        assert!(table.lookup(&key(7)).is_some());
        assert!(table.lookup(&key(3)).is_none());
        let s = stats().unwrap();
        assert_eq!(s.removed, 99);
        assert_eq!(s.entries, 1);
    }
}
