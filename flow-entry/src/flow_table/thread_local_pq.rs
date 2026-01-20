// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use ahash::RandomState;
use concurrency::sync::RwLock;
// Should we just move this to std::collections::BinaryHeap?
// We aren't using the hash table feature right now, though we may want it later.
use priority_queue::PriorityQueue;
use thread_local::ThreadLocal;
use tracing::debug;

use tracectl::trace_target;
trace_target!(
    "flow-table-pq",
    LevelFilter::INFO,
    &["flow-expiration", "pipeline"]
);

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Priority(Instant);

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.0.cmp(&other.0) {
            Ordering::Equal => Ordering::Equal,
            Ordering::Less => Ordering::Greater,
            Ordering::Greater => Ordering::Less,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Entry<K, V>
where
    K: Send + Hash + PartialEq + Eq,
    V: Send,
{
    key: K,
    value: V,
}

impl<K, V> Hash for Entry<K, V>
where
    K: Send + Hash + PartialEq + Eq,
    V: Send,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl<K, V> PartialEq for Entry<K, V>
where
    K: Send + Hash + PartialEq + Eq,
    V: Send,
{
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<K, V> Eq for Entry<K, V>
where
    K: Send + Hash + PartialEq + Eq,
    V: Send,
{
}

#[derive(Debug)]
pub(crate) struct ThreadLocalPriorityQueue<K, V>
where
    K: Send + Hash + PartialEq + Eq,
    V: Send,
{
    #[allow(clippy::type_complexity)]
    pqs: ThreadLocal<RwLock<PriorityQueue<Entry<K, V>, Priority, RandomState>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PQAction {
    Reap,
    Update(Instant),
}

impl<K, V> ThreadLocalPriorityQueue<K, V>
where
    K: Send + Sync + Hash + PartialEq + Eq,
    V: Send + Sync,
{
    pub fn new() -> Self {
        Self {
            pqs: ThreadLocal::new(),
        }
    }

    fn get_pq_lock(&self) -> &RwLock<PriorityQueue<Entry<K, V>, Priority, RandomState>> {
        self.pqs
            .get_or(|| RwLock::new(PriorityQueue::with_default_hasher()))
    }

    /// Insert an entry into the priority queue.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe but should not be called if the current thread is
    /// holding a lock on any element in the priority queue.
    ///
    /// # Panics
    ///
    /// Panics if any lock acquired by this method is poisoned.
    pub fn push(&self, key: K, value: V, expires_at: Instant) -> Option<Instant> {
        let pq = self.get_pq_lock();
        pq.write()
            .unwrap()
            .push(Entry { key, value }, Priority(expires_at))
            .map(|expires_at| expires_at.0)
    }

    /// Reap expired entries from the priority queue.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe but should not be called if the current thread is
    /// holding a lock on any element in the priority queue.
    ///
    /// # Panics
    ///
    /// Panics if any lock acquired by this method is poisoned.
    pub fn reap_expired(
        &self,
        on_expired: impl Fn(&Instant, &K, &V) -> PQAction,
        on_reaped: impl Fn(K, V),
    ) -> usize {
        let pql = self.get_pq_lock();
        let mut pq = pql.write().unwrap();
        Self::reap_expired_locked(&mut pq, &on_expired, &on_reaped)
    }

    /// Reap expired entries from all priority queues (regardless of current thread)
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe but should not be called if the current thread is
    /// holding a lock on any element in the priority queue.
    ///
    /// # Panics
    ///
    /// Panics if any lock acquired by this method is poisoned.
    pub fn reap_all_expired(
        &self,
        on_expired: impl Fn(&Instant, &K, &V) -> PQAction,
        on_reaped: impl Fn(K, V),
    ) -> usize {
        self.reap_all_expired_with_time_internal(&Instant::now(), &on_expired, &on_reaped)
    }

    #[allow(unused)] // This is unused for now if shuttle is not enabled
    #[cfg(test)]
    pub fn reap_all_expired_with_time(
        &self,
        now: &Instant,
        on_expired: impl Fn(&Instant, &K, &V) -> PQAction,
        on_reaped: impl Fn(K, V),
    ) -> usize {
        self.reap_all_expired_with_time_internal(now, &on_expired, &on_reaped)
    }

    fn reap_all_expired_with_time_internal(
        &self,
        now: &Instant,
        on_expired: impl Fn(&Instant, &K, &V) -> PQAction,
        on_reaped: impl Fn(K, V),
    ) -> usize {
        let pqs = self.pqs.iter();
        let mut count = 0;
        for pq in pqs {
            let mut pq = pq.write().unwrap();
            count += Self::reap_expired_locked_with_time(&mut pq, now, &on_expired, &on_reaped);
        }
        count
    }

    fn reap_expired_locked(
        pq: &mut concurrency::sync::RwLockWriteGuard<
            PriorityQueue<Entry<K, V>, Priority, RandomState>,
        >,
        on_expired: impl Fn(&Instant, &K, &V) -> PQAction,
        on_reaped: impl Fn(K, V),
    ) -> usize {
        Self::reap_expired_locked_with_time(pq, &Instant::now(), on_expired, on_reaped)
    }

    fn reap_expired_locked_with_time(
        pq: &mut concurrency::sync::RwLockWriteGuard<
            PriorityQueue<Entry<K, V>, Priority, RandomState>,
        >,
        now: &Instant,
        on_expired: impl Fn(&Instant, &K, &V) -> PQAction,
        on_reaped: impl Fn(K, V),
    ) -> usize {
        let mut expired = Vec::new();
        debug!(
            "Reaping expired flows at {:?}, queue size {}",
            now,
            pq.len()
        );
        while let Some((_, expires_at)) = pq.peek() {
            if *now >= expires_at.0 {
                let ret = pq.pop();
                let Some(entry) = ret else {
                    break;
                };
                // This is going to copy the entry and key, even if it is to be reinserted,
                // which sucks.  Find a better way to do this and placate the rust
                // borrow checker.  Without this copy, the borrow checker will
                // complain that you cannot pop the entry because of the borrow in the peek.
                //
                // This is probably fine for now though as we use K that is a FlowKey,
                // copying it isn't ideal but probably cheap enough, and the value is an Arc.
                expired.push(entry);
            } else {
                break;
            }
        }

        debug!(
            "Found {} expired flows at {:?}, queue size {}",
            expired.len(),
            now,
            pq.len()
        );
        let mut count = 0;
        for (entry, _) in expired {
            match on_expired(now, &entry.key, &entry.value) {
                PQAction::Reap => {
                    on_reaped(entry.key, entry.value);
                    count += 1;
                }
                PQAction::Update(new_expires_at) => {
                    pq.push(entry, Priority(new_expires_at));
                }
            }
        }

        count
    }
}

impl<K, V> Default for ThreadLocalPriorityQueue<K, V>
where
    K: Send + Sync + Hash + PartialEq + Eq,
    V: Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}
