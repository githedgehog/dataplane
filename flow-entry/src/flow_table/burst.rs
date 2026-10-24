// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Looking up a whole burst of flows at once, overlapping their cache misses.
//!
//! A lookup is a chain of dependent loads: the shard (its lock and table header), the probed group
//! of control bytes, the matching slot (key and value), then the flow the value points to. Looked
//! up one packet at a time, each of those waits for memory in turn, and a burst waits for them
//! once per packet. Here each step is taken for every packet of the burst before the next step,
//! issuing a prefetch for what the next step will read, so a burst waits for each step about once.

use super::table::{FlowTable, Table};
use concurrency::sync::Arc;
use net::FlowKey;
use net::flows::FlowInfo;

/// Start loading the cache line holding `ptr`. A hint only: it never faults, whatever the address.
#[inline]
fn prefetch<T>(ptr: *const T) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: a prefetch reads nothing the program can observe and cannot fault.
    unsafe {
        core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(ptr.cast());
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = ptr;
}

/// Bursts are looked up this many keys at a time, so the per-key scratch lives on the stack.
const CHUNK: usize = 32;

impl FlowTable {
    /// Look up every key of `keys` (skipping `None`s) and push one result per key onto `out`.
    ///
    /// Same results as calling [`FlowTable::lookup`] for each key in turn.
    pub fn lookup_burst(&self, keys: &[Option<FlowKey>], out: &mut Vec<Option<Arc<FlowInfo>>>) {
        let table = self.table.read();
        for chunk in keys.chunks(CHUNK) {
            lookup_chunk(&table, chunk, out);
        }
    }
}

fn lookup_chunk(table: &Table, keys: &[Option<FlowKey>], out: &mut Vec<Option<Arc<FlowInfo>>>) {
    let shards = table.shards();
    let mut hashes = [0u64; CHUNK];
    let mut shard_of = [0usize; CHUNK];

    // 1. Hash every key; prefetch its shard (lock word and table header share its line).
    for (i, key) in keys.iter().enumerate() {
        if let Some(key) = key {
            // dashmap hashes to usize and widens that for the table; do the same.
            hashes[i] = table.hash_usize(key) as u64;
            shard_of[i] = table.determine_shard(usize::try_from(hashes[i]).unwrap_or(usize::MAX));
            prefetch(&raw const shards[shard_of[i]]);
        }
    }

    // 2. Prefetch the group of control bytes each key's probe starts at.
    for (i, key) in keys.iter().enumerate() {
        if key.is_some() {
            let shard = shards[shard_of[i]].read();
            let mask = shard.buckets().wrapping_sub(1);
            let position = usize::try_from(hashes[i]).unwrap_or(usize::MAX) & mask;
            // The control bytes start where the buckets end.
            let ctrl: *const u8 = shard.data_end().as_ptr().cast_const().cast();
            prefetch(ctrl.wrapping_add(position));
        }
    }

    // 3. Prefetch the slot of each key's first candidate.
    for (i, key) in keys.iter().enumerate() {
        if key.is_some() {
            let shard = shards[shard_of[i]].read();
            // SAFETY: the iterator only reads the table's control bytes, and the shard's read lock
            // keeps the table alive and unchanged for as long as it is used. The candidate bucket
            // is not dereferenced: only its address is used, for a prefetch.
            if let Some(bucket) = unsafe { shard.iter_hash(hashes[i]) }.next() {
                prefetch(bucket.as_ptr().cast_const());
            }
        }
    }

    // 4. Find each key; prefetch the flow its slot points to, without touching it yet.
    for key in keys.iter().flatten() {
        if let Some(entry) = table.get(key) {
            prefetch(Arc::as_ptr(entry.value()));
        }
    }

    // 5. Look each key up for real: everything it touches is on its way, or there.
    for key in keys {
        out.push(
            key.as_ref()
                .and_then(|key| table.get(key).map(|entry| entry.value().clone())),
        );
    }
}

#[cfg(all(test, not(any(feature = "shuttle", feature = "loom"))))]
mod tests {
    use super::*;
    use net::flows::flow_key::FlowAddrs;
    use net::ipv4::UnicastIpv4Addr;
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;
    use net::{IpProtoKey, TcpProtoKey};
    use std::time::Duration;

    fn key(port: u16) -> FlowKey {
        FlowKey::new(
            Some(VpcDiscriminant::VNI(Vni::new_checked(9).unwrap())),
            FlowAddrs::V4 {
                src: UnicastIpv4Addr::new("10.9.0.1".parse().unwrap()).unwrap(),
                dst: UnicastIpv4Addr::new("10.9.0.2".parse().unwrap()).unwrap(),
            },
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(port.max(1)).unwrap(),
                dst_port: TcpPort::new_checked(80).unwrap(),
            }),
        )
    }

    /// A burst lookup finds exactly what one lookup per key finds: the same flow (by identity) or
    /// nothing, for present keys, missing keys, skipped (`None`) slots and duplicates, across
    /// chunk boundaries.
    #[test]
    fn a_burst_lookup_agrees_with_one_lookup_per_key() {
        bolero::check!()
            .with_type::<(Vec<u16>, Vec<Option<u16>>, u8)>()
            .for_each(|(present, queried, shards)| {
                let table = FlowTable::new(2usize << (shards % 6));
                for port in present {
                    let _ = table.insert(FlowInfo::new(
                        key(*port),
                        clock::now() + Duration::from_secs(60),
                    ));
                }
                let keys: Vec<Option<FlowKey>> = queried.iter().map(|q| q.map(key)).collect();
                let mut burst = Vec::new();
                table.lookup_burst(&keys, &mut burst);
                assert_eq!(burst.len(), keys.len());
                for (k, got) in keys.iter().zip(&burst) {
                    let want = k.as_ref().and_then(|k| table.lookup(k));
                    match (got, &want) {
                        (None, None) => {}
                        (Some(g), Some(w)) => {
                            assert!(Arc::ptr_eq(g, w), "a different flow for {k:?}");
                        }
                        _ => panic!("burst {got:?} vs single {want:?} for {k:?}"),
                    }
                }
            });
    }
}
