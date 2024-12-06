// use ahash::{HashMap, HashMapExt};
use std::collections::HashMap;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use rand::prelude::SliceRandom;
use rand::{random, Rng};
use std::collections::{BTreeMap, VecDeque};
use std::hint::black_box;
use std::num::NonZero;
use std::time::Duration;
use criterion::measurement::WallTime;

type KEY = u128;
type VALUE = u16;

fn fill_btreemap(vals: &Vec<(KEY, VALUE)>) -> BTreeMap<KEY, VALUE> {
    let mut map = BTreeMap::new();
    for (k, v) in vals {
        map.insert(*k, *v);
    }
    map
}

fn random_read_btreemap(map: &BTreeMap<KEY, VALUE>, kvs: &Vec<(KEY, VALUE)>) {
    for (k, _) in kvs {
        match map.get(k) {
            None => {}
            Some(read) => {
                assert!(*black_box(read) <= black_box(VALUE::MAX))
            }
        }
    }
}

fn fill_hashmap<const CAPACITY_HINT: usize>(vals: &Vec<(KEY, VALUE)>) -> HashMap<KEY, VALUE> {
    vals.iter().cloned().collect()
}

fn random_remove_btreemap(map: &mut BTreeMap<KEY, VALUE>, kvs: &Vec<(KEY, VALUE)>) {
    for (k, _) in kvs {
        match map.remove(k) {
            None => {}
            Some(read) => {
                assert!(black_box(read) <= black_box(VALUE::MAX))
            }
        }
    }
}

fn random_read_hashmap(map: &HashMap<KEY, VALUE>, kvs: &Vec<(KEY, VALUE)>) {
    for (k, _) in kvs {
        match map.get(k) {
            None => {}
            Some(read) => {
                assert!(*black_box(read) <= black_box(VALUE::MAX))
            }
        }
    }
}

fn random_remove_hashmap(map: &mut HashMap<KEY, VALUE>, kvs: &Vec<(KEY, VALUE)>) {
    for (k, _) in kvs {
        match map.remove(k) {
            None => {}
            Some(read) => {
                assert!(black_box(read) <= black_box(VALUE::MAX))
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
struct SliceBitSet {
    prefix: u8,
    bits: [u64; 4],
}

impl SliceBitSet {
    fn new(prefix: u8) -> SliceBitSet {
        let mut out = Self {
            prefix,
            ..Default::default()
        };
        // 0 isn't a legal L4 port generally speaking
        if out.prefix == 0 {
            // out.occupancy[0] = 1;
            out.bits[0] = 1;
        }
        out
    }

    fn allocate(&mut self) -> Option<NonZero<u16>> {
        let allocation = if self.bits[0] != u64::MAX {
            let bit = self.bits[0].trailing_ones() as u8;
            self.bits[0] |= 1 << bit;
            bit
        } else if self.bits[1] != u64::MAX {
            let bit = self.bits[1].trailing_ones() as u8;
            self.bits[1] |= 1 << bit;
            bit | 64 // | 64 adds 64 to an u8 which is 100% certain to be less than 64
        } else if self.bits[2] != u64::MAX {
            let bit = self.bits[2].trailing_ones() as u8;
            self.bits[2] |= 1 << bit;
            bit | 128 // | 128 adds 128 to an u8 which is 100% certain to be less than 64
        } else if self.bits[3] != u64::MAX {
            let bit = self.bits[3].trailing_ones() as u8;
            self.bits[3] |= 1 << bit;
            bit | 192 // | 192 adds 192 to an u8 which is 100% certain to be less than 64
        } else {
            return None;
        };
        let allocation = u16::from_le_bytes([allocation, self.prefix]);
        // allocation can't be zero because we checked for and eliminated zero prefix in ctor
        unsafe { Some(NonZero::new_unchecked(allocation)) }
    }

    fn deallocate(&mut self, allocation: NonZero<u16>) {
        let [allocation, prefix] = allocation.get().to_le_bytes();
        if prefix != self.prefix {
            panic!("WRONG PREFIX");
        }
        match allocation {
            0..64 => self.bits[0] ^= 1 << allocation,
            64..128 => self.bits[1] ^= 1 << (allocation ^ 64),
            128..192 => self.bits[2] ^= 1 << (allocation ^ 128),
            192.. => self.bits[3] ^= 1 << (allocation ^ 192),
        }
    }
}

#[derive(Clone)]
struct SliceBitSet2 {
    prefix: u8,
    used: [u8; u8::MAX as usize],
    free: smallvec::SmallVec<[u8; u8::MAX as usize]>,
}

impl SliceBitSet2 {
    fn new(prefix: u8) -> Self {
        let free = (if prefix == 0 { 1..u8::MAX } else { 0..u8::MAX }).collect();
        let used = [0; u8::MAX as usize];
        Self { prefix, used, free }
    }

    fn allocate(&mut self) -> Option<NonZero<u16>> {
        let index = self.free.pop()?;
        self.used[index as usize] = index;
        unsafe { Some(NonZero::new_unchecked(u16::from_le_bytes([index, self.prefix]))) }
    }

    fn deallocate(&mut self, allocation: NonZero<u16>) {
        let index = allocation.get().to_le_bytes()[0];
        self.used[index as usize] = 0;
        self.free.push(index);
    }
}

// benchmarks

fn bitset_manipulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("port allocators");
    let mut rng = rand::thread_rng();
    group.bench_function("bitset", |b| {
        b.iter(|| {
            let prefix: u8 = rng.gen();
            let mut slice = SliceBitSet::new(prefix);
            let mut allocations: Vec<_> =
                black_box((0..256).filter_map(|_| slice.allocate()).collect());
            allocations.shuffle(&mut rng);
            for allocation in allocations {
                slice.deallocate(black_box(allocation));
            }
        });
    });

    group.bench_function("free list", |b| {
        b.iter(|| {
            let prefix: u8 = rng.gen();
            let mut slice = SliceBitSet2::new(prefix);
            let mut allocations: Vec<_> =
                black_box((0..256).filter_map(|_| slice.allocate()).collect());
            allocations.shuffle(&mut rng);
            for allocation in allocations {
                slice.deallocate(black_box(allocation));
            }
        });
    });
    group.measurement_time(Duration::from_secs(60));
}

fn bitset_manipulation_bigger(c: &mut Criterion) {
    const PREFIXES: u8 = 100;
    const ALLOCATIONS: u8 = 192;
    let mut group = c.benchmark_group("connection deallocation");
    let mut rng = rand::thread_rng();
    let prefixes: Vec<u8> = (0..=PREFIXES).collect();
    let mut filled: Vec<_> = prefixes.iter().map(|prefix| {
        let mut slice = SliceBitSet::new(*prefix);
        let mut allocations: Vec<_> =
            (0..=ALLOCATIONS).filter_map(|_| slice.allocate()).collect();
        allocations.shuffle(&mut rng);
        (slice, allocations)
    }).collect();
    filled.shuffle(&mut rng);
    group.bench_function("bitset", |b| {
        b.iter(|| {
            let mut filled: VecDeque<_> = filled.clone().into_iter().collect();
            while let Some((mut slice, mut allocations)) = filled.pop_front() {
                let take: usize = rng.gen::<usize>() % allocations.len();
                let len = allocations.len() - 1;
                if take != len {
                    allocations.swap(len, take);
                }
                slice.deallocate(allocations.pop().unwrap());
                if allocations.is_empty() {
                    continue
                }
                filled.push_back((slice, allocations));
                let filled_len = filled.len();
                if filled_len == 0 {
                    break;
                }
                let take2: usize = rng.gen::<usize>() % filled_len;
                if filled_len - 1 != take2 {
                    filled.swap(filled_len - 1, take2);
                }
            }
        });
    });

    let mut filled: Vec<_> = prefixes.iter().map(|prefix| {
        let mut slice = SliceBitSet2::new(*prefix);
        let mut allocations: Vec<_> =
            (0..=ALLOCATIONS).filter_map(|_| slice.allocate()).collect();
        allocations.shuffle(&mut rng);
        (slice, allocations)
    }).collect();
    filled.shuffle(&mut rng);
    group.bench_function("vec", |b| {
        b.iter(|| {
            let mut filled: VecDeque<_> = filled.clone().into_iter().collect();
            while let Some((mut slice, mut allocations)) = filled.pop_front() {
                let take: usize = rng.gen::<usize>() % allocations.len();
                let len = allocations.len() - 1;
                if take != len {
                    allocations.swap(len, take);
                }
                slice.deallocate(allocations.pop().unwrap());
                if allocations.is_empty() {
                    continue
                }
                filled.push_back((slice, allocations));
                let filled_len = filled.len();
                if filled_len == 0 {
                    break;
                }
                let take2: usize = rng.gen::<usize>() % filled_len;
                if filled_len - 1 != take2 {
                    filled.swap(filled_len - 1, take2);
                }
            }
        });
    });
    group.measurement_time(Duration::from_secs(60));
}

fn btreemap_fill<const CAPACITY: usize>(c: &mut BenchmarkGroup<WallTime>) {
    let kv_pairs: Vec<(KEY, VALUE)> = (0..CAPACITY).map(|_| (random(), random())).collect();
    c.bench_function("btree fill", |b| {
        b.iter(|| fill_btreemap(black_box(&kv_pairs)))
    });
}

fn hashmap_fill<const CAPACITY: usize>(c: &mut BenchmarkGroup<WallTime>) {
    let kv_pairs: Vec<(KEY, VALUE)> = (0..CAPACITY).map(|_| (random(), random())).collect();
    c.bench_function("hashmap fill", |b| {
        b.iter(|| fill_hashmap::<CAPACITY>(black_box(&kv_pairs)))
    });
}

fn fill<const CAPACITY: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group("fill");
    btreemap_fill::<CAPACITY>(&mut group);
    hashmap_fill::<CAPACITY>(&mut group);
}

fn hashmap_random_read<const CAPACITY: usize>(c: &mut Criterion) {
    let mut group: BenchmarkGroup<WallTime> = c.benchmark_group("random read");
    group.bench_function("btree random access", |b| {
        let mut rng = rand::thread_rng();
        let mut kv_pairs: Vec<(KEY, VALUE)> = (0..CAPACITY).map(|_| (random(), random())).collect();
        let mut map = fill_btreemap(&kv_pairs);
        kv_pairs.shuffle(&mut rng);
        b.iter(|| {
            random_read_btreemap(black_box(&map), black_box(&kv_pairs));
            let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            kv_pairs.shuffle(&mut rng);
            // random_read_btreemap(black_box(&map), black_box(&kv_pairs));
            // let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            // kv_pairs.shuffle(&mut rng);
            // random_read_btreemap(black_box(&map), black_box(&kv_pairs));
            // let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            // kv_pairs.shuffle(&mut rng);
            random_remove_btreemap(black_box(&mut map), black_box(&kv_pairs));
        })
    });
    group.bench_function("hash table random access", |b| {
        let mut rng = rand::thread_rng();
        let mut kv_pairs: Vec<(KEY, VALUE)> = (0..CAPACITY).map(|_| (random(), random())).collect();
        let mut map = fill_hashmap::<CAPACITY>(&kv_pairs);
        kv_pairs.shuffle(&mut rng);
        b.iter(|| {
            random_read_hashmap(black_box(&map), black_box(&kv_pairs));
            let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            kv_pairs.shuffle(&mut rng);
            // random_read_hashmap(black_box(&map), black_box(&kv_pairs));
            // let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            // kv_pairs.shuffle(&mut rng);
            // random_read_hashmap(black_box(&map), black_box(&kv_pairs));
            // let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            // kv_pairs.shuffle(&mut rng);
            random_remove_hashmap(black_box(&mut map), black_box(&kv_pairs));
        })
    });
}

fn group<const CAPACITY: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group("containers");
    group.bench_function("btree random read", |b| {
        let mut rng = rand::thread_rng();
        let mut kv_pairs: Vec<(KEY, VALUE)> = (0..CAPACITY).map(|_| (random(), random())).collect();
        let mut map = fill_btreemap(&kv_pairs);
        kv_pairs.shuffle(&mut rng);
        b.iter(|| {
            random_read_btreemap(black_box(&map), black_box(&kv_pairs));
            let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            kv_pairs.shuffle(&mut rng);
            random_read_btreemap(black_box(&map), black_box(&kv_pairs));
            let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            kv_pairs.shuffle(&mut rng);
            random_read_btreemap(black_box(&map), black_box(&kv_pairs));
            let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            kv_pairs.shuffle(&mut rng);
            random_remove_btreemap(black_box(&mut map), black_box(&kv_pairs));
        })
    });
    group.bench_function("hash table random read", |b| {
        let mut rng = rand::thread_rng();
        let mut kv_pairs: Vec<(KEY, VALUE)> = (0..CAPACITY).map(|_| (random(), random())).collect();
        let mut map = fill_hashmap::<CAPACITY>(&kv_pairs);
        kv_pairs.shuffle(&mut rng);
        b.iter(|| {
            random_read_hashmap(black_box(&map), black_box(&kv_pairs));
            let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            kv_pairs.shuffle(&mut rng);
            random_read_hashmap(black_box(&map), black_box(&kv_pairs));
            let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            kv_pairs.shuffle(&mut rng);
            random_read_hashmap(black_box(&map), black_box(&kv_pairs));
            let mut kv_pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
            kv_pairs.shuffle(&mut rng);
            random_remove_hashmap(black_box(&mut map), black_box(&kv_pairs));
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = group::<256>, fill::<256>, bitset_manipulation, bitset_manipulation_bigger
);
criterion_main!(benches);
