// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)]

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
pub trait Projection<T> {
    fn project(self) -> T;
}
impl<K> Projection<Option<K>> for Option<K> {
    fn project(self) -> Option<K> {
        self
    }
}
pub trait Lookup<K, A> {
    fn lookup(&self, key: &K) -> Option<&A>;
    fn classify<S>(&self, source: S) -> Option<&A>
    where
        S: Projection<K>,
    {
        self.lookup(&source.project())
    }
    fn classify_opt<S>(&self, source: S) -> Option<&A>
    where
        S: Projection<Option<K>>,
    {
        source.project().and_then(|key| self.lookup(&key))
    }
}

impl<K: Ord, V> Lookup<K, V> for BTreeMap<K, V> {
    fn lookup(&self, key: &K) -> Option<&V> {
        BTreeMap::get(self, key)
    }
}

impl<K: Eq + Hash, V, S: std::hash::BuildHasher> Lookup<K, V> for HashMap<K, V, S> {
    fn lookup(&self, key: &K) -> Option<&V> {
        HashMap::get(self, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pkt {
        src: u32,
        dst: u32,
        sport: u16,
        dport: u16,
    }

    impl Projection<(u32, u32)> for &Pkt {
        fn project(self) -> (u32, u32) {
            (self.src, self.dst)
        }
    }

    impl Projection<(u32, u32, u16, u16)> for &Pkt {
        fn project(self) -> (u32, u32, u16, u16) {
            (self.src, self.dst, self.sport, self.dport)
        }
    }

    impl<'a> Projection<(&'a u32, &'a u32)> for &'a Pkt {
        fn project(self) -> (&'a u32, &'a u32) {
            (&self.src, &self.dst)
        }
    }
    impl Projection<Option<(u32, u32)>> for &Pkt {
        fn project(self) -> Option<(u32, u32)> {
            (self.src != 0).then_some((self.src, self.dst))
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Action {
        Allow,
        Drop,
    }

    #[test]
    fn classify_picks_the_two_tuple_projection_from_the_table_type() {
        let mut table: BTreeMap<(u32, u32), Action> = BTreeMap::new();
        table.insert((10, 20), Action::Drop);
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 22,
            dport: 80,
        };
        assert_eq!(table.classify(&pkt), Some(&Action::Drop));
    }

    #[test]
    fn classify_picks_the_four_tuple_projection_from_the_table_type() {
        let mut table: BTreeMap<(u32, u32, u16, u16), Action> = BTreeMap::new();
        table.insert((10, 20, 22, 80), Action::Allow);
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 22,
            dport: 80,
        };
        assert_eq!(table.classify(&pkt), Some(&Action::Allow));
    }

    #[test]
    fn borrowed_tuple_projection_threads_lifetime() {
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 0,
            dport: 0,
        };
        let (src, dst): (&u32, &u32) = (&pkt).project();
        assert_eq!(*src, 10);
        assert_eq!(*dst, 20);
    }

    #[test]
    fn miss_returns_none() {
        let table: BTreeMap<(u32, u32), Action> = BTreeMap::new();
        let pkt = Pkt {
            src: 1,
            dst: 2,
            sport: 3,
            dport: 4,
        };
        assert_eq!(table.classify(&pkt), None);
    }

    #[test]
    fn classify_opt_looks_up_when_projection_yields_some() {
        let mut table: BTreeMap<(u32, u32), Action> = BTreeMap::new();
        table.insert((10, 20), Action::Drop);
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 0,
            dport: 0,
        };
        assert_eq!(table.classify_opt(&pkt), Some(&Action::Drop));
    }

    #[test]
    fn classify_opt_short_circuits_when_projection_yields_none() {
        let mut table: BTreeMap<(u32, u32), Action> = BTreeMap::new();
        table.insert((0, 20), Action::Drop);
        let pkt = Pkt {
            src: 0,
            dst: 20,
            sport: 0,
            dport: 0,
        };
        assert_eq!(table.classify_opt(&pkt), None);
    }

    #[test]
    fn classify_opt_accepts_a_computed_option_via_identity() {
        let mut table: BTreeMap<(u32, u32), Action> = BTreeMap::new();
        table.insert((10, 20), Action::Drop);
        let built: Option<(u32, u32)> = Some((10, 20));
        assert_eq!(table.classify_opt(built), Some(&Action::Drop));
        assert_eq!(table.classify_opt(None::<(u32, u32)>), None);
    }

    #[test]
    fn hashmap_backend_works_the_same_way() {
        let mut table: HashMap<(u32, u32), Action> = HashMap::new();
        table.insert((10, 20), Action::Drop);
        let pkt = Pkt {
            src: 10,
            dst: 20,
            sport: 0,
            dport: 0,
        };
        assert_eq!(table.classify(&pkt), Some(&Action::Drop));
    }
}
