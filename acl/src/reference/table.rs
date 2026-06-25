// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use core::marker::PhantomData;

use lookup::Lookup;
use match_action::{FieldPredicate, FieldSpec, MatchKey};
const MAX_KEY_BYTES: usize = 256;
#[derive(Clone, Debug)]
pub struct RefRule<A> {
    fields: Vec<FieldPredicate>,
    action: A,
}

impl<A> RefRule<A> {
    #[must_use]
    pub fn new(fields: Vec<FieldPredicate>, action: A) -> Self {
        Self { fields, action }
    }

    pub fn action(&self) -> &A {
        &self.action
    }
    #[must_use]
    pub fn fields(&self) -> &[FieldPredicate] {
        &self.fields
    }

    pub(crate) fn matches_packed(&self, specs: &[FieldSpec], buf: &[u8]) -> bool {
        debug_assert_eq!(self.fields.len(), specs.len());
        self.fields
            .iter()
            .zip(specs)
            .all(|(pred, spec)| pred.matches(&buf[spec.offset..spec.offset + spec.size]))
    }
}
#[derive(Clone, Debug)]
pub struct ReferenceTable<K, A> {
    rules: Vec<RefRule<A>>,
    _key: PhantomData<fn() -> K>,
}

impl<K: MatchKey, A> ReferenceTable<K, A> {
    #[must_use]
    pub fn new(rules: Vec<RefRule<A>>) -> Self {
        Self {
            rules,
            _key: PhantomData,
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use]
    pub fn rules(&self) -> &[RefRule<A>] {
        &self.rules
    }
    fn pack(key: &K) -> Option<[u8; MAX_KEY_BYTES]> {
        if K::KEY_SIZE > MAX_KEY_BYTES {
            return None;
        }
        let mut buf = [0u8; MAX_KEY_BYTES];
        key.as_key_into(&mut buf[..K::KEY_SIZE]);
        Some(buf)
    }
    #[must_use]
    pub fn matches(&self, key: &K) -> Vec<&RefRule<A>> {
        let Some(buf) = Self::pack(key) else {
            return Vec::new();
        };
        let specs = K::field_specs();
        self.rules
            .iter()
            .filter(|rule| rule.matches_packed(specs, &buf))
            .collect()
    }
}

impl<K: MatchKey, A> Lookup<K, A> for ReferenceTable<K, A> {
    fn lookup(&self, key: &K) -> Option<&A> {
        let buf = Self::pack(key)?;
        let specs = K::field_specs();
        self.rules
            .iter()
            .find(|rule| rule.matches_packed(specs, &buf))
            .map(RefRule::action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;
    use match_action::{Erased, ExactSpec, MatchKey, PrefixSpec, RangeSpec};

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum Verdict {
        Allow,
        Drop,
    }

    #[derive(MatchKey)]
    struct FiveTuple {
        #[exact]
        proto: u8,
        #[prefix]
        src_ip: Ipv4Addr,
        #[prefix]
        dst_ip: Ipv4Addr,
        #[range]
        src_port: u16,
        #[range]
        dst_port: u16,
    }

    fn drop_10_8_to_22() -> RefRule<Verdict> {
        RefRule::new(
            FiveTupleRule {
                proto: ExactSpec::new(6),
                src_ip: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
                dst_ip: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
                src_port: RangeSpec::new(0, u16::MAX),
                dst_port: RangeSpec::exact(22),
            }
            .into_backend_fields::<Erased>(),
            Verdict::Drop,
        )
    }

    #[test]
    fn single_rule_hit_and_miss() {
        let table = ReferenceTable::new(vec![drop_10_8_to_22()]);

        assert_eq!(
            table.lookup(&FiveTuple {
                proto: 6,
                src_ip: "10.1.2.3".parse().unwrap(),
                dst_ip: "192.168.1.1".parse().unwrap(),
                src_port: 54321,
                dst_port: 22,
            }),
            Some(&Verdict::Drop),
        );
        assert_eq!(
            table.lookup(&FiveTuple {
                proto: 6,
                src_ip: "11.0.0.1".parse().unwrap(),
                dst_ip: "192.168.1.1".parse().unwrap(),
                src_port: 54321,
                dst_port: 22,
            }),
            None,
        );
        assert_eq!(
            table.lookup(&FiveTuple {
                proto: 6,
                src_ip: "10.1.2.3".parse().unwrap(),
                dst_ip: "192.168.1.1".parse().unwrap(),
                src_port: 54321,
                dst_port: 80,
            }),
            None,
        );
    }

    #[test]
    fn empty_table_always_misses() {
        let table: ReferenceTable<FiveTuple, Verdict> = ReferenceTable::empty();
        assert!(table.is_empty());
        assert_eq!(
            table.lookup(&FiveTuple {
                proto: 6,
                src_ip: Ipv4Addr::UNSPECIFIED,
                dst_ip: Ipv4Addr::UNSPECIFIED,
                src_port: 0,
                dst_port: 0,
            }),
            None,
        );
    }
    fn allow_all_tcp() -> RefRule<Verdict> {
        RefRule::new(
            FiveTupleRule {
                proto: ExactSpec::new(6),
                src_ip: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
                dst_ip: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
                src_port: RangeSpec::new(0, u16::MAX),
                dst_port: RangeSpec::new(0, u16::MAX),
            }
            .into_backend_fields::<Erased>(),
            Verdict::Allow,
        )
    }

    fn overlapping_packet() -> FiveTuple {
        FiveTuple {
            proto: 6,
            src_ip: "10.1.2.3".parse().unwrap(),
            dst_ip: "192.168.1.1".parse().unwrap(),
            src_port: 54321,
            dst_port: 22,
        }
    }

    #[test]
    fn positional_precedence_first_match_wins() {
        let table = ReferenceTable::new(vec![allow_all_tcp(), drop_10_8_to_22()]);
        assert_eq!(table.lookup(&overlapping_packet()), Some(&Verdict::Allow));
    }

    #[test]
    fn matches_is_nonlossy_and_retains_shadowed_losers() {
        let table = ReferenceTable::new(vec![allow_all_tcp(), drop_10_8_to_22()]);
        let matched = table.matches(&overlapping_packet());

        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].action(), &Verdict::Allow);
        assert_eq!(matched[1].action(), &Verdict::Drop);
    }
}
