// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use match_action::FieldSpec;

use super::table::RefRule;
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DynShapeError {
    #[error("specs are empty")]
    EmptySpecs,
    #[error(
        "spec {idx} offset {offset} disagrees with cumulative size {expected_offset} \
         of fields 0..{idx}"
    )]
    OffsetMismatch {
        idx: usize,
        offset: usize,
        expected_offset: usize,
    },
    #[error("spec {idx} has zero size")]
    ZeroSize { idx: usize },
    #[error("rule {rule} has {actual} predicates, specs has {expected}")]
    FieldCountMismatch {
        rule: usize,
        expected: usize,
        actual: usize,
    },
    #[error("rule {rule} field {field}: predicate width {actual} != spec size {expected}")]
    PredicateWidthMismatch {
        rule: usize,
        field: usize,
        expected: usize,
        actual: usize,
    },
}
#[derive(Clone, Debug)]
pub struct DynReferenceTable<A> {
    specs: Vec<FieldSpec>,
    key_size: usize,
    rules: Vec<RefRule<A>>,
}

impl<A> DynReferenceTable<A> {
    pub fn new(specs: Vec<FieldSpec>, rules: Vec<RefRule<A>>) -> Result<Self, DynShapeError> {
        let key_size = validate_specs(&specs)?;
        for (rule_idx, rule) in rules.iter().enumerate() {
            if rule.fields().len() != specs.len() {
                return Err(DynShapeError::FieldCountMismatch {
                    rule: rule_idx,
                    expected: specs.len(),
                    actual: rule.fields().len(),
                });
            }
            for (field_idx, (pred, spec)) in rule.fields().iter().zip(&specs).enumerate() {
                if pred.width() != spec.size {
                    return Err(DynShapeError::PredicateWidthMismatch {
                        rule: rule_idx,
                        field: field_idx,
                        expected: spec.size,
                        actual: pred.width(),
                    });
                }
            }
        }
        Ok(Self {
            specs,
            key_size,
            rules,
        })
    }
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.key_size
    }
    #[must_use]
    pub fn specs(&self) -> &[FieldSpec] {
        &self.specs
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
    pub fn lookup_bytes(&self, key: &[u8]) -> Option<&A> {
        assert_eq!(key.len(), self.key_size, "key length must equal key_size");
        self.rules
            .iter()
            .find(|rule| rule.matches_packed(&self.specs, key))
            .map(RefRule::action)
    }
    #[must_use]
    pub fn matches_bytes(&self, key: &[u8]) -> Vec<&RefRule<A>> {
        assert_eq!(key.len(), self.key_size, "key length must equal key_size");
        self.rules
            .iter()
            .filter(|rule| rule.matches_packed(&self.specs, key))
            .collect()
    }
}
fn validate_specs(specs: &[FieldSpec]) -> Result<usize, DynShapeError> {
    if specs.is_empty() {
        return Err(DynShapeError::EmptySpecs);
    }
    let mut cursor = 0usize;
    for (idx, spec) in specs.iter().enumerate() {
        if spec.size == 0 {
            return Err(DynShapeError::ZeroSize { idx });
        }
        if spec.offset != cursor {
            return Err(DynShapeError::OffsetMismatch {
                idx,
                offset: spec.offset,
                expected_offset: cursor,
            });
        }
        cursor += spec.size;
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use match_action::{FieldKind, FieldPredicate};

    fn spec(name: &'static str, kind: FieldKind, size: usize, offset: usize) -> FieldSpec {
        FieldSpec {
            name,
            kind,
            size,
            offset,
        }
    }

    fn make_rule_5tuple(
        proto: u8,
        src: [u8; 4],
        src_len: u8,
        dport_lo: u16,
        dport_hi: u16,
        action: u32,
    ) -> RefRule<u32> {
        use match_action::predicate::{Exact, FieldBytes, Prefix, Range};
        let proto_b: FieldBytes = [proto].iter().copied().collect();
        let src_b: FieldBytes = src.iter().copied().collect();
        let dlo: FieldBytes = dport_lo.to_be_bytes().iter().copied().collect();
        let dhi: FieldBytes = dport_hi.to_be_bytes().iter().copied().collect();
        RefRule::new(
            vec![
                FieldPredicate::Exact(Exact::new(proto_b)),
                FieldPredicate::Prefix(Prefix::new(src_b, src_len)),
                FieldPredicate::Range(Range::new(dlo, dhi)),
            ],
            action,
        )
    }

    fn five_tuple_specs() -> Vec<FieldSpec> {
        vec![
            spec("proto", FieldKind::Exact, 1, 0),
            spec("src", FieldKind::Prefix, 4, 1),
            spec("dport", FieldKind::Range, 2, 5),
        ]
    }

    #[test]
    fn lookup_bytes_hits_and_misses() {
        let table = DynReferenceTable::new(
            five_tuple_specs(),
            vec![make_rule_5tuple(6, [10, 0, 0, 0], 8, 22, 22, 0xAA)],
        )
        .expect("valid shape");
        assert_eq!(table.key_size(), 1 + 4 + 2);

        let mut key = vec![6u8];
        key.extend_from_slice(&[10, 1, 2, 3]);
        key.extend_from_slice(&22u16.to_be_bytes());
        assert_eq!(table.lookup_bytes(&key), Some(&0xAA));
        let mut key = vec![6u8];
        key.extend_from_slice(&[11, 0, 0, 0]);
        key.extend_from_slice(&22u16.to_be_bytes());
        assert_eq!(table.lookup_bytes(&key), None);
        let mut key = vec![6u8];
        key.extend_from_slice(&[10, 1, 2, 3]);
        key.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(table.lookup_bytes(&key), None);
    }

    #[test]
    fn matches_bytes_is_nonlossy() {
        use match_action::predicate::{Exact, FieldBytes};
        let broad = RefRule::new(
            vec![
                FieldPredicate::Exact(Exact::new([6u8].iter().copied().collect::<FieldBytes>())),
                FieldPredicate::Prefix(match_action::predicate::Prefix::new(
                    [0u8; 4].iter().copied().collect::<FieldBytes>(),
                    0,
                )),
                FieldPredicate::Range(match_action::predicate::Range::new(
                    0u16.to_be_bytes().iter().copied().collect::<FieldBytes>(),
                    u16::MAX
                        .to_be_bytes()
                        .iter()
                        .copied()
                        .collect::<FieldBytes>(),
                )),
            ],
            0xBB,
        );
        let narrow = make_rule_5tuple(6, [10, 0, 0, 0], 8, 22, 22, 0xCC);
        let table =
            DynReferenceTable::new(five_tuple_specs(), vec![broad, narrow]).expect("valid shape");

        let mut key = vec![6u8];
        key.extend_from_slice(&[10, 1, 2, 3]);
        key.extend_from_slice(&22u16.to_be_bytes());
        let m = table.matches_bytes(&key);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].action(), &0xBB);
        assert_eq!(m[1].action(), &0xCC);
    }

    #[test]
    fn rejects_offset_mismatch() {
        let bad = vec![
            spec("proto", FieldKind::Exact, 1, 0),
            spec("src", FieldKind::Prefix, 4, 0),
        ];
        let err = DynReferenceTable::<()>::new(bad, vec![]).unwrap_err();
        assert!(matches!(
            err,
            DynShapeError::OffsetMismatch {
                idx: 1,
                offset: 0,
                expected_offset: 1
            }
        ));
    }

    #[test]
    fn rejects_predicate_width_mismatch() {
        use match_action::predicate::{Exact, FieldBytes};
        let bad_proto: FieldBytes = [0u8, 0].iter().copied().collect();
        let rule = RefRule::new(vec![FieldPredicate::Exact(Exact::new(bad_proto))], 0u32);
        let specs = vec![spec("proto", FieldKind::Exact, 1, 0)];
        let err = DynReferenceTable::new(specs, vec![rule]).unwrap_err();
        assert!(matches!(
            err,
            DynShapeError::PredicateWidthMismatch {
                rule: 0,
                field: 0,
                expected: 1,
                actual: 2
            }
        ));
    }

    #[test]
    fn rejects_empty_specs() {
        let err = DynReferenceTable::<u32>::new(vec![], vec![]).unwrap_err();
        assert_eq!(err, DynShapeError::EmptySpecs);
    }

    #[test]
    fn rejects_zero_size_spec() {
        let bad = vec![spec("x", FieldKind::Exact, 0, 0)];
        let err = DynReferenceTable::<u32>::new(bad, vec![]).unwrap_err();
        assert_eq!(err, DynShapeError::ZeroSize { idx: 0 });
    }
    #[test]
    fn dyn_table_agrees_with_typed_table() {
        use crate::reference::ReferenceTable;
        use core::net::Ipv4Addr;
        use lookup::Lookup;
        use match_action::{ExactSpec, MatchKey, PrefixSpec, RangeSpec};

        #[derive(MatchKey)]
        struct K {
            #[exact]
            proto: u8,
            #[prefix]
            src: Ipv4Addr,
            #[range]
            dport: u16,
        }

        let rule_fields = KRule {
            proto: ExactSpec::new(6),
            src: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            dport: RangeSpec::exact(22),
        }
        .into_backend_fields::<crate::reference::Erased>();

        let typed = ReferenceTable::<K, u32>::new(vec![RefRule::new(rule_fields.clone(), 0xAA)]);
        let dynamic = DynReferenceTable::new(
            K::field_specs().to_vec(),
            vec![RefRule::new(rule_fields, 0xAA)],
        )
        .expect("valid shape");

        for (key, label) in &[
            (
                K {
                    proto: 6,
                    src: "10.1.2.3".parse().unwrap(),
                    dport: 22,
                },
                "hit",
            ),
            (
                K {
                    proto: 6,
                    src: "11.0.0.0".parse().unwrap(),
                    dport: 22,
                },
                "src miss",
            ),
            (
                K {
                    proto: 17,
                    src: "10.1.2.3".parse().unwrap(),
                    dport: 22,
                },
                "proto miss",
            ),
        ] {
            let bytes = key.as_key();
            assert_eq!(
                typed.lookup(key).copied(),
                dynamic.lookup_bytes(&bytes).copied(),
                "typed vs dynamic disagree on {label}",
            );
        }
    }
}
