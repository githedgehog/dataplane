// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use core::fmt;
pub trait Upsert {
    type Op;
    fn upsert(&mut self, op: Self::Op);
    fn seed(op: Self::Op) -> Self
    where
        Self: Sized;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastWriteWins<V> {
    pub version: u64,
    pub value: V,
}

impl<V> Upsert for LastWriteWins<V> {
    type Op = LastWriteWins<V>;

    fn upsert(&mut self, op: Self::Op) {
        if op.version > self.version {
            *self = op;
        }
    }

    fn seed(op: Self::Op) -> Self {
        op
    }
}

impl<V: fmt::Display> fmt::Display for LastWriteWins<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@v{}", self.value, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_write_wins_is_commutative() {
        let a = LastWriteWins {
            version: 1,
            value: 100,
        };
        let b = LastWriteWins {
            version: 2,
            value: 200,
        };
        let c = LastWriteWins {
            version: 3,
            value: 300,
        };

        for order in [
            [a, b, c],
            [a, c, b],
            [b, a, c],
            [b, c, a],
            [c, a, b],
            [c, b, a],
        ] {
            let mut state = LastWriteWins::<u32>::seed(order[0]);
            state.upsert(order[1]);
            state.upsert(order[2]);
            assert_eq!(state.value, 300);
            assert_eq!(state.version, 3);
        }
    }
    #[test]
    fn last_write_wins_tied_versions_violate_commutativity() {
        let mut keep_first = LastWriteWins::<u32>::seed(LastWriteWins {
            version: 5,
            value: 100,
        });
        keep_first.upsert(LastWriteWins {
            version: 5,
            value: 999,
        });

        let mut keep_second = LastWriteWins::<u32>::seed(LastWriteWins {
            version: 5,
            value: 999,
        });
        keep_second.upsert(LastWriteWins {
            version: 5,
            value: 100,
        });

        assert_eq!(keep_first.value, 100);
        assert_eq!(keep_second.value, 999);
    }
}
