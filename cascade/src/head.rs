// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use lookup::Lookup;
pub trait MutableHead: Lookup<<Self as MutableHead>::Key, <Self as MutableHead>::Action> {
    type Key;
    type Action;
    type Op;
    type Frozen: Lookup<Self::Key, Self::Action>;
    fn write(&self, op: Self::Op);
    fn freeze(&self) -> Self::Frozen;
    fn approx_size(&self) -> usize;
}
