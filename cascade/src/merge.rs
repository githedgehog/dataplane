// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
pub trait MergeInto<Target> {
    fn merge_into(&self, target: &Target) -> Target;
}
