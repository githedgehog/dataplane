// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Track native dependencies even after a Rust handle is dropped or forgotten.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::Cell;

/// The owner holds one reference; native dependents hold the others. A failed removal marks
/// dependencies retained, so dropping their handles cannot destroy objects still used by the NIC.
#[derive(Debug, Clone, Default)]
pub(super) struct Resource(pub(super) Rc<Cell<bool>>);

impl Resource {
    pub(super) fn in_use(&self) -> bool {
        self.0.get() || Rc::strong_count(&self.0) != 1
    }
}

/// Released only after confirmed native removal (or a successful replacement of dependencies).
/// Otherwise, retain the native dependencies until port teardown. Rust allocations still drop.
#[derive(Debug, Default)]
pub(super) struct Dependencies(pub(super) Vec<Resource>);

impl Dependencies {
    pub(super) fn release(&mut self) {
        self.0.clear();
    }
}

impl Drop for Dependencies {
    fn drop(&mut self) {
        for resource in &self.0 {
            resource.0.set(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_removal_retains_native_resources_without_leaking_rust_owners() {
        let resource = Resource::default();
        let weak = Rc::downgrade(&resource.0);
        drop(Dependencies(vec![resource.clone()]));
        assert!(resource.in_use());
        drop(resource);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn confirmed_removal_releases_dependencies() {
        let resource = Resource::default();
        let mut dependencies = Dependencies(vec![resource.clone()]);
        assert!(resource.in_use());
        dependencies.release();
        drop(dependencies);
        assert!(!resource.in_use());
    }

    #[test]
    fn forgotten_dependents_keep_resources_in_use() {
        let resource = Resource::default();
        let dependencies = core::mem::ManuallyDrop::new(Dependencies(vec![resource.clone()]));
        assert!(resource.in_use());
        // Reclaim the deliberately undropped dependency so leak sanitizers can run this test.
        core::mem::ManuallyDrop::into_inner(dependencies).release();
    }
}
