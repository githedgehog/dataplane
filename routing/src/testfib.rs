// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Vanilla fib used for testing

#![allow(missing_docs)]

use crate::fib::fibobjects::FibGroup;
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Debug, Default)]
#[allow(unused)]
pub struct TestFib(BTreeSet<Arc<FibGroup>>);

impl TestFib {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Arc<FibGroup>> {
        self.0.iter()
    }

    /// Add a group, without creating it if an identical group exists,
    /// returning a shared reference in any case.
    #[must_use]
    pub fn add_group(&mut self, group: FibGroup) -> Arc<FibGroup> {
        let arc_gr = Arc::new(group);
        if let Some(e) = self.0.get(&arc_gr) {
            Arc::clone(e)
        } else {
            let out = Arc::clone(&arc_gr);
            self.0.insert(arc_gr);
            out
        }
    }

    /// Remove all groups that are not referenced by anyone.
    pub fn purge(&mut self) {
        self.0.retain(|group| Arc::strong_count(group) > 1);
    }
}
