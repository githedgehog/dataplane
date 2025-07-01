// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A table to store arbitrary data for `VpcDiscriminants`.
//! This module implements a table that allows building tables to associate arbitrary data to
//! a VPC identified by a Vpc discriminant. A discriminant may be VxLAN vni or any other value
//! that allows associating a packet to a Vpc. The advantage of the map in this module is that
//! it does not make assumptions about the nature of the data stored and allows concurrent access
//! among threads using left-right. The only requirement for the data type is to implement trait
//! `Clone`.

#![allow(unused)]

use crate::{VpcDiscriminant, VpcMapError, VpcMapResult};
use ahash::RandomState;
use left_right::new_from_empty;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use std::clone::Clone;
use std::collections::HashMap;

#[derive(Clone, Default)]
pub struct VpcMap<T: Clone>(HashMap<VpcDiscriminant, T, RandomState>);

impl<T: Clone> VpcMap<T> {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
    /// Add the given entry to the map
    #[cfg(test)]
    pub(crate) fn add(&mut self, disc: VpcDiscriminant, entry: T) -> VpcMapResult<()> {
        if let std::collections::hash_map::Entry::Vacant(e) = self.0.entry(disc) {
            e.insert(entry);
            Ok(())
        } else {
            Err(VpcMapError::EntryExists(disc))
        }
    }
    /// Add the entry unconditionally.
    fn add_checked(&mut self, disc: VpcDiscriminant, entry: T) {
        self.0.insert(disc, entry);
    }
    /// Remove element with the given `VpcDiscriminant`. Won't fail if not there.
    pub(crate) fn del(&mut self, disc: VpcDiscriminant) {
        self.0.remove(&disc);
    }
    /// Get reference to element with the given `VpcDiscriminant`
    pub fn get(&self, disc: VpcDiscriminant) -> Option<&T> {
        self.0.get(&disc)
    }
}

enum VpcMapChange<T: Clone> {
    Add(VpcDiscriminant, T),
    Del(VpcDiscriminant),
    SetMap(VpcMap<T>),
}
impl<T: Clone> Absorb<VpcMapChange<T>> for VpcMap<T> {
    fn absorb_first(&mut self, change: &mut VpcMapChange<T>, _: &Self) {
        match change {
            VpcMapChange::Add(disc, entry) => {
                self.add_checked(*disc, entry.clone());
            }
            VpcMapChange::Del(disc) => {
                self.del(*disc);
            }
            VpcMapChange::SetMap(new_map) => {
                *self = new_map.clone();
            }
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub struct VpcMapWriter<T: Clone>(WriteHandle<VpcMap<T>, VpcMapChange<T>>);
pub struct VpcMapReader<T: Clone>(ReadHandle<VpcMap<T>>);

impl<T: Clone> VpcMapWriter<T> {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> VpcMapWriter<T> {
        let (w, _) = new_from_empty::<VpcMap<T>, VpcMapChange<T>>(VpcMap::new());
        VpcMapWriter(w)
    }
    #[must_use]
    pub fn get_reader(&self) -> VpcMapReader<T> {
        VpcMapReader(self.0.clone())
    }
    /// Completely replaces the inner `VpcMap` with the provided one. This is useful when the
    /// map is built for configuration purposes (E.g. some NAT tables).
    pub fn set_map(&mut self, map: VpcMap<T>) {
        self.0.append(VpcMapChange::SetMap(map));
        self.0.publish();
    }
    /// Add an entry to the `VpcMap`
    pub fn add(&mut self, disc: VpcDiscriminant, entry: T, publish: bool) -> VpcMapResult<()> {
        let inner = self.0.raw_write_handle();
        unsafe {
            let inner = inner.as_ref();
            if inner.0.contains_key(&disc) {
                return Err(VpcMapError::EntryExists(disc));
            }
        }
        self.0.append(VpcMapChange::Add(disc, entry));
        if publish {
            self.0.publish();
        }
        Ok(())
    }
    /// Remove the entry with the given `VpcDiscriminant`
    pub fn del(&mut self, disc: VpcDiscriminant, publish: bool) {
        self.0.append(VpcMapChange::Del(disc));
        if publish {
            self.0.publish();
        }
    }
    pub fn publish(&mut self) {
        self.0.publish();
    }
}

impl<T: Clone> VpcMapReader<T> {
    pub fn enter(&self) -> Option<ReadGuard<'_, VpcMap<T>>> {
        self.0.enter()
    }
    // TODO provide an easy api to read
}
