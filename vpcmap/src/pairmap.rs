// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A table to store arbitrary data for a pair of `VpcDiscriminant`s.
//! This table allows storing arbitrary chunks of data that relate two VPCs by means of storing
//! generic objects for two `VpcDiscriminant`s. The examples that follow clarifies the utility.
//!
//! Suppose we need to store some chunk of data for a couple of VPCs identified by their VxLAN Vni; that is,
//! by some tuple (vni1, vni2). We generically refer to this tuple as (east, west).
//! The data may be statistics or some NAT mapping or whatever other information may relate those two VPCs.
//! Suppose that the specific Vni values are (3000,4000). The table defined in this module provides a very simple
//! implementation of a hash table that:
//!    * stores data object automatically creating (east, west) or (west, east) keys without duplicating the data
//!    * provides concurrent access to the table using left-right.
//!
//!    (key)
//! ┌────────────┐
//! │(east, west)┼────────┐
//! └────────────┘        │  ┌───────────┐
//!                       └──► arbitrary │
//!                        ┌─►   data    │
//! ┌────────────┐         │ └───────────┘
//! │(west, east)┼─────────┘
//! └────────────┘
//!
//! Some uses may require that the data returned by query (east, west) be different from that returned when
//! querying for (west, east). This may occur when performing symmetrical operations that have some sense of directionality.
//! An example where this sense of directionality matters is when processing packets between two VPCs (e.g. 3000 and 4000).
//! On the forward path, we may access some NAT table by querying for (3000, 4000). For return traffic,
//! we may query for (4000, 3000). In both cases, we may want to access different NAT mappings within the same data.
//! (Ofc, other implementations could simply allow for this by storing two distinct objects; one per permutation of the discriminants).
//! Storing both together has the advantage that one cannot exist without the other.
//!
//! ┌────────────┐
//! │(east, west)┼────────┐
//! └────────────┘        │  ┌───────┬────────┐
//!                       └──►  east │  west  │
//!                        ┌─►  data │  data  │
//! ┌────────────┐         │ └───────┴────────┘
//! │(west, east)┼─────────┘
//! └────────────┘
//!
//! This table allows for such "directional" queries too thanks to a very simple trait `VpcPair`.
//! In either use of the table, it is forbidden to add elements with east == west for obvious reasons, and the code
//! will panic since this is a bug.

#![allow(unused)]

use super::{VpcDiscriminant, VpcMapError, VpcMapResult};
use ahash::RandomState;
use left_right::new_from_empty;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use std::collections::HashMap;
use std::rc::Rc;

pub trait VpcPair {
    type SidedData;
    fn get_east_disc(&self) -> VpcDiscriminant;
    fn get_west_disc(&self) -> VpcDiscriminant;
    fn get_east_data(&self) -> &Self::SidedData;
    fn get_west_data(&self) -> &Self::SidedData;
}

#[derive(Clone, Default)]
pub struct VpcPairMap<P: VpcPair + Clone>(
    HashMap<(VpcDiscriminant, VpcDiscriminant), Rc<P>, RandomState>,
);
impl<P: VpcPair + Clone> VpcPairMap<P> {
    pub fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
    pub fn add(&mut self, entry: P) {
        let east = entry.get_east_disc();
        let west = entry.get_west_disc();
        #[cfg(test)]
        if east == west {
            unreachable!("Bug: can't insert pair with identical discriminants");
        }
        let rcpair = Rc::new(entry);
        self.0.insert((east, west), rcpair.clone());
        self.0.insert((west, east), rcpair);
    }
    pub fn del(&mut self, east: VpcDiscriminant, west: VpcDiscriminant) {
        self.0.remove(&(east, west));
        self.0.remove(&(west, east));
    }
    /// Get the data associated to a certain (east, west) pair.
    /// Returns None if no data is associated to (east, west) or (west, east).
    pub fn get(&self, east: VpcDiscriminant, west: VpcDiscriminant) -> Option<&P> {
        self.0.get(&(east, west)).map(|v| &**v)
    }
    fn get_data(entry: &P, disc: VpcDiscriminant) -> &P::SidedData {
        if entry.get_east_disc() == disc {
            entry.get_east_data()
        } else if entry.get_west_disc() == disc {
            entry.get_west_data()
        } else {
            // either we did not sanitize input or there is a bug in the
            // VpcPair implementation of the type using this map.
            unreachable!()
        }
    }
    pub fn ordered_get(
        &self,
        east: VpcDiscriminant,
        west: VpcDiscriminant,
    ) -> Option<(&P::SidedData, &P::SidedData)> {
        if let Some(entry) = self.0.get(&(east, west)) {
            Some((Self::get_data(entry, east), Self::get_data(entry, west)))
        } else {
            None
        }
    }
}

enum VpcPairMapChange<P: Clone + VpcPair> {
    Add(P),
    Del(VpcDiscriminant, VpcDiscriminant),
    SetMap(VpcPairMap<P>),
}

impl<T: VpcPair + Clone> Absorb<VpcPairMapChange<T>> for VpcPairMap<T> {
    fn absorb_first(&mut self, change: &mut VpcPairMapChange<T>, _: &Self) {
        match change {
            VpcPairMapChange::Add(entry) => self.add(entry.clone()),
            VpcPairMapChange::Del(east, west) => self.del(*east, *west),
            VpcPairMapChange::SetMap(new_map) => *self = new_map.clone(),
        }
    }
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub struct VpcPairMapWriter<P: VpcPair + Clone>(WriteHandle<VpcPairMap<P>, VpcPairMapChange<P>>);
pub struct VpcPairMapReader<P: VpcPair + Clone>(ReadHandle<VpcPairMap<P>>);

impl<P: VpcPair + Clone> VpcPairMapWriter<P> {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> VpcPairMapWriter<P> {
        let (w, _) = new_from_empty::<VpcPairMap<P>, VpcPairMapChange<P>>(VpcPairMap::new());
        VpcPairMapWriter(w)
    }
    #[must_use]
    pub fn get_reader(&self) -> VpcPairMapReader<P> {
        VpcPairMapReader(self.0.clone())
    }

    /// Add an entry to the `VpcMap`
    pub fn add(&mut self, pair: P, publish: bool) -> VpcMapResult<()> {
        let east = pair.get_east_disc();
        let west = pair.get_west_disc();
        if east == west {
            return Err(VpcMapError::InvalidInput);
        }
        let key1 = (east, west);
        let key2 = (east, west);
        let inner = self.0.raw_write_handle();
        unsafe {
            let inner = inner.as_ref();
            if inner.0.contains_key(&key1) || inner.0.contains_key(&key2) {
                return Err(VpcMapError::PairedEntryExists(east, west));
            }
        }
        self.0.append(VpcPairMapChange::Add(pair));
        if publish {
            self.0.publish();
        }
        Ok(())
    }
    pub fn del(&mut self, east: VpcDiscriminant, west: VpcDiscriminant, publish: bool) {
        self.0.append(VpcPairMapChange::Del(east, west));
        if publish {
            self.0.publish();
        }
    }
    pub fn publish(&mut self) {
        self.0.publish();
    }
}

impl<P: VpcPair + Clone> VpcPairMapReader<P> {
    pub fn enter(&self) -> Option<ReadGuard<'_, VpcPairMap<P>>> {
        self.0.enter()
    }
    // TODO provide an easy api to read
}
