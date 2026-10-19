// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What our neighbours have told us: the remote systems table of IEEE 802.1AB-2016 §9.2.10.
//!
//! Pure bookkeeping, with time passed in, so that the receive task decides when things happen and the
//! table only decides what they mean.

use net::eth::mac::SourceMac;
use net::lldp::{ChassisId, Lldpdu, PortId};
use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

/// One neighbour, as last heard on one of our ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    /// The MAC the neighbour's frames came from.
    pub source: SourceMac,
    /// What the neighbour last advertised.
    pub lldpdu: Lldpdu,
    /// When we first heard it on this port, since it was last forgotten.
    pub first_heard: Instant,
    /// When we last heard it.
    pub last_heard: Instant,
    /// When we forget it unless we hear from it again.
    pub expires: Instant,
}

/// What hearing an LLDPDU did to the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Heard {
    /// A neighbour we did not know.
    New,
    /// A known neighbour, advertising something different.
    Changed,
    /// A known neighbour, saying the same thing again.
    Refreshed,
    /// A neighbour telling us to forget it (time to live 0).
    Withdrawn,
    /// A neighbour we did not know, ignored because the port already has as many as it may hold.
    TooMany,
}

impl Heard {
    /// Whether this changed what the table says, as opposed to only when it expires.
    #[must_use]
    pub fn changed(self) -> bool {
        matches!(self, Heard::New | Heard::Changed | Heard::Withdrawn)
    }
}

/// A neighbour's identity: the chassis and port it advertises (802.1AB's "MSAP identifier").
type Key = (ChassisId, PortId);

/// The neighbours heard on each of our ports, keyed by `P`, whatever names a local port.
#[derive(Debug)]
pub struct Neighbors<P> {
    ports: HashMap<P, HashMap<Key, Neighbor>>,
    max_per_port: NonZeroUsize,
}

impl<P: Eq + Hash + Clone> Neighbors<P> {
    /// A table holding at most `max_per_port` neighbours on any one port.
    ///
    /// A point-to-point link has one neighbour; more is a shared segment or a misbehaving peer, and the
    /// bound keeps either from growing the table without limit. Known neighbours always refresh; a new
    /// one beyond the bound is ignored until an existing one goes.
    #[must_use]
    pub fn new(max_per_port: NonZeroUsize) -> Neighbors<P> {
        Neighbors {
            ports: HashMap::new(),
            max_per_port,
        }
    }

    /// Record that `lldpdu` arrived on `port` from `source` at `now`.
    pub fn hear(&mut self, port: &P, source: SourceMac, lldpdu: Lldpdu, now: Instant) -> Heard {
        let key = (lldpdu.chassis_id().clone(), lldpdu.port_id().clone());
        let ttl = lldpdu.ttl();
        if ttl.is_shutdown() {
            let removed = self
                .ports
                .get_mut(port)
                .and_then(|neighbors| neighbors.remove(&key));
            self.ports.retain(|_, neighbors| !neighbors.is_empty());
            // Forgetting a neighbour we never knew changes nothing.
            return if removed.is_some() {
                Heard::Withdrawn
            } else {
                Heard::Refreshed
            };
        }
        let expires = now + Duration::from_secs(ttl.as_secs().into());
        let neighbors = self.ports.entry(port.clone()).or_default();
        if let Some(known) = neighbors.get_mut(&key) {
            let changed = known.lldpdu != lldpdu || known.source != source;
            known.source = source;
            known.lldpdu = lldpdu;
            known.last_heard = now;
            known.expires = expires;
            return if changed {
                Heard::Changed
            } else {
                Heard::Refreshed
            };
        }
        if neighbors.len() >= self.max_per_port.get() {
            return Heard::TooMany;
        }
        neighbors.insert(
            key,
            Neighbor {
                source,
                lldpdu,
                first_heard: now,
                last_heard: now,
                expires,
            },
        );
        Heard::New
    }

    /// Forget every neighbour whose time to live has run out by `now`, returning how many went.
    pub fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        for neighbors in self.ports.values_mut() {
            let before = neighbors.len();
            neighbors.retain(|_, neighbor| neighbor.expires > now);
            expired += before - neighbors.len();
        }
        self.ports.retain(|_, neighbors| !neighbors.is_empty());
        expired
    }

    /// Forget every neighbour on `port`, as when its link goes down, returning how many went.
    pub fn forget_port(&mut self, port: &P) -> usize {
        self.ports
            .remove(port)
            .map_or(0, |neighbors| neighbors.len())
    }

    /// When the next neighbour expires, if any are known.
    #[must_use]
    pub fn next_expiry(&self) -> Option<Instant> {
        self.ports
            .values()
            .flat_map(HashMap::values)
            .map(|neighbor| neighbor.expires)
            .min()
    }

    /// Every neighbour, with the port it was heard on.
    pub fn iter(&self) -> impl Iterator<Item = (&P, &Neighbor)> {
        self.ports
            .iter()
            .flat_map(|(port, neighbors)| neighbors.values().map(move |neighbor| (port, neighbor)))
    }

    /// How many neighbours are known, on all ports together.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ports.values().map(HashMap::len).sum()
    }

    /// Whether no neighbours are known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{Heard, Neighbors};
    use net::eth::mac::{Mac, SourceMac};
    use net::lldp::{ChassisId, IdOctets, Lldpdu, OptionalTlv, PortId, Text, TimeToLive};
    use std::num::NonZeroUsize;
    use std::time::Duration;

    fn switch() -> SourceMac {
        SourceMac::new(Mac([0x02, 0, 0, 0, 0, 0x10])).unwrap()
    }

    fn lldpdu(chassis: &str, ttl: u16) -> Lldpdu {
        Lldpdu::new(
            ChassisId::LocallyAssigned(IdOctets::new(chassis.as_bytes()).unwrap()),
            PortId::InterfaceName(IdOctets::new(b"Ethernet0").unwrap()),
            TimeToLive::new(ttl),
        )
    }

    fn table() -> Neighbors<&'static str> {
        Neighbors::new(NonZeroUsize::new(2).unwrap())
    }

    #[test]
    fn a_neighbour_lasts_as_long_as_its_time_to_live() {
        let start = clock::now();
        let mut neighbors = table();
        assert_eq!(
            neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 120), start),
            Heard::New
        );
        assert_eq!(
            neighbors.next_expiry(),
            Some(start + Duration::from_secs(120))
        );
        assert_eq!(neighbors.expire(start + Duration::from_secs(119)), 0);
        assert_eq!(neighbors.expire(start + Duration::from_secs(120)), 1);
        assert!(neighbors.is_empty());
    }

    #[test]
    fn hearing_again_extends_the_time_to_live() {
        let start = clock::now();
        let mut neighbors = table();
        neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 120), start);
        let later = start + Duration::from_secs(30);
        assert_eq!(
            neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 120), later),
            Heard::Refreshed
        );
        assert_eq!(neighbors.expire(start + Duration::from_secs(120)), 0);
        let (_, neighbor) = neighbors.iter().next().unwrap();
        assert_eq!((neighbor.first_heard, neighbor.last_heard), (start, later));
    }

    #[test]
    fn news_from_a_neighbour_is_a_change() {
        let start = clock::now();
        let mut neighbors = table();
        neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 120), start);
        let mut renamed = lldpdu("leaf-1", 120);
        renamed
            .try_push(OptionalTlv::SystemName(
                Text::new(b"leaf-1.example").unwrap(),
            ))
            .unwrap();
        assert_eq!(
            neighbors.hear(&"eth1", switch(), renamed, start),
            Heard::Changed
        );
        assert_eq!(neighbors.len(), 1);
    }

    #[test]
    fn a_shutdown_frame_forgets_the_neighbour_at_once() {
        let start = clock::now();
        let mut neighbors = table();
        neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 120), start);
        assert_eq!(
            neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 0), start),
            Heard::Withdrawn
        );
        assert!(neighbors.is_empty());
        // Forgetting a stranger changes nothing.
        assert_eq!(
            neighbors.hear(&"eth1", switch(), lldpdu("leaf-9", 0), start),
            Heard::Refreshed
        );
    }

    #[test]
    fn the_same_neighbour_on_two_ports_is_two_entries() {
        let start = clock::now();
        let mut neighbors = table();
        neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 120), start);
        assert_eq!(
            neighbors.hear(&"eth2", switch(), lldpdu("leaf-1", 120), start),
            Heard::New
        );
        assert_eq!(neighbors.forget_port(&"eth1"), 1);
        assert_eq!(neighbors.len(), 1);
    }

    #[test]
    fn a_port_holds_a_bounded_number_of_neighbours() {
        let start = clock::now();
        let mut neighbors = table();
        neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 120), start);
        neighbors.hear(&"eth1", switch(), lldpdu("leaf-2", 120), start);
        assert_eq!(
            neighbors.hear(&"eth1", switch(), lldpdu("leaf-3", 120), start),
            Heard::TooMany
        );
        // Known neighbours still refresh, and a slot that frees up can be taken.
        assert_eq!(
            neighbors.hear(&"eth1", switch(), lldpdu("leaf-1", 120), start),
            Heard::Refreshed
        );
        neighbors.hear(&"eth1", switch(), lldpdu("leaf-2", 0), start);
        assert_eq!(
            neighbors.hear(&"eth1", switch(), lldpdu("leaf-3", 120), start),
            Heard::New
        );
    }
}
