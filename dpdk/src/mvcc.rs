use crate::flow::MacAddr;
use core::fmt::Display;
use left_right::ReadHandle;
use std::cell::Cell;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::num::NonZero;
use std::sync::Arc;

#[repr(transparent)]
#[derive(Debug)]
struct AtomicVersion(core::sync::atomic::AtomicU64);

/// A version of a configured object
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
struct Version(NonZero<u64>);

#[derive(Debug, Clone)]
struct RoutingTable {
    pub id: Id<Self>,
    _whatever: (), // <- impl not relevant for current discussion
}

#[derive(Debug, Clone, Default)]
struct Route {
    _whatever: (), // <- impl not relevant for current discussion
}

struct UpdateSet<'a> {
    _whatever: PhantomData<&'a ()>,
}

impl UpdateSet<'_> {
    fn whatever(_lhs: &RoutingTable, _rhs: &RoutingTable) -> Self {
        todo!()
    }
}

impl<'a> Iterator for UpdateSet<'a> {
    type Item
        = &'a RouteUpdate
    where
        Self: 'a;

    fn next(&mut self) -> Option<&'a RouteUpdate> {
        todo!()
    }
}

#[derive(Debug, Clone)]
enum RouteUpdate {
    Added(Route),
    Removed(Route),
    Updated(Ipv4Addr, Interface),
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
struct Id<T>(pub u32, PhantomData<T>);

#[derive(Debug, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
struct Interface {
    pub id: Id<Self>,
    pub mac: MacAddr,
}

fn biscuit(x: Interface) -> Id<Interface> {
    x.id
}

impl RoutingTable {
    fn new() -> RoutingTable {
        todo!()
    }
    fn add(&mut self, _route: Route) -> &mut RouteUpdate {
        todo!()
    }
    fn remove(&mut self, _route: &Route) -> &mut RouteUpdate {
        todo!()
    }
    fn lookup(&self, _target: Ipv4Addr) -> Option<(Ipv4Addr, Interface)> {
        todo!()
    }
    fn diff(&self, rhs: &RoutingTable) -> impl Iterator<Item = &RouteUpdate> {
        UpdateSet::whatever(self, rhs) // <- impl not relevant for conversation
    }
}

type BroadcastTx<T> = std::sync::mpsc::Sender<T>; // <- TODO: replace with actual broadcast channel
type BroadcastRx<T> = std::sync::mpsc::Receiver<T>; // <- TODO: replace with actual broadcast channel

struct WriteSideHistory<T> {
    working: (Version, Arc<T>),
    ready: (Version, Arc<T>),
    outbound: BroadcastTx<(Version, Arc<T>)>,
}

struct ReadSideHistory<T> {
    incoming: BroadcastRx<(Version, Arc<T>)>,
    tracking: VecDeque<(Version, Arc<T>)>,
}

struct Versioned<T: Clone> {
    current_as_of: Cell<Version>,
    target: Cell<Arc<T>>,
    reader: ReadHandle<Versioned<T>>,
}

trait StateAsOf<T> {
    fn as_of_version(&self, version: Version) -> Option<&T>;
}

// impl<T: Clone> StateAsOf<T> for Versioned<T> {
//     fn as_of_version(&self, version: Version) -> Option<&T> {
//         let current_as_of = self.current_as_of.get();
//         debug_assert!(version < current_as_of, "Time can't go backwards");
//         if version == current_as_of {
//             match self.target.upgrade() {
//                 None => return None,
//                 Some(a) => return Some(a.as_ref()),
//             }
//         }
//         // TODO: search bloom filter
//         let updated = self.reader.enter().map(|x| *x);
//         match updated {
//             None => {
//                 self.target.get_mut(Weak::new());
//                 None
//             }
//             Some(new) => {
//                 self.current_as_of.set(new.current_as_of.get());
//                 self.target.set(new.target.take());
//                 match (&self.target).get_mut().upgrade() {
//                     None => None,
//                     Some(a) => Some(a.as_ref()),
//                 }
//             }
//         }
//     }
// }

// #[derive(Clone)]
// struct VersionedPtr<T>(Arc<Versioned<T>>);

impl Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.get())
    }
}

impl Version {
    /// Create a new counter.
    fn new() -> Self {
        Version(NonZero::<u64>::MIN)
    }

    /// Increment the version.
    ///
    /// # SAFETY:
    ///
    /// Ensure that the version is not equal to [`u64::MAX`].
    ///
    /// It is undefined behavior to overflow the counter.
    /// It is profoundly unrealistic that overflow will ever be an issue in practice.
    #[tracing::instrument(level = "debug")]
    fn inc(&mut self) {
        debug_assert!(self.0.get() < u64::MAX, "Increment called on maxed counter");
        self.0 = self.0.saturating_add(1);
    }
}

trait Operation {}

#[derive(Debug, Hash)]
struct NodeId(u64);

enum Node {}

struct Reference {
    item: NodeId,
    references: NodeId,
}

struct Configuration {
    version: Version,
}

struct Filter;

struct Config {
    version: Version,
    filters: VecDeque<(Version, Filter)>,
}
