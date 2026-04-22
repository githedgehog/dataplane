// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Design scratch.  Not wired into the public API, not feature-gated,
//! compiles alongside the crate so the ideas can evolve under the
//! real trait/import surface.
//!
//! Organized in labelled sections rather than submodules so related
//! thoughts stay readable top-to-bottom.  Move out when a section
//! earns its own module.

#![allow(dead_code)] // scratch
#![allow(missing_docs)] // scratch

use std::{
    collections::HashMap,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    num::{NonZero, NonZeroU32},
    time::Instant,
};

use net::{
    buffer::PacketBufferMut,
    eth::mac::{Mac, SourceMac},
    ipv4::{Ipv4, UnicastIpv4Addr},
    ipv6::UnicastIpv6Addr,
    packet::Packet,
    tcp::TcpPort,
    udp::UdpPort,
    vlan::Vlan,
};

// =========================================================================
// Scratch 1: Decision lattice for Field access
// =========================================================================

#[repr(transparent)]
struct Field<T, D>
where
    D: Decision,
{
    tracked: T,
    level: PhantomData<D>,
}

// `Decision` is the floor of the lattice.  Supertrait chain encodes the
// strict inclusion: Mutating -> Actionable -> Decision.  A function
// generic over `D: Actionable` then accepts both `Actionable` and
// `Mutating` markers by trait inheritance, no runtime matching.
trait Decision {}
trait ActionableRead: Decision {}
trait MutableWrite: ActionableRead {}

// Passive: read for observability only (e.g. hit counters).  May not
// participate in branch conditions, may not be written.
#[repr(transparent)]
#[non_exhaustive]
struct Passive;

// Actionable: may be read and the read value may inform branch
// conditions.  Not writable.  E.g. ttl for "is ttl zero?" decisions.
#[repr(transparent)]
#[non_exhaustive]
struct Actionable;

// Mutating: may be read, branched on, and written.  E.g. src address
// for NAT.
#[repr(transparent)]
#[non_exhaustive]
struct Mutating;

impl Decision for Passive {}

impl Decision for Actionable {}
impl ActionableRead for Actionable {}

impl Decision for Mutating {}
impl ActionableRead for Mutating {}
impl MutableWrite for Mutating {}

// One extra axis we owe ourselves: once a field has been written,
// subsequent reads in the SAME NF traversal must not be branch-eligible.
// The lossless split of the op log into (reads, overlay) depends on this.
// Likely implementation: a writer method consumes the `Field<T, Mutating>`
// by value and returns `Field<T, Passive>` for the rest of the traversal.
// (Or uses a type-state that tracks "has-been-written" in a PhantomData
// axis orthogonal to Decision.)

// =========================================================================
// Scratch 2: Op-log shape (CoW overlay + ordered read trace)
// =========================================================================

// A "builder" / "overlay" / copy-on-write version of `Headers`.
//
// 1. Multiple writes to the same field coalesce in the overlay; we
//    do not append a log entry per intermediate value.
// 2. Bump-allocated `DiffHeaders` packs better in L1d than a `Vec<Op>`
//    over a large enum: optional fields cost only their own bits,
//    Vec pays the largest-variant cost per slot.
// 3. Compile-time Id per Headers element supports a bitset for
//    "was this field touched" queries in O(1).
//
// Pairs with an ordered `Vec<ReadOp>` that records predicates (reads
// classified by `Decision` marker).  Predicate reads are
// order-preserved; write deltas are commutative in final state.
// The Decision lattice above enforces "branch reads precede writes,"
// which is the discipline that makes the split lossless.

// =========================================================================
// Scratch 3: Port/Address + NAT concretions
// =========================================================================

trait Port: Copy + std::hash::Hash + PartialEq + Eq + 'static {}

trait Address: Copy + std::hash::Hash + PartialEq + Eq + 'static {
    type Unicast: Address<Unicast = Self::Unicast> + Into<Self> + AsRef<Self> + TryFrom<Self>;
}

impl Port for TcpPort {}
impl Port for UdpPort {}

impl Address for Ipv4Addr {
    type Unicast = UnicastIpv4Addr;
}

impl Address for UnicastIpv4Addr {
    type Unicast = Self;
}

impl Address for Ipv6Addr {
    type Unicast = UnicastIpv6Addr;
}

impl Address for UnicastIpv6Addr {
    type Unicast = Self;
}

impl Address for Mac {
    type Unicast = SourceMac;
}

impl Address for SourceMac {
    type Unicast = Self;
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct NatTableEntry<Addr, Port> {
    forward: NatMatch<Addr, Port>,
    reverse: NatMatch<Addr, Port>,
    hits: u64,
    established: Instant,
    last_hit: Instant,
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct NatMatch<Addr, Port> {
    addr: Addr,
    port: Port,
}

#[derive(Clone)]
enum NatState<Addr, Port> {
    New(NatMatch<Addr, Port>),
    Established(NatMatch<Addr, Port>),
    Related(NatMatch<Addr, Port>),
    Expected(NatMatch<Addr, Port>),
    Invalid,
}

// =========================================================================
// Scratch 4: The NF-as-Table-DAG framework
// =========================================================================
//
// An NF is a typed DAG of Tables.  The framework sees the DAG at
// construction and can do capability/offload analysis on it directly.
// Packet traversal is a walk over the DAG, executed by the framework.
//
// Key design moves:
//
// * Probe and install are separate operations.  `probe(&self, key)`
//   is pure; `install(&mut self, spec)` is an explicit mutation.
//   The op log records them as distinct events so learned offloads
//   can be synthesized from the probe path alone and learning can
//   be attributed to install sites.
//
// * Tables carry identity.  `TableId` is compile-time stable per NF;
//   `MatchId` identifies the specific entry that fired.  The op log
//   record for a packet is a sequence of (TableId, MatchId, Fate).
//
// * Stateful tables are a supertrait of Table.  Stateless tables
//   (FIB-shaped) cannot accidentally claim mutation; stateful
//   tables (NAT/ARP-shaped) must opt in to `install`/`evict`.
//
// * The NF owns the miss policy.  When `probe` returns None, the NF
//   decides whether to Trap (ship to control plane) or Learn
//   (compute an install spec and install before retrying).
//   Keeps Tables pure; keeps NF-specific decision logic visible.

// -- Identity -------------------------------------------------------------

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
#[repr(transparent)]
struct TableId(NonZero<u32>);

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct MatchId {
    table: TableId,
    local: u32, // Not sure if this should get a wrapper type.
}

// -- Fate: what happens when an entry fires -------------------------------
//
// Closed vocabulary.  Mutations on the packet (DecrementTtl,
// SetSrcAddr, etc.) are NOT in Fate -- they live in the op-log
// overlay side (scratch 2) and are applied by the Field<_,
// MutableWrite> methods invoked during action execution.  Fate
// expresses only control-flow and metadata outcomes.

enum Fate {
    /// Terminate processing, let the packet proceed.
    Accept, // I don't really understand Accept.  Do you mean emit to the wire?  How is this different than Forward?

    /// Terminate processing, drop the packet.
    Drop,

    /// Continue to another table within this NF.
    Jump(TableId), // This makes sense to me as an action, and I love that it is scoped to an NF.
    // that said, I am not sure we can "let this one out" as an abstraction.
    // Unless I fail to understand what you are driving at (entirely  possible),
    // this feels like it would be leaky
    /// Ship to a slower tier (control plane / software fallback).
    Trap,

    /// Hand-off between NFs (deferred detail; NF composition will
    /// add a NfId here or similar).
    Forward,
}

// -- The Table trait ------------------------------------------------------

trait Table {
    type Key<'a>
    where
        Self: 'a;
    type Entry<'a>
    where
        Self: 'a;

    fn id(&self) -> TableId;

    /// Pure lookup.  Returns the entry that fires plus its identity.
    /// Miss is `None`; it is the NF's decision what to do then.
    fn probe<'a>(&'a self, key: Self::Key<'a>) -> Option<(MatchId, Self::Entry<'a>)>;

    /// The control-flow fate associated with a given entry.  For
    /// simple tables this is stored on the entry; for complex ones
    /// it may be a function of entry state.
    fn fate_for<'a>(&self, entry: &Self::Entry<'a>) -> Fate;
}

/// Tables whose entries are created by traffic, not the control
/// plane.  NAT conntrack, ARP, MAC-learning are stateful; a FIB
/// programmed by routing is static (relative to the traffic
/// pattern).
trait DynamicTable: Table {
    type InstallSpec;

    fn install(&mut self, spec: Self::InstallSpec) -> MatchId;

    fn evict(&mut self, id: MatchId);
}

// -- NetworkFunction ------------------------------------------------------

/// An NF declares its table topology and the policy for handling
/// probe misses.  The framework drives the traversal by walking
/// `entry()` and following `Fate::Jump` edges.
trait NetworkFunction {
    /// The first table a packet visits.
    fn entry(&self) -> TableId;

    /// Given a miss on `table` for `key`, decide what to do.
    /// Distinct from probe so the Table trait stays pure.
    fn on_miss(&mut self, table: TableId, /* key view */ ctx: MissCtx<'_>) -> MissAction;
}

/// Abstract handle to whatever the probe tried to match on.
/// Production version will be typed per-table; this is a placeholder.
struct MissCtx<'a> {
    _marker: PhantomData<&'a ()>,
}

enum MissAction {
    /// No entry installed, packet traps.
    Trap,

    /// Install a new entry (the NF has already computed its
    /// install spec) and re-probe.  The concrete spec lives in the
    /// owning Table's `InstallSpec`, keyed by `table`.
    Learn { table: TableId /* spec: ... */ },

    /// No entry installed, packet proceeds with a default fate.
    Default(Fate),
}

// Open question (flagged, not solved): how does the framework walk
// the DAG when tables have different Key/Entry GATs?  A naive
// `fn table(&self, id: TableId) -> &dyn Table<Key<'_> = ?, Entry<'_> = ?>`
// cannot erase GATs.  Options:
//
//   (a) NF holds an enum over its concrete tables; framework
//       dispatches via a match on the enum.  Lose dyn, keep types.
//       Monomorphized per NF.
//
//   (b) Erase to a uniform byte-buffer Key/Entry at the dyn
//       boundary.  Ugly; pushes typing out into a protocol.
//
//   (c) Visitor: framework passes a "driver" to the NF which calls
//       back into the framework as it probes.  NF author writes a
//       match statement stitching its tables together; framework
//       owns the loop around it.  Most ergonomic IMO.
//
// Probably (a) for phase 1, (c) for phase 2 when NF composition
// needs a uniform representation.

// =========================================================================
// Scratch 4b: NAT rebuilt on scratch 4
// =========================================================================

// The pre-framework NAT (scratch 3) had lookup conflate probe+install,
// and the action was an `Option`-ish enum of "use existing" vs "create
// new."  Under the Table-first framework NAT is a single stateful table
// whose miss policy is "Learn or Trap" depending on NF config.

struct NatConntrack<A: Address, P: Port> {
    id: TableId,
    forward: HashMap<NatMatch<A, P>, usize>,
    reverse: HashMap<NatMatch<A, P>, usize>,
    mappings: slab::Slab<NatTableEntry<A, P>>,
}

/// What the NAT install policy must produce: both directions of the
/// mapping, to be placed into the forward and reverse maps.
struct NatInstallSpec<A: Address, P: Port> {
    forward_key: NatMatch<A, P>,
    reverse_key: NatMatch<A, P>,
    entry: NatTableEntry<A, P>,
}

impl<A, P> Table for NatConntrack<A, P>
where
    A: Address,
    P: Port,
{
    type Key<'a>
        = &'a NatMatch<A, P>
    where
        Self: 'a;

    type Entry<'a>
        = &'a NatTableEntry<A, P>
    where
        Self: 'a;

    fn id(&self) -> TableId {
        self.id
    }

    fn probe<'a>(&'a self, key: Self::Key<'a>) -> Option<(MatchId, Self::Entry<'a>)> {
        let slab_idx = *self.forward.get(key)?;
        // `forward` and `mappings` are maintained invariantly together;
        // a key in `forward` implies a live entry in `mappings`.
        let entry = self.mappings.get(slab_idx)?;
        let match_id = MatchId {
            table: self.id,
            local: u32::try_from(slab_idx).unwrap_or(u32::MAX),
        };
        Some((match_id, entry))
    }

    fn fate_for<'a>(&self, _entry: &Self::Entry<'a>) -> Fate {
        // Action side: the entry carries the reverse mapping that will
        // be applied as a set of closed mutations on the packet's
        // Field<T, MutableWrite> wrappers (scratch 1 + scratch 2).
        // The Fate itself is just "continue": the next NF (route) will
        // run after the mutations land.
        Fate::Forward
    }
}

impl<A, P> DynamicTable for NatConntrack<A, P>
where
    A: Address,
    P: Port,
{
    type InstallSpec = NatInstallSpec<A, P>;

    fn install(&mut self, spec: Self::InstallSpec) -> MatchId {
        let slab_idx = self.mappings.insert(spec.entry);
        self.forward.insert(spec.forward_key, slab_idx);
        self.reverse.insert(spec.reverse_key, slab_idx);
        MatchId {
            table: self.id,
            local: u32::try_from(slab_idx).unwrap_or(u32::MAX),
        }
    }

    fn evict(&mut self, id: MatchId) {
        debug_assert_eq!(id.table, self.id);
        let Some(entry) = self.mappings.try_remove(id.local as usize) else {
            return;
        };
        self.forward.remove(&entry.forward);
        self.reverse.remove(&entry.reverse);
    }
}

// The NAT NF ties the conntrack table to a miss policy.  For a
// "stateful outbound NAT" (learn on egress), misses in the forward
// direction trigger Learn; misses in the reverse direction trigger
// Trap (the flow must exist or the reverse packet is out-of-state).
// That direction-sensitive policy lives here, not in the Table.

struct OutboundNatNf<A: Address, P: Port> {
    conntrack: NatConntrack<A, P>,
    // Address/port pool, aging thresholds, etc., live here too.
}

impl<A: Address, P: Port> NetworkFunction for OutboundNatNf<A, P> {
    fn entry(&self) -> TableId {
        self.conntrack.id
    }

    fn on_miss(&mut self, table: TableId, _ctx: MissCtx<'_>) -> MissAction {
        debug_assert_eq!(table, self.conntrack.id);
        // Real impl inspects direction (which context carries), allocates
        // a translation from the pool, assembles a NatInstallSpec, and
        // returns MissAction::Learn.  For reverse-direction misses:
        // MissAction::Trap.
        MissAction::Trap
    }
}


