// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The rules a rate limiter enforces, and how they reach the workers.

use crate::classify::VpcDestination;
use crate::counts::Counts;
use acl::table::Backend;
use concurrency::slot::Slot;
use concurrency::sync::{Arc, Mutex};
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::ratelimit::{ColorAction, ColorActions, ValidatedRateLimits};
use policer::{Color, Profile, SharedMeter};
use std::num::NonZeroUsize;
use std::time::Instant;

/// What a table's meters count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// A packet costs one token per byte of IP packet.
    Bytes,
    /// A packet costs one token.
    Packets,
}

impl Unit {
    /// What a packet of `bytes` bytes costs.
    pub(crate) fn cost(self, bytes: u32) -> u64 {
        match self {
            Unit::Bytes => u64::from(bytes),
            Unit::Packets => 1,
        }
    }
}

/// What of a rule outlives a configuration: its meter, and what it has counted.
#[derive(Debug)]
pub(crate) struct Enforcement {
    profile: Profile,
    pub(crate) meter: SharedMeter,
    /// One per worker that has used the rule.
    counts: Mutex<Vec<Arc<Counts>>>,
}

impl Enforcement {
    fn new(profile: Profile, workers: NonZeroUsize, now: Instant) -> Enforcement {
        Enforcement {
            profile,
            meter: SharedMeter::new(profile, workers, now),
            counts: Mutex::new(Vec::new()),
        }
    }

    /// New counts for a worker to keep.
    pub(crate) fn counter(&self) -> Arc<Counts> {
        let counts = Arc::new(Counts::default());
        self.counts.lock().push(Arc::clone(&counts));
        counts
    }

    /// Packets and bytes counted as `color`, by every worker.
    fn total(&self, color: Color) -> (u64, u64) {
        self.counts
            .lock()
            .iter()
            .map(|counts| counts.get(color))
            .fold((0, 0), |(p, b), (packets, bytes)| (p + packets, b + bytes))
    }
}

/// One rule: what it is called, what it matches, its profile, and what each color does.
#[derive(Debug)]
pub struct Rule {
    name: String,
    matches: String,
    actions: ColorActions,
    pub(crate) enforcement: Arc<Enforcement>,
}

impl Rule {
    /// The rule's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What the rule matches, for people.
    #[must_use]
    pub fn matches(&self) -> &str {
        &self.matches
    }

    /// The rule's rates and bursts, in its table's unit.
    #[must_use]
    pub fn profile(&self) -> Profile {
        self.enforcement.profile
    }

    /// What happens to a packet of `color`.
    #[must_use]
    pub fn action(&self, color: Color) -> ColorAction {
        match color {
            Color::Green => self.actions.green,
            Color::Yellow => self.actions.yellow,
            Color::Red => self.actions.red,
        }
    }

    /// Packets and bytes the rule has colored `color`.
    #[must_use]
    pub fn counted(&self, color: Color) -> (u64, u64) {
        self.enforcement.total(color)
    }
}

/// One table of rules, all counting in one unit, and the classifier that picks one for a packet.
#[derive(Debug)]
pub struct RuleTable<C> {
    unit: Unit,
    pub(crate) classifier: C,
    pub(crate) rules: Box<[Rule]>,
}

impl<C> RuleTable<C> {
    /// What the table's meters count.
    #[must_use]
    pub fn unit(&self) -> Unit {
        self.unit
    }

    /// The rules, in the order the classifier indexes them.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// What enforced a rule called `name` with `profile`, if one did: a rule keeps its meter and
    /// counts across configurations unless its profile changes.
    fn enforcement(&self, name: &str, profile: Profile) -> Option<Arc<Enforcement>> {
        self.rules
            .iter()
            .find(|rule| rule.name == name && rule.enforcement.profile == profile)
            .map(|rule| Arc::clone(&rule.enforcement))
    }
}

impl RuleTable<VpcDestination> {
    fn empty(unit: Unit) -> Self {
        RuleTable {
            unit,
            classifier: VpcDestination::empty(),
            rules: Box::new([]),
        }
    }

    /// The rules `limits` configures, keeping the meters and counts of any rule `previous` already
    /// enforces.
    fn build(
        limits: &ValidatedRateLimits,
        previous: &RuleTable<VpcDestination>,
        workers: NonZeroUsize,
        now: Instant,
        backend: Backend,
    ) -> Result<Self, ConfigError> {
        let keys: Vec<_> = limits
            .iter()
            .map(|limit| (limit.vni(), limit.destination()))
            .collect();
        let rules = limits
            .iter()
            .map(|limit| Rule {
                name: limit.name().to_string(),
                matches: format!(
                    "from {} (vni {}) to {}",
                    limit.vpc(),
                    limit.vni().as_u32(),
                    limit.destination()
                ),
                actions: limit.actions(),
                enforcement: previous
                    .enforcement(limit.name(), limit.profile())
                    .unwrap_or_else(|| Arc::new(Enforcement::new(limit.profile(), workers, now))),
            })
            .collect();
        Ok(RuleTable {
            unit: previous.unit,
            classifier: VpcDestination::new(&keys, backend)?,
            rules,
        })
    }
}

/// Every rule a rate limiter enforces: the byte table, and the packet table after it.
#[derive(Debug)]
pub struct RateLimits<C> {
    pub(crate) bytes: RuleTable<C>,
    pub(crate) packets: RuleTable<C>,
}

impl<C> RateLimits<C> {
    /// The byte limits.
    #[must_use]
    pub fn bytes(&self) -> &RuleTable<C> {
        &self.bytes
    }

    /// The packet limits.
    #[must_use]
    pub fn packets(&self) -> &RuleTable<C> {
        &self.packets
    }

    /// Both tables, in the order a packet meets them.
    #[must_use]
    pub fn tables(&self) -> [&RuleTable<C>; 2] {
        [&self.bytes, &self.packets]
    }
}

impl RateLimits<VpcDestination> {
    /// No rules at all.
    #[must_use]
    pub fn empty() -> Self {
        RateLimits {
            bytes: RuleTable::empty(Unit::Bytes),
            packets: RuleTable::empty(Unit::Packets),
        }
    }

    /// The rate limits `overlay` configures, keeping the meters and counts of any rule `previous`
    /// already enforces in the same table.
    ///
    /// # Errors
    ///
    /// Fails if a classifier cannot be built.
    pub fn build(
        overlay: &ValidatedOverlay,
        previous: &RateLimits<VpcDestination>,
        workers: NonZeroUsize,
        now: Instant,
        backend: Backend,
    ) -> Result<Self, ConfigError> {
        let limits = overlay.rate_limits();
        Ok(RateLimits {
            bytes: RuleTable::build(limits.bytes(), &previous.bytes, workers, now, backend)?,
            packets: RuleTable::build(limits.packets(), &previous.packets, workers, now, backend)?,
        })
    }
}

/// Publishes [`RateLimits`] to the workers.
#[derive(Debug)]
pub struct RateLimitWriter<C> {
    slot: Arc<Slot<RateLimits<C>>>,
    workers: NonZeroUsize,
}

impl<C> Clone for RateLimitWriter<C> {
    fn clone(&self) -> Self {
        RateLimitWriter {
            slot: Arc::clone(&self.slot),
            workers: self.workers,
        }
    }
}

impl<C> RateLimitWriter<C> {
    /// A writer publishing `initial` to `workers` workers.
    #[must_use]
    pub fn new(initial: RateLimits<C>, workers: NonZeroUsize) -> Self {
        RateLimitWriter {
            slot: Arc::new(Slot::from_pointee(initial)),
            workers,
        }
    }

    /// Publish `limits`.
    pub fn store(&self, limits: RateLimits<C>) {
        self.slot.store(Arc::new(limits));
    }

    /// What the workers enforce now.
    #[must_use]
    pub fn load(&self) -> Arc<RateLimits<C>> {
        self.slot.load_full()
    }

    /// A reader of what this writer publishes.
    #[must_use]
    pub fn reader(&self) -> RateLimitReader<C> {
        RateLimitReader(Arc::clone(&self.slot))
    }
}

impl RateLimitWriter<VpcDestination> {
    /// Enforce the rate limits `overlay` configures, using `backend`'s classifier.
    ///
    /// # Errors
    ///
    /// Fails, enforcing what it did before, if the classifier cannot be built.
    pub fn apply(&self, overlay: &ValidatedOverlay, backend: Backend) -> Result<(), ConfigError> {
        let current = self.load();
        let next = RateLimits::build(overlay, &current, self.workers, clock::now(), backend)?;
        self.store(next);
        Ok(())
    }
}

/// Reads the [`RateLimits`] a [`RateLimitWriter`] publishes.
#[derive(Debug)]
pub struct RateLimitReader<C>(Arc<Slot<RateLimits<C>>>);

impl<C> Clone for RateLimitReader<C> {
    fn clone(&self) -> Self {
        RateLimitReader(Arc::clone(&self.0))
    }
}

impl<C> RateLimitReader<C> {
    /// What the workers enforce now.
    #[must_use]
    pub fn load(&self) -> Arc<RateLimits<C>> {
        self.0.load_full()
    }
}
