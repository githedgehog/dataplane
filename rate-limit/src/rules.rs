// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared named meters and configuration publication.

use crate::classify::{Classify, PeeringRules};
use crate::counts::Counts;
use crate::drops::Drops;
use crate::ingress::IngressRules;
use acl::table::Backend;
use concurrency::slot::Slot;
use concurrency::sync::{Arc, Mutex};
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::ingress::IngressAction;
use config::external::overlay::ratelimit::Meter as ConfigMeter;
use config::external::overlay::ratelimit::{ColorAction, ColorActions};
use net::vxlan::Vni;
use policer::{Color, Profile, SharedMeter};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::time::Instant;

/// The tokens consumed by a meter component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// One token per byte of IP packet, and of anything the frame carries after it.
    Bytes,
    /// One token per packet.
    Packets,
}
impl Unit {
    pub(crate) const ALL: [Self; 2] = [Self::Bytes, Self::Packets];
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Bytes => 0,
            Self::Packets => 1,
        }
    }
    pub(crate) fn cost(self, bytes: u32) -> u64 {
        match self {
            Self::Bytes => u64::from(bytes),
            Self::Packets => 1,
        }
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Bytes => "bits",
            Self::Packets => "pkts",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Enforcement {
    profile: Profile,
    pub(crate) meter: SharedMeter,
    counts: Arc<Mutex<MeterCounts>>,
}
impl Enforcement {
    fn new(profile: Profile, workers: NonZeroUsize, now: Instant, previous: Option<&Self>) -> Self {
        Self {
            profile,
            meter: SharedMeter::new(profile, workers, now),
            counts: previous.map_or_else(
                || Arc::new(Mutex::new(MeterCounts::default())),
                |p| Arc::clone(&p.counts),
            ),
        }
    }
    pub(crate) fn shares_counts(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.counts, &other.counts)
    }
    pub(crate) fn counter(&self) -> Arc<Counts> {
        let counts = Arc::new(Counts::default());
        self.counts.lock().workers.push(Arc::clone(&counts));
        counts
    }
    fn total(&self, color: Color) -> (u64, u64) {
        self.counts.lock().total(color)
    }
}

#[derive(Debug, Default)]
struct MeterCounts {
    workers: Vec<Arc<Counts>>,
    exported: [(u64, u64); 3],
}
impl MeterCounts {
    fn total(&self, color: Color) -> (u64, u64) {
        self.workers
            .iter()
            .map(|c| c.get(color))
            .fold((0, 0), |(p, b), (packets, bytes)| (p + packets, b + bytes))
    }
}

/// One bandwidth or packet-rate component of a named meter.
#[derive(Debug)]
pub struct Component {
    actions: ColorActions,
    pub(crate) enforcement: Arc<Enforcement>,
}
impl Component {
    /// Rates and bursts in this component's token unit.
    #[must_use]
    pub fn profile(&self) -> Profile {
        self.enforcement.profile
    }
    /// How far the workers' leases may let a burst exceed each bucket, committed then excess.
    #[must_use]
    pub fn lease_slack(&self) -> [u64; 2] {
        self.enforcement.meter.lease_slack()
    }
    /// Action for a policing result.
    #[must_use]
    pub fn action(&self, color: Color) -> ColorAction {
        match color {
            Color::Green => self.actions.green,
            Color::Yellow => self.actions.yellow,
            Color::Red => self.actions.red,
        }
    }
    /// Cumulative packets and bytes across all workers and rules using this meter.
    #[must_use]
    pub fn counted(&self, color: Color) -> (u64, u64) {
        self.enforcement.total(color)
    }
}

/// One named meter shared by every rule that references it.
#[derive(Debug)]
pub struct Meter {
    name: String,
    pub(crate) components: [Option<Component>; 2],
}
impl Meter {
    /// The peering-scoped meter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The bandwidth or packet-rate component, if configured.
    #[must_use]
    pub fn component(&self, unit: Unit) -> Option<&Component> {
        self.components[unit.index()].as_ref()
    }
}

/// What a rule does with the packets it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Charge the meter at this position in [`RateLimits::meters`], and act on its color.
    Police(usize),
    /// Drop them.
    Drop,
}

/// One ordered match, policing or dropping what it matches.
#[derive(Debug)]
pub struct Rule {
    pub(crate) action: Action,
    /// The source VPC it matches, if just one: what its drops are counted under.
    pub(crate) from: Option<Vni>,
    matches: String,
}
impl Rule {
    /// What it does.
    #[must_use]
    pub fn action(&self) -> Action {
        self.action
    }
    /// The charged meter's position in [`RateLimits::meters`], if it polices.
    #[must_use]
    pub fn meter(&self) -> Option<usize> {
        match self.action {
            Action::Police(meter) => Some(meter),
            Action::Drop => None,
        }
    }
    /// The validated match, for inspection.
    #[must_use]
    pub fn matches(&self) -> &str {
        &self.matches
    }
}

/// The classifier, ordered rules, and shared named meters for a configuration.
#[derive(Debug)]
pub struct RateLimits<C> {
    pub(crate) classifier: C,
    pub(crate) rules: Box<[Rule]>,
    pub(crate) meters: Box<[Meter]>,
    pub(crate) attempt_offloads: bool,
    /// What drop rules dropped, carried from one configuration to the next.
    pub(crate) drops: Arc<Drops>,
}
impl<C> RateLimits<C> {
    /// Whether a capable NIC should enforce what it can of the gateway's policy in front of
    /// software: unless the gateway turned offload off. Published with the rate limits, so NIC
    /// offload sees it together with the rules it applies to.
    #[must_use]
    pub fn attempt_offloads(&self) -> bool {
        self.attempt_offloads
    }
    /// Named meters, including those not currently referenced by a rule.
    #[must_use]
    pub fn meters(&self) -> &[Meter] {
        &self.meters
    }
    /// The classifier selecting rules, which keeps the typed rules it was built from.
    #[must_use]
    pub fn classifier(&self) -> &C {
        &self.classifier
    }
    /// Rules in match order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Packets drop rules dropped, by source VPC, since the process started.
    #[must_use]
    pub fn dropped(&self) -> std::collections::BTreeMap<net::vxlan::Vni, u64> {
        self.drops.totals()
    }
}

/// A configured rule, as [`Policy::rules`] gives it.
#[derive(Debug, Clone, Copy)]
pub struct Configured<'a> {
    /// The name of the meter it charges, or `None` to drop.
    pub meter: Option<&'a str>,
    /// The source VPC it matches, if just one.
    pub from: Option<Vni>,
    /// Its description, for inspection.
    pub description: &'a str,
}

/// What a [`RateLimits`] is built from: the part of a validated configuration it enforces, and
/// a classifier for its rules.
pub trait Policy: Classify + Sized {
    /// Which policy, as the `policy` label of its metrics: meter names are only unique within one.
    const LABEL: &'static str;
    /// A classifier matching no traffic.
    fn empty() -> Self;
    /// Its meters, by name, and its rules in match order.
    fn rules(overlay: &ValidatedOverlay) -> (&BTreeMap<String, ConfigMeter>, Vec<Configured<'_>>);
    /// The classifier of those rules.
    ///
    /// # Errors
    ///
    /// Returns classifier construction errors.
    fn new(overlay: &ValidatedOverlay, backend: Backend) -> Result<Self, ConfigError>;
}

impl Policy for PeeringRules {
    const LABEL: &'static str = "peering";
    fn empty() -> Self {
        PeeringRules::empty()
    }
    fn rules(overlay: &ValidatedOverlay) -> (&BTreeMap<String, ConfigMeter>, Vec<Configured<'_>>) {
        let config = overlay.rate_limits();
        let rules = config
            .rules
            .iter()
            .map(|r| Configured {
                meter: Some(r.meter.as_str()),
                from: Some(r.from),
                description: r.description.as_str(),
            })
            .collect();
        (&config.meters, rules)
    }
    fn new(overlay: &ValidatedOverlay, backend: Backend) -> Result<Self, ConfigError> {
        PeeringRules::new(&overlay.rate_limits().rules, backend)
    }
}

impl Policy for IngressRules {
    const LABEL: &'static str = "ingress";
    fn empty() -> Self {
        IngressRules::empty()
    }
    fn rules(overlay: &ValidatedOverlay) -> (&BTreeMap<String, ConfigMeter>, Vec<Configured<'_>>) {
        let config = overlay.ingress();
        let rules = config
            .rules
            .iter()
            .map(|r| {
                let meter = match &r.action {
                    IngressAction::Drop => None,
                    IngressAction::Police(meter) => Some(meter.as_str()),
                };
                Configured {
                    meter,
                    from: Some(r.from),
                    description: r.description.as_str(),
                }
            })
            .collect();
        (&config.meters, rules)
    }
    fn new(overlay: &ValidatedOverlay, backend: Backend) -> Result<Self, ConfigError> {
        IngressRules::new(&overlay.ingress().rules, backend)
    }
}

impl<C: Policy> RateLimits<C> {
    /// Publish cumulative meter and drop counters to the installed metrics recorder.
    pub fn publish_metrics(&self) {
        self.drops.publish_metrics();
        metrics::describe_counter!(
            "rate_limit_packets_total",
            metrics::Unit::Count,
            "Packets metered across all rules and workers"
        );
        metrics::describe_counter!(
            "rate_limit_bytes_total",
            metrics::Unit::Bytes,
            "IP bytes, with any trailer forwarded after them, metered across all rules and workers"
        );
        for meter in &self.meters {
            for unit in Unit::ALL {
                let Some(component) = meter.component(unit) else {
                    continue;
                };
                let mut counts = component.enforcement.counts.lock();
                for (i, (result, color)) in [
                    ("conforming", Color::Green),
                    ("excess", Color::Yellow),
                    ("over_limit", Color::Red),
                ]
                .into_iter()
                .enumerate()
                {
                    let (packets, bytes) = counts.total(color);
                    let (old_packets, old_bytes) = counts.exported[i];
                    metrics::counter!("rate_limit_packets_total", "policy" => C::LABEL, "meter" => meter.name.clone(), "unit" => unit.label(), "result" => result).increment(packets - old_packets);
                    metrics::counter!("rate_limit_bytes_total", "policy" => C::LABEL, "meter" => meter.name.clone(), "unit" => unit.label(), "result" => result).increment(bytes - old_bytes);
                    counts.exported[i] = (packets, bytes);
                }
            }
        }
    }

    /// No configured meters or rules.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            classifier: C::empty(),
            rules: Box::new([]),
            meters: Box::new([]),
            attempt_offloads: true,
            drops: Arc::new(Drops::default()),
        }
    }

    /// Build a new configuration, retaining leases for unchanged profiles and cumulative counters
    /// for existing meter names.
    ///
    /// # Errors
    ///
    /// Returns classifier construction errors.
    pub fn build(
        overlay: &ValidatedOverlay,
        previous: &Self,
        workers: NonZeroUsize,
        now: Instant,
        backend: Backend,
    ) -> Result<Self, ConfigError> {
        let (config_meters, config_rules) = C::rules(overlay);
        let (meters, indices) = meters(config_meters, &previous.meters, workers, now);
        let rules = config_rules
            .into_iter()
            .map(
                |Configured {
                     meter,
                     from,
                     description,
                 }| {
                    let action = match meter {
                        None => Action::Drop,
                        Some(name) => {
                            Action::Police(indices.get(name).copied().ok_or_else(|| {
                                ConfigError::InvalidRateLimit(format!("unknown meter {name}"))
                            })?)
                        }
                    };
                    Ok(Rule {
                        action,
                        from,
                        matches: description.to_string(),
                    })
                },
            )
            .collect::<Result<_, ConfigError>>()?;
        Ok(Self {
            classifier: C::new(overlay, backend)?,
            rules,
            meters,
            attempt_offloads: !overlay.offloads_disabled(),
            drops: Arc::clone(&previous.drops),
        })
    }
}
/// meters that carry over from `previous`, and the position of each, by name.
fn meters<'a>(
    config_meters: &'a BTreeMap<String, ConfigMeter>,
    previous: &[Meter],
    workers: NonZeroUsize,
    now: Instant,
) -> (Box<[Meter]>, BTreeMap<&'a str, usize>) {
    let mut indices = BTreeMap::new();
    let meters = config_meters
        .iter()
        .enumerate()
        .map(|(index, (name, meter))| {
            indices.insert(name.as_str(), index);
            let previous = previous.iter().find(|m| m.name == *name);
            let components = [meter.bytes, meter.packets];
            let components = std::array::from_fn(|i| {
                components[i].map(|c| {
                    let old = previous.and_then(|m| m.components[i].as_ref());
                    let enforcement = match old {
                        Some(old) if old.profile() == c.profile => Arc::clone(&old.enforcement),
                        _ => Arc::new(Enforcement::new(
                            c.profile,
                            workers,
                            now,
                            old.map(|c| c.enforcement.as_ref()),
                        )),
                    };
                    Component {
                        actions: c.actions,
                        enforcement,
                    }
                })
            });
            Meter {
                name: name.clone(),
                components,
            }
        })
        .collect();
    (meters, indices)
}

/// Publishes rate-limit configurations to workers.
#[derive(Debug)]
pub struct RateLimitWriter<C> {
    slot: Arc<Slot<RateLimits<C>>>,
    workers: NonZeroUsize,
}
impl<C> Clone for RateLimitWriter<C> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
            workers: self.workers,
        }
    }
}
impl<C> RateLimitWriter<C> {
    /// Publish `initial` to `workers` workers.
    #[must_use]
    pub fn new(initial: RateLimits<C>, workers: NonZeroUsize) -> Self {
        Self {
            slot: Arc::new(Slot::from_pointee(initial)),
            workers,
        }
    }
    /// Replace the current configuration.
    pub fn store(&self, limits: RateLimits<C>) {
        self.slot.store(Arc::new(limits));
    }
    /// Current configuration.
    #[must_use]
    pub fn load(&self) -> Arc<RateLimits<C>> {
        self.slot.load_full()
    }
    /// A reader for workers and observers.
    #[must_use]
    pub fn reader(&self) -> RateLimitReader<C> {
        RateLimitReader(Arc::clone(&self.slot))
    }
}
impl<C: Policy> RateLimitWriter<C> {
    /// Build and publish a validated configuration.
    ///
    /// # Errors
    ///
    /// Retains the current configuration if classifier construction fails.
    pub fn apply(&self, overlay: &ValidatedOverlay, backend: Backend) -> Result<(), ConfigError> {
        let next = RateLimits::build(overlay, &self.load(), self.workers, clock::now(), backend)?;
        self.store(next);
        Ok(())
    }
}

/// Reads the configuration shared with workers.
#[derive(Debug)]
pub struct RateLimitReader<C>(Arc<Slot<RateLimits<C>>>);
impl<C> Clone for RateLimitReader<C> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
impl<C> RateLimitReader<C> {
    /// Current configuration.
    #[must_use]
    pub fn load(&self) -> Arc<RateLimits<C>> {
        self.0.load_full()
    }
}
