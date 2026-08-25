// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A [`metrics::Recorder`] that remembers what was exported, so a test can assert on the series an
//! operator actually scrapes.
//!
//! Nothing in the suite installed a recorder before this, which meant every `gauge.set()` in
//! `stats` -- every number that reaches a dashboard -- went to the no-op recorder and was
//! unobserved. Tests could assert what [`crate::VpcStatsStore`] held, but the store is the input
//! to the export, not the export: the metric *name*, the label set, and the lifetime of a series
//! are all decided between the two, and none of that was covered.
//!
//! Install it per test with [`metrics::set_default_local_recorder`], which is thread-local and so
//! needs no global mutation and no serialisation between tests. The collector must then be driven
//! on that same thread -- `clock.block_on(..)` on a paused clock does exactly that.

use std::collections::{BTreeMap, BTreeSet};
use concurrency::sync::{Mutex, MutexGuard};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The label set of one series, as a scraper would see it.
pub(crate) type Labels = BTreeMap<String, String>;

/// A series: its metric name and its labels.
pub(crate) type SeriesId = (String, Labels);

/// Everything exported so far, and its current value.
pub(crate) type Series = BTreeMap<SeriesId, f64>;

/// A metric name and the label keys one of its series was registered with, in order.
pub(crate) type Shape = (String, Vec<String>);

/// A recorder that keeps the current value of every gauge registered through it.
///
/// Counters and histograms are not kept: `stats` exports its counts as gauges, so there is nothing
/// yet for them to observe.
#[derive(Debug, Default, Clone)]
pub(crate) struct Scrape {
    /// Every series' current value.
    held: Arc<Mutex<Series>>,
    /// The label keys of every series as they were *registered*, in order and with repeats. The
    /// value map cannot show these: it is keyed by a `BTreeMap`, which silently merges a label key
    /// that appears twice.
    shapes: Arc<Mutex<BTreeSet<Shape>>>,
    /// Every call to `register_gauge`, including the re-registrations of a series that already
    /// exists. Distinct from the number of series: the collector re-registers what it already has,
    /// and how often it does that is the cost being watched.
    registrations: Arc<AtomicUsize>,
}

impl Scrape {
    /// The current value of one series, or `None` if it was never registered.
    pub(crate) fn get(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        let labels: Labels = labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        self.held().get(&(name.to_string(), labels)).copied()
    }

    /// The label keys of every series registered under `name`, in registration order, with
    /// repeats kept.
    pub(crate) fn label_shapes(&self, name: &str) -> BTreeSet<Vec<String>> {
        self.shapes
            .lock()
            .iter()
            .filter(|(series, _)| series == name)
            .map(|(_, keys)| keys.clone())
            .collect()
    }

    /// How many times a gauge has been registered, counting repeats.
    pub(crate) fn registrations(&self) -> usize {
        self.registrations.load(Ordering::Relaxed)
    }

    /// Every series exported under `name`, with its labels and current value.
    pub(crate) fn series(&self, name: &str) -> Vec<(Labels, f64)> {
        self.held()
            .iter()
            .filter(|((series, _), _)| series == name)
            .map(|((_, labels), value)| (labels.clone(), *value))
            .collect()
    }

    /// Every series whose value is not zero, formatted one per line and sorted, for a failure
    /// message that says what *was* exported rather than only what was expected.
    pub(crate) fn nonzero(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .held()
            .iter()
            .filter(|&(_, &v)| v != 0.0)
            .map(|((name, labels), value)| {
                let labels: Vec<String> =
                    labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
                format!("{name}{{{}}} = {value}", labels.join(","))
            })
            .collect();
        out.sort();
        out
    }

    fn held(&self) -> MutexGuard<'_, Series> {
        self.held.lock()
    }
}

/// One series' storage, handed out as the [`metrics::Gauge`] the caller writes through.
#[derive(Debug)]
struct Cell {
    at: SeriesId,
    into: Arc<Mutex<Series>>,
}

impl Cell {
    fn with(&self, f: impl FnOnce(&mut f64)) {
        let mut held = self.into.lock();
        f(held.entry(self.at.clone()).or_insert(0.0));
    }
}

impl metrics::GaugeFn for Cell {
    fn increment(&self, value: f64) {
        self.with(|held| *held += value);
    }

    fn decrement(&self, value: f64) {
        self.with(|held| *held -= value);
    }

    fn set(&self, value: f64) {
        self.with(|held| *held = value);
    }
}

impl metrics::Recorder for Scrape {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn register_counter(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        metrics::Counter::noop()
    }

    fn register_gauge(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        let labels = key
            .labels()
            .map(|label| (label.key().to_string(), label.value().to_string()))
            .collect();
        let at = (key.name().to_string(), labels);
        // Registering a series that already exists must not disturb its value: the collector
        // re-registers on every update, and a scrape between two updates has to see the last value
        // set rather than a zero.
        self.registrations.fetch_add(1, Ordering::Relaxed);
        self.shapes.lock().insert((
            key.name().to_string(),
            key.labels().map(|label| label.key().to_string()).collect(),
        ));
        self.held().entry(at.clone()).or_insert(0.0);
        metrics::Gauge::from_arc(Arc::new(Cell {
            at,
            into: self.held.clone(),
        }))
    }

    fn register_histogram(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}
