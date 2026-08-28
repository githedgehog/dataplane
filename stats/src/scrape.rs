// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use concurrency::sync::{Mutex, MutexGuard};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type Labels = BTreeMap<String, String>;

pub(crate) type SeriesId = (String, Labels);

pub(crate) type Series = BTreeMap<SeriesId, f64>;

pub(crate) type Shape = (String, Vec<String>);

#[derive(Debug, Default, Clone)]
pub(crate) struct Scrape {
    held: Arc<Mutex<Series>>,
    shapes: Arc<Mutex<BTreeSet<Shape>>>,
    registrations: Arc<AtomicUsize>,
}

impl Scrape {
    pub(crate) fn get(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        let labels: Labels = labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        self.held().get(&(name.to_string(), labels)).copied()
    }

    pub(crate) fn label_shapes(&self, name: &str) -> BTreeSet<Vec<String>> {
        self.shapes
            .lock()
            .iter()
            .filter(|(series, _)| series == name)
            .map(|(_, keys)| keys.clone())
            .collect()
    }

    pub(crate) fn registrations(&self) -> usize {
        self.registrations.load(Ordering::Relaxed)
    }

    pub(crate) fn series(&self, name: &str) -> Vec<(Labels, f64)> {
        self.held()
            .iter()
            .filter(|((series, _), _)| series == name)
            .map(|((_, labels), value)| (labels.clone(), *value))
            .collect()
    }

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

    fn register_histogram(
        &self,
        _: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}
