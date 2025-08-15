// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{MetricDescription, MetricSpec};
use metrics::Level;
use serde::Serialize;
use std::collections::BTreeMap;

pub trait Register<T> {
    fn register(self) -> Registered<T>;
}

#[derive(Debug, Serialize)]
pub struct Registered<T> {
    #[serde(flatten)]
    details: MetricSpec,
    #[serde(skip)]
    pub metric: T,
}

impl Register<metrics::Counter> for MetricSpec {
    fn register(self) -> Registered<metrics::Counter> {
        let k = self.key();
        let m = self.metadata();
        let metric = metrics::with_recorder(|r| {
            r.describe_counter(
                self.id().to_string().into(),
                Some(self.unit()),
                self.description().to_string().into(),
            );
            r.register_counter(&k, &m)
        });
        Registered {
            details: self,
            metric,
        }
    }
}

impl Register<metrics::Gauge> for MetricSpec {
    fn register(self) -> Registered<metrics::Gauge> {
        let k = self.key();
        let m = self.metadata();
        let metric = metrics::with_recorder(|r| {
            r.describe_gauge(
                self.id().to_string().into(),
                Some(self.unit()),
                self.description().to_string().into(),
            );
            r.register_gauge(&k, &m)
        });
        Registered {
            details: self,
            metric,
        }
    }
}

impl Register<metrics::Histogram> for MetricSpec {
    fn register(self) -> Registered<metrics::Histogram> {
        let k = self.key();
        let m = self.metadata();
        let metric = metrics::with_recorder(|r| {
            r.describe_histogram(
                self.id().to_string().into(),
                Some(self.unit()),
                self.description().to_string().into(),
            );
            r.register_histogram(&k, &m)
        });
        Registered {
            details: self,
            metric,
        }
    }
}

impl<T> MetricDescription for Registered<T> {
    fn description(&self) -> &str {
        self.details.description()
    }

    fn id(&self) -> &str {
        self.details.id()
    }

    fn labels(&self) -> &BTreeMap<String, String> {
        self.details.labels()
    }

    fn level(&self) -> Level {
        self.details.level()
    }

    fn target(&self) -> &str {
        self.details.target()
    }

    fn unit(&self) -> metrics::Unit {
        self.details.unit()
    }
}
