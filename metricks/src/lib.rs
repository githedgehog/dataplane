// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements a packet stats sink.
//! Currently, it only includes `PacketDropStats`, but another type of statistics could
//! be added like protocol breakdowns.

use derive_builder::Builder;
use metrics::{Level, Unit};
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
#[allow(unused)]
use tracing::{error, trace, warn};
use vpcmap::VpcDiscriminant;

pub trait Description {
    fn action(&self) -> &str;
    fn description(&self) -> &str;
    fn id(&self) -> &str;
    fn labels(&self) -> &BTreeMap<String, String>;
    fn level(&self) -> Level;
    fn target(&self) -> &str;
    fn unit(&self) -> metrics::Unit;
    fn module_path(&self) -> Option<&str> {
        None
    }
}

mod serdefix {
    use metrics::Level;
    use serde::Deserialize;

    pub(super) fn deserialize_level<'de, D>(deserializer: D) -> Result<Level, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match Level::try_from(s.as_str()) {
            Ok(l) => Ok(l),
            Err(e) => Err(serde::de::Error::custom(e)),
        }
    }

    const fn level_to_string(level: &Level) -> &'static str {
        match *level {
            Level::ERROR => "error",
            Level::WARN => "warn",
            Level::INFO => "info",
            Level::DEBUG => "debug",
            Level::TRACE => "trace",
        }
    }

    pub(super) fn serialize_level<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(level_to_string(level))
    }

    fn parse_unit(s: &str) -> Result<metrics::Unit, String> {
        Ok(match s {
            "count" => metrics::Unit::Count,
            "percent" => metrics::Unit::CountPerSecond,
            "seconds" => metrics::Unit::CountPerSecond,
            "milliseconds" => metrics::Unit::CountPerSecond,
            "microseconds" => metrics::Unit::CountPerSecond,
            "nanoseconds" => metrics::Unit::CountPerSecond,
            "tebibytes" => metrics::Unit::CountPerSecond,
            "gibibytes" => metrics::Unit::CountPerSecond,
            "mebibytes" => metrics::Unit::CountPerSecond,
            "kibibytes" => metrics::Unit::CountPerSecond,
            "bytes" => metrics::Unit::CountPerSecond,
            "terabits_per_second" => metrics::Unit::CountPerSecond,
            "gigabits_per_second" => metrics::Unit::CountPerSecond,
            "megabits_per_second" => metrics::Unit::CountPerSecond,
            "kilobits_per_second" => metrics::Unit::CountPerSecond,
            "bits_per_second" => metrics::Unit::CountPerSecond,
            "count_per_second" => metrics::Unit::CountPerSecond,
            s => Err(format!("Unknown unit: {s}"))?,
        })
    }

    pub(super) fn deserialize_unit<'de, D>(deserializer: D) -> Result<metrics::Unit, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_unit(&s).map_err(serde::de::Error::custom)
    }

    pub(super) fn serialize_unit<S>(unit: &metrics::Unit, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(unit.as_str())
    }

    pub(super) const fn default_level() -> Level {
        Level::INFO
    }

    pub(super) fn empty_string() -> String {
        "".to_string()
    }
}

#[derive(Serialize, Deserialize, Builder, Debug, Clone, MultiIndexMap)]
#[builder(name = "MetricBuilder")]
pub struct MetricSpec {
    #[builder(setter(into))]
    #[multi_index(ordered_unique)]
    id: String,
    #[builder(setter(into))]
    #[serde(
        deserialize_with = "serdefix::deserialize_unit",
        serialize_with = "serdefix::serialize_unit"
    )]
    unit: metrics::Unit,
    #[builder(setter(into), default = "Level::INFO")]
    #[serde(
        deserialize_with = "serdefix::deserialize_level",
        serialize_with = "serdefix::serialize_level",
        default = "serdefix::default_level"
    )]
    level: Level,
    #[builder(setter(into))]
    #[serde(
        skip_serializing_if = "String::is_empty",
        default = "serdefix::empty_string"
    )]
    #[multi_index(ordered_non_unique)]
    action: String,
    #[builder(setter(into))]
    #[serde(
        skip_serializing_if = "String::is_empty",
        default = "serdefix::empty_string"
    )]
    #[multi_index(ordered_non_unique)]
    target: String,
    #[builder(setter(into))]
    #[serde(
        skip_serializing_if = "String::is_empty",
        default = "serdefix::empty_string"
    )]
    description: String,
    #[builder(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
}

#[derive(Debug)]
struct CountAndRate {
    pub count: Registered<metrics::Counter>,
    pub rate: Registered<metrics::Gauge>,
}

#[derive(Debug)]
struct PacketAndBytes {
    pub packet: CountAndRate,
    pub bytes: CountAndRate,
}

#[derive(Debug)]
struct ProcessingMetrics {
    pub forward: PacketAndBytes,
    pub drop: PacketAndBytes,
}

#[derive(Debug, MultiIndexMap)]
#[multi_index_derive(Debug)]
struct VpcMetrics {
    #[multi_index(hashed_unique)]
    discriminant: VpcDiscriminant,
    pipeline: ProcessingMetrics,
    peering: HashMap<VpcDiscriminant, ProcessingMetrics>,
}

#[derive(Debug)]
pub struct PipelineMetrics {
    pipeline: ProcessingMetrics,
    vpc: MultiIndexVpcMetricsMap,
}

#[test]
fn biscuit() {
    let x = |x: PipelineMetrics| {
        x.pipeline.drop.packet.count.metric.increment(1);
        x.pipeline.drop.bytes.rate.metric.decrement(17.2);
        x.vpc
            .get(VpcDiscriminant::VNI(17.try_into().unwrap()))
            .unwrap()
            .drop
            .packet
            .count
            .metric
            .increment(1);
    };
}

pub trait Register<T> {
    fn register(self) -> Registered<T>;
}

impl Register<metrics::Counter> for MetricSpec {
    fn register(self) -> Registered<metrics::Counter> {
        let k = self.key();
        let m = self.metatdata();
        let metric = metrics::with_recorder(|r| {
            r.describe_counter(
                self.id().to_string().into(),
                Some(self.unit()),
                self.description().to_string().into(),
            );
            r.register_counter(&k, &m)
        });
        Registered {
            details: Arc::new(self),
            metric,
        }
    }
}

impl Register<metrics::Gauge> for MetricSpec {
    fn register(self) -> Registered<metrics::Gauge> {
        let k = self.key();
        let m = self.metatdata();
        let metric = metrics::with_recorder(|r| {
            r.describe_gauge(
                self.id().to_string().into(),
                Some(self.unit()),
                self.description().to_string().into(),
            );
            r.register_gauge(&k, &m)
        });
        Registered {
            details: Arc::new(self),
            metric,
        }
    }
}

impl Register<metrics::Histogram> for MetricSpec {
    fn register(self) -> Registered<metrics::Histogram> {
        let k = self.key();
        let m = self.metatdata();
        let metric = metrics::with_recorder(|r| {
            r.describe_histogram(
                self.id().to_string().into(),
                Some(self.unit()),
                self.description().to_string().into(),
            );
            r.register_histogram(&k, &m)
        });
        Registered {
            details: Arc::new(self),
            metric,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Registered<T> {
    #[serde(flatten)]
    details: Arc<MetricSpec>,
    #[serde(skip)]
    pub metric: T,
}

impl MetricSpec {
    fn key(&self) -> metrics::Key {
        let labels: Vec<_> = self
            .labels()
            .iter()
            .map(|(k, v)| metrics::Label::new(k.clone(), v.clone()))
            .chain([metrics::Label::from(&(
                "action".to_string(),
                self.action().to_string(),
            ))])
            .collect();
        metrics::Key::from_parts(self.id().to_string(), labels)
    }

    fn metatdata(&self) -> metrics::Metadata {
        metrics::Metadata::new(self.target(), self.level(), self.module_path())
    }
}

impl Description for MetricSpec {
    fn action(&self) -> &str {
        &self.action
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    fn level(&self) -> Level {
        self.level
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn unit(&self) -> metrics::Unit {
        self.unit
    }
}

impl<T> Description for Registered<T> {
    fn action(&self) -> &str {
        self.details.action()
    }

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

#[macro_export]
macro_rules! associate {
    {$($key:expr => $value:expr),* $(,)?} => {
        {
            let mut labels = BTreeMap::new();
            $(
                labels.insert($key.to_string(), $value.to_string());
            )*
            labels
        }
    };
}

#[cfg(test)]
mod tests {
    use super::{MetricBuilder, Register, Registered};
    use std::collections::BTreeMap;

    #[test]
    fn test_counter() {
        let counter: Registered<metrics::Counter> = MetricBuilder::default()
            .id("test_counter")
            .description("test counter")
            .unit(metrics::Unit::Count)
            .action("drop")
            .labels(
                [("potato".to_string(), "biscuit".to_string())]
                    .iter()
                    .cloned()
                    .collect::<BTreeMap<_, _>>(),
            )
            .level(metrics::Level::INFO)
            .target("nat")
            .build()
            .unwrap()
            .register();
        counter.metric.increment(7);
        counter.metric.increment(3);
    }

    #[test]
    fn test_gauge() {
        let gauge: Registered<metrics::Gauge> = MetricBuilder::default()
            .id("test_gauge")
            .description("test gauge")
            .unit(metrics::Unit::MegabitsPerSecond)
            .action("sent")
            .labels(associate!("potato" => "biscuit", "science" => "cheese"))
            .level(metrics::Level::WARN)
            .target("test")
            .build()
            .unwrap()
            .register();
        gauge.metric.decrement(17.2);
        gauge.metric.increment(11.9);
    }

    #[test]
    fn test_histogram() {
        let histogram: Registered<metrics::Histogram> = MetricBuilder::default()
            .id("test_hist")
            .description("test histogram")
            .unit(metrics::Unit::Count)
            .action("received")
            .level(metrics::Level::DEBUG)
            .target("test")
            .build()
            .unwrap()
            .register();
        histogram.metric.record(11.2);
        histogram.metric.record(2);
        histogram.metric.record(17);
    }
}
