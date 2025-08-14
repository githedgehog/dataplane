// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::vpc::RegisteredPipelineMetrics;
use derive_builder::Builder;
use metrics::{Level, Unit};
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use vpcmap::VpcDiscriminant;

pub trait MetricDescription {
    fn action(&self) -> &str;
    fn description(&self) -> &str;
    fn id(&self) -> &str;
    fn labels(&self) -> &BTreeMap<String, String>;
    fn level(&self) -> Level;
    fn target(&self) -> &str;
    fn unit(&self) -> Unit;
    fn module_path(&self) -> Option<&str> {
        None
    }
}

#[derive(Serialize, Deserialize, Builder, Debug, Clone, MultiIndexMap)]
#[builder(name = "MetricBuilder")]
pub struct MetricSpec {
    #[builder(setter(into))]
    #[multi_index(ordered_unique)]
    pub id: String,
    #[builder(setter(into))]
    #[serde(
        deserialize_with = "serdefix::deserialize_unit",
        serialize_with = "serdefix::serialize_unit"
    )]
    pub unit: Unit,
    #[builder(setter(into), default = "Level::INFO")]
    #[serde(
        deserialize_with = "serdefix::deserialize_level",
        serialize_with = "serdefix::serialize_level",
        default = "serdefix::default_level"
    )]
    pub level: Level,
    #[builder(setter(into))]
    #[serde(
        skip_serializing_if = "String::is_empty",
        default = "serdefix::empty_string"
    )]
    #[multi_index(ordered_non_unique)]
    pub action: String,
    #[builder(setter(into))]
    #[serde(
        skip_serializing_if = "String::is_empty",
        default = "serdefix::empty_string"
    )]
    #[multi_index(ordered_non_unique)]
    pub target: String,
    #[builder(setter(into))]
    #[serde(
        skip_serializing_if = "String::is_empty",
        default = "serdefix::empty_string"
    )]
    pub description: String,
    #[builder(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl MetricSpec {
    pub fn builder() -> MetricBuilder {
        MetricBuilder::default()
    }

    pub fn new(id: impl AsRef<str>, action: impl AsRef<str>, unit: Unit) -> MetricSpec {
        MetricSpec {
            id: id.as_ref().to_string(),
            unit,
            level: Level::INFO,
            action: action.as_ref().to_string(),
            target: "".to_string(),
            description: "".to_string(),
            labels: Default::default(),
        }
    }
}

#[macro_export]
macro_rules! map {
    [$($key:expr => $value:expr),* $(,)?] => {
        {
            [
               $(($key.to_string(), $value.to_string())),*
            ].into_iter().collect()
        }
    };
}

impl MetricSpec {
    pub(crate) fn key(&self) -> metrics::Key {
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

    pub(crate) fn metadata(&self) -> metrics::Metadata<'_> {
        metrics::Metadata::new(self.target(), self.level(), self.module_path())
    }
}

impl MetricDescription for MetricSpec {
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

    fn unit(&self) -> Unit {
        self.unit
    }
}

// scratch to check api
#[allow(unused)]
fn scratch(pipeline: &RegisteredPipelineMetrics) {
    pipeline.total.rx.byte.count.metric.increment(17);
    pipeline.total.rx.byte.rate.metric.set(17);
    pipeline.total.rx.packet.count.metric.increment(17);
    pipeline.total.rx.packet.rate.metric.set(17);

    pipeline.total.tx.byte.count.metric.increment(17);
    pipeline.total.tx.byte.rate.metric.set(17);
    pipeline.total.tx.packet.count.metric.increment(17);
    pipeline.total.tx.packet.rate.metric.set(17);

    pipeline.vpcs().for_each(|(&disc, vpc)| {
        vpc.total.tx.byte.count.metric.increment(17);
        vpc.total.tx.byte.rate.metric.set(17);
        vpc.total.tx.packet.count.metric.increment(17);
        vpc.total.tx.packet.rate.metric.set(17);

        vpc.peer(&VpcDiscriminant::VNI(1.try_into().unwrap()))
            .unwrap()
            .rx
            .byte
            .count
            .metric
            .increment(17);

        vpc.peers().for_each(|(&disc, peer)| {
            peer.tx.byte.count.metric.increment(11);
            peer.tx.byte.rate.metric.set(17);
            peer.tx.packet.count.metric.increment(11);
            peer.tx.packet.rate.metric.set(17);
        });
    });
}

mod serdefix {
    use metrics::Level;
    use serde::Deserialize;

    pub(crate) fn deserialize_level<'de, D>(deserializer: D) -> Result<Level, D::Error>
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

    pub(crate) fn serialize_level<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(level_to_string(level))
    }

    fn parse_unit(s: &str) -> Result<metrics::Unit, String> {
        Ok(match s {
            "count" => metrics::Unit::Count,
            "percent" => metrics::Unit::Percent,
            "seconds" => metrics::Unit::Seconds,
            "milliseconds" => metrics::Unit::Milliseconds,
            "microseconds" => metrics::Unit::Microseconds,
            "nanoseconds" => metrics::Unit::Nanoseconds,
            "tebibytes" => metrics::Unit::Tebibytes,
            "gibibytes" => metrics::Unit::Gibibytes,
            "mebibytes" => metrics::Unit::Mebibytes,
            "kibibytes" => metrics::Unit::Kibibytes,
            "bytes" => metrics::Unit::Bytes,
            "terabits_per_second" => metrics::Unit::TerabitsPerSecond,
            "gigabits_per_second" => metrics::Unit::GigabitsPerSecond,
            "megabits_per_second" => metrics::Unit::MegabitsPerSecond,
            "kilobits_per_second" => metrics::Unit::KilobitsPerSecond,
            "bits_per_second" => metrics::Unit::BitsPerSecond,
            "count_per_second" => metrics::Unit::CountPerSecond,
            s => Err(format!("Unknown unit: {s}"))?,
        })
    }

    pub(crate) fn deserialize_unit<'de, D>(deserializer: D) -> Result<metrics::Unit, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_unit(&s).map_err(serde::de::Error::custom)
    }

    pub(crate) fn serialize_unit<S>(unit: &metrics::Unit, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(unit.as_str())
    }

    pub(crate) const fn default_level() -> Level {
        Level::INFO
    }

    pub(crate) fn empty_string() -> String {
        "".to_string()
    }
}
