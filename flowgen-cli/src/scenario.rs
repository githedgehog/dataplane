// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a run is told to do, as a YAML file says it.
//!
//! A scenario names the port to generate on, the protocol speakers (agents) that run for the
//! whole of it, and its cases, run in order: each a set of streams sent at once, how long to give
//! them, and what to expect of the counters they leave. See `scenarios/` for examples.

use std::path::Path;
use std::time::Duration;

use flowgen::bfd;
use flowgen::frame::Endpoints;
use flowgen::sender::Stream;
use flowgen::tcp::{Addressing, Encap, Role};
use serde::{Deserialize, Serialize};

/// A whole run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// The port to generate on.
    pub port: PortSpec,
    /// More EAL arguments, after the ones every run uses: `--no-huge`, `-m`, and so on.
    #[serde(default)]
    pub eal: Vec<String>,
    /// Where to read the gateway's telemetry from, if anywhere.
    #[serde(default)]
    pub telemetry: Option<Telemetry>,
    /// How often progress is sampled into the report.
    #[serde(default = "one_second", with = "duration_text")]
    pub sample_every: Duration,
    /// Protocol speakers that run for the whole of the run.
    #[serde(default)]
    pub agents: Vec<AgentSpec>,
    /// The cases, run in order.
    pub cases: Vec<CaseSpec>,
}

fn one_second() -> Duration {
    Duration::from_secs(1)
}

/// The port to generate on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortSpec {
    /// The name its counters are reported under (`port.<name>.*`).
    #[serde(default = "port_name")]
    pub name: String,
    /// A PCI device, by address, bound to a driver DPDK can use (`vfio-pci`, or `mlx5_core`).
    #[serde(default)]
    pub pci: Option<String>,
    /// A virtual device, as `--vdev` takes it: `net_af_packet0,iface=eth1`, `net_ring0`.
    #[serde(default)]
    pub vdev: Option<String>,
    /// Receive and transmit queues each; streams spread their flows over them.
    #[serde(default = "one")]
    pub queues: u16,
    /// Descriptors per queue.
    #[serde(default = "descriptors")]
    pub descriptors: u16,
    /// Mbufs in the port's pool.
    #[serde(default = "pool_size")]
    pub pool_size: u32,
    /// The MTU, or the device's default.
    #[serde(default)]
    pub mtu: Option<u16>,
}

fn port_name() -> String {
    "generator".to_string()
}

fn one() -> u16 {
    1
}

fn descriptors() -> u16 {
    1024
}

fn pool_size() -> u32 {
    (1 << 14) - 1
}

/// Which device a port is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Device<'a> {
    /// A PCI device, by address.
    Pci(&'a str),
    /// A virtual device, as `--vdev` takes it.
    Vdev(&'a str),
}

impl PortSpec {
    /// The port's device.
    ///
    /// # Errors
    ///
    /// Unless exactly one of `pci` and `vdev` is given.
    pub fn device(&self) -> Result<Device<'_>, ScenarioError> {
        match (&self.pci, &self.vdev) {
            (Some(pci), None) => Ok(Device::Pci(pci)),
            (None, Some(vdev)) => Ok(Device::Vdev(vdev)),
            _ => Err(ScenarioError::Invalid(
                "a port is either `pci` or `vdev`, and not both".to_string(),
            )),
        }
    }
}

/// Where the gateway's telemetry is.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    /// Its Prometheus endpoint: `http://host:port/metrics`.
    pub url: String,
}

/// A protocol speaker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSpec {
    /// A BFD peer.
    Bfd {
        /// Its name, under which it reports (`bfd.<name>.*`).
        name: String,
        /// Its addresses and ports; the destination port should be 3784.
        endpoints: Endpoints,
        /// Its session.
        session: bfd::Config,
    },
    /// The generating host's own network stack, as far as the switch needs one: it answers ARP
    /// for the streams' addresses on their VLANs, announces them, and takes other link traffic
    /// (`host.<name>.*`). Needed on a real port, where the kernel sees nothing.
    Host {
        /// Its name, under which it reports.
        name: String,
        /// The port's MAC.
        #[serde(with = "flowgen::frame::mac_text")]
        mac: flowgen::frame::Mac,
        /// The addresses it answers for.
        addresses: Vec<flowgen::host::Address>,
        /// How often to announce them again after the first time; never, if zero.
        #[serde(default, with = "duration_text")]
        announce_every: Duration,
    },
    /// A smoltcp host.
    Tcp {
        /// Its name, under which it reports (`tcp.<name>.*`, and `bgp.<name>.*` for a BGP speaker).
        name: String,
        /// Its address.
        addressing: Addressing,
        /// How its packets travel.
        encap: Encap,
        /// What it does.
        role: Role,
    },
}

/// One case of a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// Its name, unique within the run.
    pub name: String,
    /// What it sends.
    #[serde(default)]
    pub streams: Vec<Stream>,
    /// How long it lasts at least, however soon its streams are done: how long the agents get.
    #[serde(default, with = "duration_text")]
    pub hold: Duration,
    /// How long, once everything is sent, to wait after the last frame came back.
    #[serde(default = "one_second", with = "duration_text")]
    pub quiet: Duration,
    /// The longest it may take.
    #[serde(default = "a_minute", with = "duration_text")]
    pub limit: Duration,
    /// What its counters must come to.
    #[serde(default)]
    pub expect: Vec<Expect>,
}

fn a_minute() -> Duration {
    Duration::from_secs(60)
}

/// A counter or gauge's bound at the end of a case.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    /// The check's name, unique within the case.
    pub id: String,
    /// The counter or gauge: `generator.<stream>.lost`, `bfd.<peer>.flaps`, `dataplane.<metric>...`.
    /// Counters are since the case began; gauges as they stand.
    pub path: String,
    /// Exactly this.
    #[serde(default)]
    pub exactly: Option<u64>,
    /// At least this.
    #[serde(default)]
    pub min: Option<u64>,
    /// At most this.
    #[serde(default)]
    pub max: Option<u64>,
}

/// Why a scenario could not be had.
#[derive(Debug, thiserror::Error)]
pub enum ScenarioError {
    /// The file could not be read.
    #[error("could not read {path}: {source}")]
    Read {
        /// The file.
        path: String,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The file is not a scenario.
    #[error("{path} is not a scenario: {source}")]
    Parse {
        /// The file.
        path: String,
        /// Why.
        #[source]
        source: serde_yaml_ng::Error,
    },
    /// The scenario is a scenario, but not one that can run.
    #[error("{0}")]
    Invalid(String),
}

impl Scenario {
    /// The scenario in the YAML file at `path`, checked.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, is not a scenario, or describes one that cannot run.
    pub fn load(path: &Path) -> Result<Scenario, ScenarioError> {
        let shown = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|source| ScenarioError::Read {
            path: shown.clone(),
            source,
        })?;
        let scenario = Scenario::from_yaml(&text).map_err(|source| ScenarioError::Parse {
            path: shown,
            source,
        })?;
        scenario.check()?;
        Ok(scenario)
    }

    /// A scenario from YAML. Enums are written as maps of one key -- `order: { shuffled: 7 }` --
    /// as in the report, rather than as YAML tags.
    ///
    /// # Errors
    ///
    /// If `text` is not a scenario.
    pub fn from_yaml(text: &str) -> Result<Scenario, serde_yaml_ng::Error> {
        serde_yaml_ng::with::singleton_map_recursive::deserialize(
            serde_yaml_ng::Deserializer::from_str(text),
        )
    }

    /// The scenario as YAML, written as [`Scenario::from_yaml`] reads it.
    ///
    /// # Errors
    ///
    /// If it cannot be written.
    pub fn to_yaml(&self) -> Result<String, serde_yaml_ng::Error> {
        let mut out = Vec::new();
        serde_yaml_ng::with::singleton_map_recursive::serialize(
            self,
            &mut serde_yaml_ng::Serializer::new(&mut out),
        )?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Check what serde cannot: names unique, schedules followable, bounds meaningful.
    ///
    /// # Errors
    ///
    /// The first thing wrong.
    pub fn check(&self) -> Result<(), ScenarioError> {
        let invalid = |what: String| Err(ScenarioError::Invalid(what));
        if self.cases.is_empty() {
            return invalid("a scenario needs at least one case".to_string());
        }
        self.port.device()?;
        if self.port.queues == 0 {
            return invalid("a port needs at least one queue".to_string());
        }
        // Names need only differ within a kind: each kind reports under its own prefix.
        let mut agents = std::collections::BTreeSet::new();
        for agent in &self.agents {
            let (kind, name) = match agent {
                AgentSpec::Bfd { name, .. } => ("bfd", name),
                AgentSpec::Host { name, .. } => ("host", name),
                AgentSpec::Tcp { name, .. } => ("tcp", name),
            };
            if !agents.insert((kind, name.clone())) {
                return invalid(format!("two {kind} agents are called {name:?}"));
            }
        }
        let mut cases = std::collections::BTreeSet::new();
        for case in &self.cases {
            if !cases.insert(case.name.clone()) {
                return invalid(format!("two cases are called {:?}", case.name));
            }
            let mut streams = std::collections::BTreeSet::new();
            for stream in &case.streams {
                if !streams.insert(stream.name.clone()) {
                    return invalid(format!(
                        "case {:?} has two streams called {:?}",
                        case.name, stream.name
                    ));
                }
                if let Err(e) = stream.schedule.validate() {
                    return invalid(format!(
                        "case {:?}, stream {:?}: {e}",
                        case.name, stream.name
                    ));
                }
                if let Some(Err(e)) = stream.frame.mutation.map(|m| m.check(&stream.frame)) {
                    return invalid(format!(
                        "case {:?}, stream {:?}: {e}",
                        case.name, stream.name
                    ));
                }
            }
            let mut ids = std::collections::BTreeSet::new();
            for expect in &case.expect {
                if !ids.insert(expect.id.clone()) {
                    return invalid(format!(
                        "case {:?} has two expectations called {:?}",
                        case.name, expect.id
                    ));
                }
                if expect.exactly.is_some() && (expect.min.is_some() || expect.max.is_some()) {
                    return invalid(format!(
                        "case {:?}, expectation {:?}: `exactly` with `min` or `max`",
                        case.name, expect.id
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Durations as people write them: `250ms`, `1s`, `1.5s`, `2m`.
pub mod duration_text {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    /// Write `duration` in milliseconds, or seconds if whole.
    ///
    /// # Errors
    ///
    /// If `serializer` fails.
    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        let text = if duration.subsec_millis() == 0 {
            format!("{}s", duration.as_secs())
        } else {
            format!("{}ms", duration.as_millis())
        };
        serializer.serialize_str(&text)
    }

    /// Read a duration.
    ///
    /// # Errors
    ///
    /// If the text is not a duration.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse(&text).ok_or_else(|| {
            D::Error::custom(format!(
                "{text:?} is not a duration: say `250ms`, `1s`, `1.5s` or `2m`"
            ))
        })
    }

    /// `text` as a duration, if it is one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Duration> {
        let text = text.trim();
        let (number, unit) = text.split_at(text.find(|c: char| c.is_ascii_alphabetic())?);
        let number: f64 = number.trim().parse().ok()?;
        let seconds = match unit {
            "ms" => number / 1000.0,
            "s" => number,
            "m" => number * 60.0,
            _ => return None,
        };
        (seconds.is_finite() && seconds >= 0.0).then(|| Duration::from_secs_f64(seconds))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn durations_read_as_written() {
        assert_eq!(
            duration_text::parse("250ms"),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            duration_text::parse("1.5s"),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(duration_text::parse("2m"), Some(Duration::from_secs(120)));
        assert_eq!(duration_text::parse("2"), None);
        assert_eq!(duration_text::parse("-1s"), None);
        assert_eq!(duration_text::parse("1h"), None);
    }

    /// Every example scenario loads, checks, and survives a round trip through YAML.
    #[test]
    fn the_examples_are_scenarios() {
        let dir = Path::new(
            &std::env::var("CARGO_MANIFEST_DIR")
                .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string()),
        )
        .join("scenarios");
        let mut seen = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "yaml") {
                let scenario = Scenario::load(&path).unwrap_or_else(|e| panic!("{e}"));
                let again = Scenario::from_yaml(&scenario.to_yaml().unwrap()).unwrap();
                again.check().unwrap();
                seen += 1;
            }
        }
        assert!(seen > 0, "no example scenarios");
    }

    #[test]
    fn mistakes_are_refused() {
        let base = "
port: { vdev: net_ring0 }
cases:
  - name: a
";
        let scenario = Scenario::from_yaml(base).unwrap();
        scenario.check().unwrap();
        for (yaml, why) in [
            ("port: { vdev: x }\ncases: []\n", "no cases"),
            (
                "port: { vdev: x }\ncases: [{name: a}, {name: a}]\n",
                "repeated case",
            ),
            (
                "port: { vdev: x, queues: 0 }\ncases: [{name: a}]\n",
                "no queues",
            ),
            (
                "port: { vdev: x, pci: y }\ncases: [{name: a}]\n",
                "two devices",
            ),
            ("port: {}\ncases: [{name: a}]\n", "no device"),
            (
                "port: { vdev: x }\ncases: [{name: a, expect: [{id: x, path: p, exactly: 1, min: 0}]}]\n",
                "exactly with min",
            ),
        ] {
            let scenario = Scenario::from_yaml(yaml).unwrap();
            assert!(scenario.check().is_err(), "{why} was accepted");
        }
        assert!(
            Scenario::from_yaml("port: { vdev: x }\ncases: [{name: a, hodl: 1s}]\n").is_err(),
            "a misspelt field was accepted"
        );
    }

    /// A stream's frames can be mutated, but only in headers they have.
    #[test]
    fn a_mutation_is_checked_against_the_frames() {
        let stream = |mutation: &str| {
            format!(
                "
port: {{ vdev: x }}
cases:
  - name: a
    streams:
      - name: s
        space:
          src: {{ first: 10.0.0.1, count: 1 }}
          dst: {{ first: 10.1.0.1, count: 1 }}
          sport: {{ first: 1024, count: 1 }}
          dport: {{ first: 80, count: 1 }}
          order: sequential
        schedule: {{ window: 1, churn: 0, rounds: 1 }}
        frame:
          src_mac: \"02:00:00:00:00:01\"
          dst_mac: \"02:00:00:00:00:02\"
          payload_len: 64
          ttl: 64
          mutation: {mutation}
        rate_pps: null
        returns: nothing
"
            )
        };
        let ttl = Scenario::from_yaml(&stream("{ change: { ttl: { ttl: 0 } } }")).unwrap();
        ttl.check().unwrap();
        let outer = Scenario::from_yaml(&stream("{ layer: outer, change: ip_checksum }")).unwrap();
        assert!(
            outer.check().is_err(),
            "an untunnelled frame has no outer layer"
        );
    }
}
