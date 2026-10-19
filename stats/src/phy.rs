// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A port's physical layer and PCIe link, as `mstlink` reports them for NVIDIA/Mellanox devices.
//!
//! Series are `port_phy_*` and `port_pcie_*`, labelled with the configured interface name as
//! `port`, and `lane` numbered from 1 like the transceiver series (`mstlink` numbers from 0).
//! Cumulative values are counters. The device's own counts restart from zero when someone clears
//! them (`mstlink --pc`); the published counters carry on from where they were, so they only ever
//! rise, as Prometheus expects. Gauges with nothing to say read `NaN`.

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;
use metrics::{Counter, Gauge, Unit};
use mstlink::{FecHistogram, Pcie, PortReport};

/// Base id of the physical layer metric family. Every series below is `{BASE}_{suffix}`.
pub(crate) const PHY_METRIC_BASE: &str = "port_phy";

/// Base id of the PCIe link metric family.
pub(crate) const PCIE_METRIC_BASE: &str = "port_pcie";

fn labels(port: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut all = vec![("port".to_string(), port.to_string())];
    all.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
    );
    all
}

fn gauge(id: String, port: &str, extra: &[(&str, &str)], description: &str) -> Gauge {
    let mut spec = MetricSpec::new(id, Unit::Count, labels(port, extra));
    spec.description = description.to_string();
    let registered: Registered<Gauge> = spec.register();
    registered.metric
}

fn counter(id: String, port: &str, extra: &[(&str, &str)], description: &str) -> Cumulative {
    let mut spec = MetricSpec::new(id, Unit::Count, labels(port, extra));
    spec.description = description.to_string();
    let registered: Registered<Counter> = spec.register();
    Cumulative::new(registered.metric)
}

fn set(gauge: &Gauge, value: Option<f64>) {
    gauge.set(value.unwrap_or(f64::NAN));
}

/// A counter fed with a device's cumulative count, which someone may clear.
///
/// [`Counter::absolute`] only ever raises a counter, so publishing a cleared count as it is would
/// hold the series at its old value until the device counted past it, hiding everything counted in
/// between. A count that drops is taken as a clear, and what was counted before it carries over.
#[derive(Debug)]
struct Cumulative {
    counter: Counter,
    last: u64,
    carried: u64,
}

impl Cumulative {
    fn new(counter: Counter) -> Self {
        Cumulative {
            counter,
            last: 0,
            carried: 0,
        }
    }

    fn publish(&mut self, count: Option<u64>) {
        let Some(count) = count else { return };
        if count < self.last {
            self.carried = self.carried.saturating_add(self.last);
        }
        self.last = count;
        self.counter.absolute(self.carried.saturating_add(count));
    }
}

/// A port's physical layer series, registered once and extended as lanes and bins appear.
#[derive(Debug)]
pub struct PhyMetrics {
    port: String,
    info: Option<(Vec<String>, Gauge)>,
    status: Gauge,
    raw_ber: Gauge,
    effective_ber: Gauge,
    effective_errors: Cumulative,
    link_down: Cumulative,
    link_recoveries: Cumulative,
    lanes: Vec<PhyLane>,
    fec_bins: Vec<Cumulative>,
}

#[derive(Debug)]
struct PhyLane {
    raw_ber: Gauge,
    raw_errors: Cumulative,
    initial_fom: Gauge,
    last_fom: Gauge,
    grades: [Gauge; 3],
}

impl PhyLane {
    fn new(port: &str, lane: usize) -> Self {
        let lane = (lane + 1).to_string();
        let at = [("lane", lane.as_str())];
        let id = |suffix: &str| format!("{PHY_METRIC_BASE}_{suffix}");
        let fom = |measure: &str| {
            gauge(
                id("eye_fom"),
                port,
                &[("lane", lane.as_str()), ("measure", measure)],
                "the receiver's eye figure of merit, on the firmware's own scale: larger is wider",
            )
        };
        PhyLane {
            raw_ber: gauge(
                id("raw_ber"),
                port,
                &at,
                "bit error rate before FEC, per lane",
            ),
            raw_errors: counter(id("raw_errors"), port, &at, "bit errors before FEC"),
            initial_fom: fom("initial"),
            last_fom: fom("last"),
            grades: ["upper", "mid", "lower"].map(|eye| {
                gauge(
                    id("eye_grade"),
                    port,
                    &[("lane", lane.as_str()), ("eye", eye)],
                    "a PAM4 eye's grade; absent on NRZ links",
                )
            }),
        }
    }
}

impl PhyMetrics {
    /// Register a port's series, using the configured interface name as the `port` label.
    #[must_use]
    pub fn new(port: &str) -> PhyMetrics {
        let id = |suffix: &str| format!("{PHY_METRIC_BASE}_{suffix}");
        PhyMetrics {
            port: port.to_string(),
            info: None,
            status: gauge(
                id("troubleshooting_status"),
                port,
                &[],
                "the firmware's diagnosis of the link: 0 when it sees no issue; \
                 port_phy_info's recommendation says what it suggests otherwise",
            ),
            raw_ber: gauge(id("raw_ber"), port, &[], "bit error rate before FEC"),
            effective_ber: gauge(id("effective_ber"), port, &[], "bit error rate after FEC"),
            effective_errors: counter(
                id("effective_errors"),
                port,
                &[],
                "bit errors FEC could not correct",
            ),
            link_down: counter(id("link_down"), port, &[], "times the link went down"),
            link_recoveries: counter(
                id("link_recoveries"),
                port,
                &[],
                "times the link recovered from errors without going down",
            ),
            lanes: Vec::new(),
            fec_bins: Vec::new(),
        }
    }

    /// Publish what `mstlink -c -e` said.
    pub fn publish(&mut self, report: &PortReport) {
        self.publish_info(Some(report));
        set(
            &self.status,
            report.troubleshooting.status_opcode.map(f64::from),
        );
        let counters = report.counters.clone().unwrap_or_default();
        set(&self.raw_ber, counters.raw_ber);
        set(&self.effective_ber, counters.effective_ber);
        self.effective_errors.publish(counters.effective_errors);
        self.link_down.publish(counters.link_down);
        self.link_recoveries.publish(counters.link_error_recovery);

        let eye = report.eye.clone().unwrap_or_default();
        let lanes = counters
            .raw_ber_per_lane
            .len()
            .max(counters.raw_errors_per_lane.len())
            .max(eye.lanes.len());
        while self.lanes.len() < lanes {
            self.lanes.push(PhyLane::new(&self.port, self.lanes.len()));
        }
        for (i, lane) in self.lanes.iter_mut().enumerate() {
            set(
                &lane.raw_ber,
                counters.raw_ber_per_lane.get(i).copied().flatten(),
            );
            lane.raw_errors
                .publish(counters.raw_errors_per_lane.get(i).copied().flatten());
            let eye = eye.lanes.get(i);
            let value =
                |field: fn(&mstlink::EyeLane) -> Option<u32>| eye.and_then(field).map(f64::from);
            set(&lane.initial_fom, value(|e| e.initial_fom));
            set(&lane.last_fom, value(|e| e.last_fom));
            set(&lane.grades[0], value(|e| e.upper_grade));
            set(&lane.grades[1], value(|e| e.mid_grade));
            set(&lane.grades[2], value(|e| e.lower_grade));
        }
    }

    /// Publish a FEC histogram. A link without FEC has none; its bins keep their last counts.
    pub fn publish_fec(&mut self, histogram: &FecHistogram) {
        while self.fec_bins.len() < histogram.bins.len() {
            let bin = self.fec_bins.len().to_string();
            self.fec_bins.push(counter(
                format!("{PHY_METRIC_BASE}_fec_codewords"),
                &self.port,
                &[("corrected_symbols", bin.as_str())],
                "FEC codewords that needed this many symbols corrected; a growing count in \
                 the higher bins warns of a link approaching what FEC can correct",
            ));
        }
        for (counter, (_, count)) in self.fec_bins.iter_mut().zip(&histogram.bins) {
            counter.publish(Some(*count));
        }
    }

    /// `port_phy_info` carries the link's state and the firmware's recommendation as labels, and
    /// the value 1; a change retires the old series to 0.
    fn publish_info(&mut self, report: Option<&PortReport>) {
        let identity = report.map(|report| {
            let operational = &report.operational;
            let troubleshooting = &report.troubleshooting;
            [
                &operational.state,
                &operational.physical_state,
                &operational.speed,
                &operational.width,
                &operational.fec,
                &troubleshooting.recommendation,
            ]
            .map(|value| value.clone().unwrap_or_default())
            .to_vec()
        });
        if let Some((labels, _)) = &self.info
            && Some(labels) == identity.as_ref()
        {
            return;
        }
        if let Some((_, old)) = self.info.take() {
            old.set(0.0);
        }
        let Some(identity) = identity else { return };
        let keys = [
            "state",
            "physical_state",
            "speed",
            "width",
            "fec",
            "recommendation",
        ];
        let extra: Vec<(&str, &str)> = keys
            .iter()
            .zip(&identity)
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let info = gauge(
            format!("{PHY_METRIC_BASE}_info"),
            &self.port,
            &extra,
            "1 for the link's current state, with the firmware's recommendation, as labels",
        );
        info.set(1.0);
        self.info = Some((identity, info));
    }
}

/// A port's PCIe link series.
#[derive(Debug)]
pub struct PcieMetrics {
    generation: [Gauge; 2],
    width: [Gauge; 2],
    errors: [Cumulative; 4],
    effective_ber: Gauge,
}

impl PcieMetrics {
    /// Register a port's series, using the configured interface name as the `port` label.
    #[must_use]
    pub fn new(port: &str) -> PcieMetrics {
        let id = |suffix: &str| format!("{PCIE_METRIC_BASE}_{suffix}");
        let both = |suffix: &str, description: &str| {
            ["active", "enabled"]
                .map(|state| gauge(id(suffix), port, &[("state", state)], description))
        };
        PcieMetrics {
            generation: both(
                "generation",
                "the PCIe generation the link runs at (active) and could (enabled)",
            ),
            width: both(
                "width",
                "lanes the PCIe link uses (active) and could (enabled); fewer active than \
                 enabled means it trained down, and the host bandwidth is capped",
            ),
            errors: ["crc_dllp", "crc_tlp", "rx", "tx"].map(|kind| {
                counter(
                    id("errors"),
                    port,
                    &[("kind", kind)],
                    "PCIe link errors, by kind",
                )
            }),
            effective_ber: gauge(
                id("effective_ber"),
                port,
                &[],
                "the PCIe link's bit error rate",
            ),
        }
    }

    /// Publish what `mstlink --port_type PCIE -c` said.
    pub fn publish(&mut self, pcie: &Pcie) {
        set(&self.generation[0], pcie.generation_active.map(f64::from));
        set(&self.generation[1], pcie.generation_enabled.map(f64::from));
        set(&self.width[0], pcie.width_active.map(f64::from));
        set(&self.width[1], pcie.width_enabled.map(f64::from));
        let errors = [
            pcie.crc_errors_dllp,
            pcie.crc_errors_tlp,
            pcie.rx_errors,
            pcie.tx_errors,
        ];
        for (counter, value) in self.errors.iter_mut().zip(errors) {
            counter.publish(value);
        }
        set(&self.effective_ber, pcie.effective_ber);
    }
}

#[cfg(test)]
mod exported {
    use super::*;
    use crate::scrape::Scrape;

    /// The crate's directory, read at run time rather than with `env!`: test archives built in the
    /// nix sandbox run on the host, where the build path does not exist. nextest's
    /// `--workspace-remap` (and plain `cargo test`) set it to where the sources are.
    fn manifest_dir() -> String {
        std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string())
    }

    fn fixture(link: &str, file: &str) -> String {
        let path = format!("{}/../mstlink/tests/fixtures/{link}/{file}", manifest_dir());
        std::fs::read_to_string(path).unwrap()
    }

    fn get(scrape: &Scrape, id: &str, extra: &[(&str, &str)]) -> Option<f64> {
        let mut all = vec![("port", "eth0")];
        all.extend_from_slice(extra);
        scrape.get(id, &all)
    }

    fn count(scrape: &Scrape, id: &str, extra: &[(&str, &str)]) -> Option<u64> {
        let mut all = vec![("port", "eth0")];
        all.extend_from_slice(extra);
        scrape.counter(id, &all)
    }

    #[test]
    fn a_400g_port_publishes_its_lanes_and_histogram() {
        let report = PortReport::parse(&fixture("qsfp112-400g", "port.json")).unwrap();
        let histogram =
            FecHistogram::parse(&fixture("qsfp112-400g", "fec-histogram.json")).unwrap();
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let mut metrics = PhyMetrics::new("eth0");
            metrics.publish(&report);
            metrics.publish_fec(&histogram);
        });

        assert_eq!(
            get(&scrape, "port_phy_troubleshooting_status", &[]),
            Some(0.0)
        );
        assert_eq!(get(&scrape, "port_phy_raw_ber", &[]), Some(5e-11));
        assert_eq!(
            get(&scrape, "port_phy_raw_ber", &[("lane", "2")]),
            Some(1e-10)
        );
        assert_eq!(
            count(&scrape, "port_phy_raw_errors", &[("lane", "2")]),
            Some(1_623_516)
        );
        assert_eq!(
            get(
                &scrape,
                "port_phy_eye_grade",
                &[("lane", "2"), ("eye", "upper")]
            ),
            Some(67.0)
        );
        assert_eq!(
            count(
                &scrape,
                "port_phy_fec_codewords",
                &[("corrected_symbols", "1")]
            ),
            Some(1_613_216)
        );
        let info = scrape.series("port_phy_info");
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].0["speed"], "400G");
        assert_eq!(info[0].0["recommendation"], "No issue was observed");
    }

    #[test]
    fn an_nrz_port_has_no_grades_to_publish() {
        let report = PortReport::parse(&fixture("sfp-10g", "port.json")).unwrap();
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || PhyMetrics::new("eth0").publish(&report));

        let last = get(
            &scrape,
            "port_phy_eye_fom",
            &[("lane", "1"), ("measure", "last")],
        );
        assert!(last.is_some_and(|fom| fom > 0.0));
        let grade = get(
            &scrape,
            "port_phy_eye_grade",
            &[("lane", "1"), ("eye", "mid")],
        );
        assert!(grade.unwrap().is_nan());
        assert_eq!(
            get(&scrape, "port_phy_raw_ber", &[("lane", "2")]),
            None,
            "one lane"
        );
    }

    #[test]
    fn a_link_change_retires_the_old_state() {
        let fast = PortReport::parse(&fixture("qsfp112-400g", "port.json")).unwrap();
        let slow = PortReport::parse(&fixture("sfp-10g", "port.json")).unwrap();
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let mut metrics = PhyMetrics::new("eth0");
            metrics.publish(&fast);
            metrics.publish(&fast);
            metrics.publish(&slow);
        });
        let mut info: Vec<(String, f64)> = scrape
            .series("port_phy_info")
            .into_iter()
            .map(|(labels, value)| (labels["speed"].clone(), value))
            .collect();
        info.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(info, [("10G".to_string(), 1.0), ("400G".to_string(), 0.0)]);
    }

    #[test]
    fn a_cleared_device_count_does_not_stall_the_counter() {
        let mut report = PortReport::parse(&fixture("qsfp112-400g", "port.json")).unwrap();
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let mut metrics = PhyMetrics::new("eth0");
            let mut publish = |link_down| {
                report.counters.as_mut().unwrap().link_down = Some(link_down);
                metrics.publish(&report);
            };
            publish(5);
            publish(7);
            publish(1); // cleared, then the link went down once more
            publish(3);
        });
        assert_eq!(count(&scrape, "port_phy_link_down", &[]), Some(7 + 3));
    }

    #[test]
    fn a_trained_down_pcie_link_shows() {
        let pcie = Pcie::parse(&fixture("qsfp112-400g", "pcie.json")).unwrap();
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || PcieMetrics::new("eth0").publish(&pcie));

        assert_eq!(
            get(&scrape, "port_pcie_width", &[("state", "active")]),
            Some(8.0)
        );
        assert_eq!(
            get(&scrape, "port_pcie_width", &[("state", "enabled")]),
            Some(16.0)
        );
        assert_eq!(
            get(&scrape, "port_pcie_generation", &[("state", "active")]),
            Some(5.0)
        );
        assert_eq!(
            count(&scrape, "port_pcie_errors", &[("kind", "tx")]),
            Some(2)
        );
    }
}
