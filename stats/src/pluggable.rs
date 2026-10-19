// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Pluggable module (transceiver or cable) readings, one set per port.
//!
//! Every series is `transceiver_*` with the configured interface name as the `port` label, and
//! lane series add a `lane` label numbered from 1, as the module specifications number lanes.
//! Units are part of the name (Prometheus base units) because [`metrics::Unit`] has none for them.
//!
//! A reading the module does not implement, or every reading while no module answers, is `NaN`
//! rather than 0: dashboards show a gap instead of a plausible but false value.

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;
use metrics::{Gauge, Unit};
use transceiver::{Bounds, Crossings, LaneFlags, LaneMonitors, Module, RxPowerKind};

/// Base id of the module metric family. Every series below is `{BASE}_{suffix}`.
pub(crate) const TRANSCEIVER_METRIC_BASE: &str = "transceiver";

/// The four limits of a monitored quantity, as label values.
const LEVELS: [&str; 4] = ["high_alarm", "low_alarm", "high_warning", "low_warning"];

/// Lane conditions a module may flag, as label values.
const FAULTS: [&str; 5] = ["tx_fault", "tx_los", "tx_lol", "rx_los", "rx_lol"];

/// Gauges registered once per port, extended as a module with more lanes appears.
#[derive(Debug)]
pub struct TransceiverMetrics {
    port: String,
    present: Gauge,
    /// The identity labels of the series last set to 1, and that series.
    info: Option<(Vec<String>, Gauge)>,
    temperature: Gauge,
    supply: Gauge,
    temperature_crossed: [Gauge; 4],
    supply_crossed: [Gauge; 4],
    thresholds: Thresholds,
    lanes: Vec<LaneGauges>,
}

/// The four limit gauges of each monitored quantity.
#[derive(Debug)]
struct Thresholds {
    temperature: [Gauge; 4],
    supply: [Gauge; 4],
    tx_bias: [Gauge; 4],
    tx_power: [Gauge; 4],
    rx_power: [Gauge; 4],
}

#[derive(Debug)]
struct LaneGauges {
    tx_bias: Gauge,
    tx_power: Gauge,
    rx_power: Gauge,
    tx_bias_crossed: [Gauge; 4],
    tx_power_crossed: [Gauge; 4],
    rx_power_crossed: [Gauge; 4],
    faults: [Gauge; 5],
}

fn gauge(port: &str, suffix: &str, labels: &[(&str, &str)], description: &str) -> Gauge {
    let mut all = vec![("port".to_string(), port.to_string())];
    all.extend(
        labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
    );
    let mut spec = MetricSpec::new(
        format!("{TRANSCEIVER_METRIC_BASE}_{suffix}"),
        Unit::Count,
        all,
    );
    spec.description = description.to_string();
    let registered: Registered<Gauge> = spec.register();
    registered.metric
}

/// One gauge per limit, labelled `level`, with any extra labels.
fn levels(port: &str, suffix: &str, labels: &[(&str, &str)], description: &str) -> [Gauge; 4] {
    LEVELS.map(|level| {
        let mut labels = labels.to_vec();
        labels.push(("level", level));
        gauge(port, suffix, &labels, description)
    })
}

const CROSSED: &str = "1 if the module flagged the reading beyond this limit at the last poll; \
     modules that latch flags report a crossing since the previous poll, so a brief excursion \
     between polls still shows";

impl Thresholds {
    fn new(port: &str) -> Self {
        let limit = |quantity: &str, unit: &str| {
            levels(
                port,
                &format!("threshold_{quantity}_{unit}"),
                &[],
                &format!("the {quantity} limits the module warns and alarms at"),
            )
        };
        Thresholds {
            temperature: limit("temperature", "celsius"),
            supply: limit("supply", "volts"),
            tx_bias: limit("tx_bias", "amperes"),
            tx_power: limit("tx_power", "watts"),
            rx_power: limit("rx_power", "watts"),
        }
    }
}

impl LaneGauges {
    fn new(port: &str, lane: usize) -> Self {
        let lane = (lane + 1).to_string();
        let labels = [("lane", lane.as_str())];
        LaneGauges {
            tx_bias: gauge(port, "tx_bias_amperes", &labels, "laser bias current"),
            tx_power: gauge(port, "tx_power_watts", &labels, "transmitted optical power"),
            rx_power: gauge(
                port,
                "rx_power_watts",
                &labels,
                "received optical power; average or OMA, as transceiver_info's rx_power says",
            ),
            tx_bias_crossed: levels(
                port,
                "crossed",
                &[("lane", lane.as_str()), ("quantity", "tx_bias")],
                CROSSED,
            ),
            tx_power_crossed: levels(
                port,
                "crossed",
                &[("lane", lane.as_str()), ("quantity", "tx_power")],
                CROSSED,
            ),
            rx_power_crossed: levels(
                port,
                "crossed",
                &[("lane", lane.as_str()), ("quantity", "rx_power")],
                CROSSED,
            ),
            faults: FAULTS.map(|fault| {
                gauge(
                    port,
                    "lane_fault",
                    &[("lane", lane.as_str()), ("fault", fault)],
                    "1 if the module flagged the lane condition at the last poll, NaN if it \
                     does not report it",
                )
            }),
        }
    }

    fn publish(&self, readings: Option<&LaneMonitors>, flags: Option<&LaneFlags>) {
        let readings = readings.copied().unwrap_or_default();
        set(
            &self.tx_bias,
            readings.tx_bias.map(|c| f64::from(c.microamps()) / 1e6),
        );
        set(
            &self.tx_power,
            readings.tx_power.map(|p| p.milliwatts() / 1e3),
        );
        set(
            &self.rx_power,
            readings.rx_power.map(|p| p.milliwatts() / 1e3),
        );
        crossed(&self.tx_bias_crossed, flags.map(|f| f.tx_bias));
        crossed(&self.tx_power_crossed, flags.map(|f| f.tx_power));
        crossed(&self.rx_power_crossed, flags.map(|f| f.rx_power));
        let faults = flags.map_or([None; 5], |f| {
            [f.tx_fault, f.tx_los, f.tx_lol, f.rx_los, f.rx_lol]
        });
        for (gauge, fault) in self.faults.iter().zip(faults) {
            set(gauge, fault.map(f64::from));
        }
    }
}

fn set(gauge: &Gauge, value: Option<f64>) {
    gauge.set(value.unwrap_or(f64::NAN));
}

fn crossed(gauges: &[Gauge; 4], crossings: Option<Crossings>) {
    let values = crossings.map(|c| [c.high_alarm, c.low_alarm, c.high_warning, c.low_warning]);
    for (i, gauge) in gauges.iter().enumerate() {
        set(gauge, values.map(|v| f64::from(v[i])));
    }
}

fn limits<T: Copy>(gauges: &[Gauge; 4], bounds: Option<Bounds<T>>, value: impl Fn(T) -> f64) {
    let values = bounds.map(|b| [b.high_alarm, b.low_alarm, b.high_warning, b.low_warning]);
    for (i, gauge) in gauges.iter().enumerate() {
        set(gauge, values.map(|v| value(v[i])));
    }
}

impl TransceiverMetrics {
    /// Register a port's gauges, using the configured interface name as the `port` label.
    ///
    /// Lane gauges are registered when a module with lanes is first published.
    #[must_use]
    pub fn new(port: &str) -> TransceiverMetrics {
        TransceiverMetrics {
            port: port.to_string(),
            present: gauge(
                port,
                "present",
                &[],
                "1 if a module answered at the last poll",
            ),
            info: None,
            temperature: gauge(port, "temperature_celsius", &[], "module case temperature"),
            supply: gauge(port, "supply_volts", &[], "module supply voltage"),
            temperature_crossed: levels(port, "crossed", &[("quantity", "temperature")], CROSSED),
            supply_crossed: levels(port, "crossed", &[("quantity", "supply")], CROSSED),
            thresholds: Thresholds::new(port),
            lanes: Vec::new(),
        }
    }

    /// Publish what a module reported.
    pub fn publish(&mut self, module: &Module) {
        self.present.set(1.0);
        self.publish_info(Some(module));

        let monitors = &module.monitors;
        set(&self.temperature, monitors.temperature.map(|t| t.celsius()));
        set(&self.supply, monitors.supply.map(|v| v.volts()));
        let flags = module.flags.as_ref();
        crossed(&self.temperature_crossed, flags.map(|f| f.temperature));
        crossed(&self.supply_crossed, flags.map(|f| f.supply));

        let thresholds = module.thresholds.unwrap_or_default();
        limits(&self.thresholds.temperature, thresholds.temperature, |t| {
            t.celsius()
        });
        limits(&self.thresholds.supply, thresholds.supply, |v| v.volts());
        limits(&self.thresholds.tx_bias, thresholds.tx_bias, |c| {
            f64::from(c.microamps()) / 1e6
        });
        limits(&self.thresholds.tx_power, thresholds.tx_power, |p| {
            p.milliwatts() / 1e3
        });
        limits(&self.thresholds.rx_power, thresholds.rx_power, |p| {
            p.milliwatts() / 1e3
        });

        let lanes = monitors.lanes.len().max(flags.map_or(0, |f| f.lanes.len()));
        while self.lanes.len() < lanes {
            self.lanes
                .push(LaneGauges::new(&self.port, self.lanes.len()));
        }
        for (i, lane) in self.lanes.iter().enumerate() {
            lane.publish(monitors.lanes.get(i), flags.and_then(|f| f.lanes.get(i)));
        }
    }

    /// Publish that no module answered: every reading becomes `NaN`.
    pub fn absent(&mut self) {
        self.present.set(0.0);
        self.publish_info(None);
        for gauge in [&self.temperature, &self.supply] {
            gauge.set(f64::NAN);
        }
        crossed(&self.temperature_crossed, None);
        crossed(&self.supply_crossed, None);
        for gauges in [
            &self.thresholds.temperature,
            &self.thresholds.supply,
            &self.thresholds.tx_bias,
            &self.thresholds.tx_power,
            &self.thresholds.rx_power,
        ] {
            for gauge in gauges {
                gauge.set(f64::NAN);
            }
        }
        for lane in &self.lanes {
            lane.publish(None, None);
        }
    }

    /// `transceiver_info` carries the module's identity in its labels and the value 1. A module
    /// swap changes the labels, so the old series is set to 0 rather than left claiming the module
    /// is still there; an unchanged module keeps its series untouched.
    fn publish_info(&mut self, module: Option<&Module>) {
        let identity = module.map(|module| {
            let inventory = &module.inventory;
            let rx_power = match module.monitors.rx_power_kind {
                RxPowerKind::Average => "average",
                RxPowerKind::Oma => "oma",
            };
            [
                module.identifier.name(),
                &inventory.vendor,
                &inventory.part_number,
                &inventory.revision,
                &inventory.serial_number,
                rx_power,
            ]
            .map(str::to_string)
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
            "identifier",
            "vendor",
            "part_number",
            "revision",
            "serial_number",
            "rx_power",
        ];
        let labels: Vec<(&str, &str)> = keys
            .iter()
            .zip(&identity)
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let info = gauge(
            &self.port,
            "info",
            &labels,
            "1 for the module in the port, with its identity as labels",
        );
        info.set(1.0);
        self.info = Some((identity, info));
    }
}

#[cfg(test)]
mod exported {
    use super::*;
    use crate::scrape::Scrape;
    use transceiver::{Block, I2cAddress, Image, Region};

    /// A module captured in the lab, decoded.
    fn captured(dir: &str, regions: &[(Region, &str)]) -> Module {
        let mut image = Image::new();
        for (region, file) in regions {
            let path = format!(
                "{}/../transceiver/tests/fixtures/{dir}/{file}",
                env!("CARGO_MANIFEST_DIR")
            );
            let bytes = std::fs::read(&path).unwrap();
            image.insert(*region, Block::try_from(bytes.as_slice()).unwrap());
        }
        transceiver::decode(&image).unwrap()
    }

    /// An FS QSFP112-SR4: four lanes, every monitor, thresholds and flags.
    fn optic() -> Module {
        captured(
            "qsfp112-sr4-fs-port0",
            &[
                (Region::Lower(I2cAddress::A0), "lower.bin"),
                (Region::upper(0x00), "page-00.bin"),
                (Region::upper(0x01), "page-01.bin"),
                (Region::upper(0x02), "page-02.bin"),
                (Region::banked(0, 0x11), "page-11.bin"),
            ],
        )
    }

    /// A passive QSFP112 copper cable: flat memory, no monitors at all.
    fn cable() -> Module {
        captured(
            "qsfp112-dac-port0",
            &[
                (Region::Lower(I2cAddress::A0), "lower.bin"),
                (Region::upper(0x00), "page-00.bin"),
            ],
        )
    }

    fn get(scrape: &Scrape, suffix: &str, labels: &[(&str, &str)]) -> Option<f64> {
        let mut all = vec![("port", "eth0")];
        all.extend_from_slice(labels);
        scrape.get(&format!("{TRANSCEIVER_METRIC_BASE}_{suffix}"), &all)
    }

    fn info(scrape: &Scrape) -> Vec<(String, f64)> {
        scrape
            .series(&format!("{TRANSCEIVER_METRIC_BASE}_info"))
            .into_iter()
            .map(|(labels, value)| (labels["serial_number"].clone(), value))
            .collect()
    }

    #[test]
    fn an_optic_publishes_every_reading() {
        let module = optic();
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || TransceiverMetrics::new("eth0").publish(&module));

        assert_eq!(get(&scrape, "present", &[]), Some(1.0));
        assert_eq!(info(&scrape), [("C2606276848".to_string(), 1.0)]);
        let temperature = module.monitors.temperature.unwrap().celsius();
        assert_eq!(get(&scrape, "temperature_celsius", &[]), Some(temperature));
        for (i, lane) in module.monitors.lanes.iter().enumerate() {
            let lane_label = (i + 1).to_string();
            let labels = [("lane", lane_label.as_str())];
            let bias = f64::from(lane.tx_bias.unwrap().microamps()) / 1e6;
            assert_eq!(get(&scrape, "tx_bias_amperes", &labels), Some(bias));
            let rx = lane.rx_power.unwrap().milliwatts() / 1e3;
            assert_eq!(get(&scrape, "rx_power_watts", &labels), Some(rx));
            let crossed = [
                ("lane", lane_label.as_str()),
                ("quantity", "rx_power"),
                ("level", "high_alarm"),
            ];
            assert_eq!(get(&scrape, "crossed", &crossed), Some(0.0));
        }
        assert_eq!(
            get(&scrape, "tx_bias_amperes", &[("lane", "5")]),
            None,
            "only 4 lanes"
        );
        let high_alarm = module
            .thresholds
            .unwrap()
            .temperature
            .unwrap()
            .high_alarm
            .celsius();
        assert_eq!(
            get(
                &scrape,
                "threshold_temperature_celsius",
                &[("level", "high_alarm")]
            ),
            Some(high_alarm)
        );
    }

    #[test]
    fn a_cable_publishes_gaps_not_zeros() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            TransceiverMetrics::new("eth0").publish(&cable())
        });

        assert_eq!(get(&scrape, "present", &[]), Some(1.0));
        assert!(get(&scrape, "temperature_celsius", &[]).unwrap().is_nan());
        assert!(
            get(
                &scrape,
                "threshold_rx_power_watts",
                &[("level", "low_alarm")]
            )
            .unwrap()
            .is_nan()
        );
        assert_eq!(
            get(&scrape, "tx_bias_amperes", &[("lane", "1")]),
            None,
            "no lanes"
        );
    }

    #[test]
    fn an_absent_module_leaves_nothing_claiming_otherwise() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let mut metrics = TransceiverMetrics::new("eth0");
            metrics.publish(&optic());
            metrics.absent();
        });

        assert_eq!(get(&scrape, "present", &[]), Some(0.0));
        assert_eq!(info(&scrape), [("C2606276848".to_string(), 0.0)]);
        assert!(get(&scrape, "temperature_celsius", &[]).unwrap().is_nan());
        assert!(
            get(&scrape, "rx_power_watts", &[("lane", "3")])
                .unwrap()
                .is_nan()
        );
        let fault = [("lane", "2"), ("fault", "rx_los")];
        assert!(get(&scrape, "lane_fault", &fault).unwrap().is_nan());
    }

    #[test]
    fn a_swap_retires_the_old_identity() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let mut metrics = TransceiverMetrics::new("eth0");
            metrics.publish(&optic());
            metrics.publish(&optic());
            metrics.publish(&cable());
        });

        let mut series = info(&scrape);
        series.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            series,
            [
                ("C2606276848".to_string(), 0.0),
                ("WTN11Q51001".to_string(), 1.0),
            ]
        );
        // The cable has no lanes, so the optic's lane gauges go blank rather than keep its values.
        assert!(
            get(&scrape, "tx_power_watts", &[("lane", "1")])
                .unwrap()
                .is_nan()
        );
    }
}
