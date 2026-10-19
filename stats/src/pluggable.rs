// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Pluggable module (transceiver or cable) readings, one set per port.
//!
//! The names, labels and units follow the fabric agent's switch metrics (`fabric_agent_transceiver_*`),
//! so the same panels and alerts serve switch and gateway optics: every series is `transceiver_*`
//! with the configured interface name as the `transceiver` label, lane series add a `lane` label
//! numbered from 1 as the module specifications number lanes, optical power is in dBm, bias in mA,
//! temperature in degrees Celsius and supply in volts. Those are not Prometheus base units, which is
//! why the units are in the descriptions rather than the names.
//!
//! A reading the module does not implement, or every reading while no module answers, is `NaN`
//! rather than 0: dashboards show a gap instead of a plausible but false value. An optical power of
//! zero (no light at all) is `-Inf` dBm, as the fabric agent reports it, so that it is not mistaken
//! for the weakest light a module can measure (0.1 uW, -40 dBm).
//!
//! The module's alarm, warning and lane fault flags are published twice. The gauges say whether a
//! flag was set at the last poll. The `_readings_total` counters count the polls at which it was:
//! readings found out of tolerance, not the number of times a reading went out of tolerance. A
//! condition lasting across five polls adds five; two brief excursions between the same two polls
//! add one. Modules that latch their flags (SFF-8636, CMIS, and some SFF-8472) report anything since
//! the previous poll, so an excursion between polls is still counted once.

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;
use metrics::{Counter, Gauge, Unit};
use transceiver::{Bounds, Crossings, LaneFlags, LaneMonitors, Module, RxPowerKind};

/// Base id of the module metric family. Every series below is `{BASE}_{suffix}`.
pub(crate) const TRANSCEIVER_METRIC_BASE: &str = "transceiver";

/// The label naming the port the module is in, as the fabric agent names it.
const PORT_LABEL: &str = "transceiver";

/// The four limits of a monitored quantity, as label values of the flag series.
const LEVELS: [&str; 4] = ["high_alarm", "low_alarm", "high_warning", "low_warning"];

/// The four limits of a monitored quantity, as the fabric agent's threshold series name them, in
/// the order of [`LEVELS`].
const THRESHOLD_NAMES: [(&str, &str); 4] = [
    ("alarm", "hi"),
    ("alarm", "lo"),
    ("warning", "hi"),
    ("warning", "lo"),
];

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
    voltage: Gauge,
    temperature_flags: Flagged<4>,
    voltage_flags: Flagged<4>,
    thresholds: Thresholds,
    lanes: Vec<LaneGauges>,
}

/// The four limit gauges of each monitored quantity.
#[derive(Debug)]
struct Thresholds {
    temperature: [Gauge; 4],
    voltage: [Gauge; 4],
    bias: [Gauge; 4],
    out_power: [Gauge; 4],
    in_power: [Gauge; 4],
}

/// Flags as published: whether each was set at the last poll, and how many polls found it set.
#[derive(Debug)]
struct Flagged<const N: usize> {
    now: [Gauge; N],
    readings: [Counter; N],
}

#[derive(Debug)]
struct LaneGauges {
    bias: Gauge,
    out_power: Gauge,
    in_power: Gauge,
    bias_flags: Flagged<4>,
    out_power_flags: Flagged<4>,
    in_power_flags: Flagged<4>,
    faults: Flagged<5>,
}

fn spec(port: &str, suffix: &str, labels: &[(&str, &str)], description: &str) -> MetricSpec {
    let mut all = vec![(PORT_LABEL.to_string(), port.to_string())];
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
    spec
}

fn gauge(port: &str, suffix: &str, labels: &[(&str, &str)], description: &str) -> Gauge {
    let registered: Registered<Gauge> = spec(port, suffix, labels, description).register();
    registered.metric
}

fn counter(port: &str, suffix: &str, labels: &[(&str, &str)], description: &str) -> Counter {
    let registered: Registered<Counter> = spec(port, suffix, labels, description).register();
    registered.metric
}

const CROSSED: &str = "1 if the module flagged the reading beyond this limit at the last poll; \
     modules that latch flags report a crossing since the previous poll, so a brief excursion \
     between polls still shows";

const OUT_OF_TOLERANCE: &str = "polls at which the module flagged the reading beyond this limit: \
     readings out of tolerance, not excursions. A crossing lasting several polls counts once per \
     poll; several between two polls count once";

const LANE_FAULT: &str =
    "1 if the module flagged the lane condition at the last poll, NaN if it does not report it";

const LANE_FAULT_READINGS: &str = "polls at which the module flagged the lane condition: \
     readings, not occurrences. A condition lasting several polls counts once per poll; several \
     between two polls count once";

impl Flagged<4> {
    /// The flags of one quantity's four limits, labelled `level`, with any extra labels.
    fn limits(port: &str, labels: &[(&str, &str)]) -> Self {
        let with_level = |level: &'static str| {
            let mut labels = labels.to_vec();
            labels.push(("level", level));
            labels
        };
        Flagged {
            now: LEVELS.map(|level| gauge(port, "crossed", &with_level(level), CROSSED)),
            readings: LEVELS.map(|level| {
                counter(
                    port,
                    "out_of_tolerance_readings_total",
                    &with_level(level),
                    OUT_OF_TOLERANCE,
                )
            }),
        }
    }

    fn publish(&self, crossings: Option<Crossings>) {
        self.publish_flags(
            crossings.map(|c| [c.high_alarm, c.low_alarm, c.high_warning, c.low_warning].map(Some)),
        );
    }
}

impl<const N: usize> Flagged<N> {
    /// Publish each flag: [`None`] for the lot when nothing was read, and per flag when the module
    /// does not report it. Only a set flag counts a reading.
    fn publish_flags(&self, flags: Option<[Option<bool>; N]>) {
        let flags = flags.unwrap_or([None; N]);
        for ((gauge, readings), flag) in self.now.iter().zip(&self.readings).zip(flags) {
            set(gauge, flag.map(f64::from));
            if flag == Some(true) {
                readings.increment(1);
            }
        }
    }
}

impl Thresholds {
    fn new(port: &str) -> Self {
        // The fabric agent's names: `transceiver_alarm_rx_power_hi` and so on.
        let limit = |quantity: &str, unit: &str| {
            THRESHOLD_NAMES.map(|(kind, side)| {
                gauge(
                    port,
                    &format!("{kind}_{quantity}_{side}"),
                    &[],
                    &format!("the {quantity} {kind} limit on the {side} side, in {unit}"),
                )
            })
        };
        Thresholds {
            temperature: limit("temp", "degrees Celsius"),
            voltage: limit("volt", "volts"),
            bias: limit("tx_bias", "mA"),
            out_power: limit("tx_power", "dBm"),
            in_power: limit("rx_power", "dBm"),
        }
    }
}

impl LaneGauges {
    fn new(port: &str, lane: usize) -> Self {
        let lane = (lane + 1).to_string();
        let lane = lane.as_str();
        let labels = [("lane", lane)];
        LaneGauges {
            bias: gauge(port, "bias", &labels, "laser bias current, in mA"),
            out_power: gauge(
                port,
                "out_power",
                &labels,
                "transmitted optical power, in dBm; -Inf for no light",
            ),
            in_power: gauge(
                port,
                "in_power",
                &labels,
                "received optical power, in dBm; -Inf for no light; average or OMA, as \
                 transceiver_info's rx_power says",
            ),
            bias_flags: Flagged::limits(port, &[("lane", lane), ("quantity", "tx_bias")]),
            out_power_flags: Flagged::limits(port, &[("lane", lane), ("quantity", "tx_power")]),
            in_power_flags: Flagged::limits(port, &[("lane", lane), ("quantity", "rx_power")]),
            faults: Flagged {
                now: FAULTS.map(|fault| {
                    gauge(
                        port,
                        "lane_fault",
                        &[("lane", lane), ("fault", fault)],
                        LANE_FAULT,
                    )
                }),
                readings: FAULTS.map(|fault| {
                    counter(
                        port,
                        "lane_fault_readings_total",
                        &[("lane", lane), ("fault", fault)],
                        LANE_FAULT_READINGS,
                    )
                }),
            },
        }
    }

    fn publish(&self, readings: Option<&LaneMonitors>, flags: Option<&LaneFlags>) {
        let readings = readings.copied().unwrap_or_default();
        set(&self.bias, readings.tx_bias.map(|c| c.milliamps()));
        set(&self.out_power, readings.tx_power.map(|p| p.dbm()));
        set(&self.in_power, readings.rx_power.map(|p| p.dbm()));
        self.bias_flags.publish(flags.map(|f| f.tx_bias));
        self.out_power_flags.publish(flags.map(|f| f.tx_power));
        self.in_power_flags.publish(flags.map(|f| f.rx_power));
        self.faults
            .publish_flags(flags.map(|f| [f.tx_fault, f.tx_los, f.tx_lol, f.rx_los, f.rx_lol]));
    }
}

fn set(gauge: &Gauge, value: Option<f64>) {
    gauge.set(value.unwrap_or(f64::NAN));
}

fn limits<T: Copy>(gauges: &[Gauge; 4], bounds: Option<Bounds<T>>, value: impl Fn(T) -> f64) {
    let values = bounds.map(|b| [b.high_alarm, b.low_alarm, b.high_warning, b.low_warning]);
    for (i, gauge) in gauges.iter().enumerate() {
        set(gauge, values.map(|v| value(v[i])));
    }
}

impl TransceiverMetrics {
    /// Register a port's gauges, using the configured interface name as the `transceiver` label.
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
            temperature: gauge(
                port,
                "temperature",
                &[],
                "module case temperature, in degrees Celsius",
            ),
            voltage: gauge(port, "voltage", &[], "module supply voltage, in volts"),
            temperature_flags: Flagged::limits(port, &[("quantity", "temperature")]),
            voltage_flags: Flagged::limits(port, &[("quantity", "supply")]),
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
        set(&self.voltage, monitors.supply.map(|v| v.volts()));
        let flags = module.flags.as_ref();
        self.temperature_flags.publish(flags.map(|f| f.temperature));
        self.voltage_flags.publish(flags.map(|f| f.supply));

        let thresholds = module.thresholds.unwrap_or_default();
        limits(&self.thresholds.temperature, thresholds.temperature, |t| {
            t.celsius()
        });
        limits(&self.thresholds.voltage, thresholds.supply, |v| v.volts());
        limits(&self.thresholds.bias, thresholds.tx_bias, |c| c.milliamps());
        limits(&self.thresholds.out_power, thresholds.tx_power, |p| p.dbm());
        limits(&self.thresholds.in_power, thresholds.rx_power, |p| p.dbm());

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
        for gauge in [&self.temperature, &self.voltage] {
            gauge.set(f64::NAN);
        }
        self.temperature_flags.publish(None);
        self.voltage_flags.publish(None);
        for gauges in [
            &self.thresholds.temperature,
            &self.thresholds.voltage,
            &self.thresholds.bias,
            &self.thresholds.out_power,
            &self.thresholds.in_power,
        ] {
            for gauge in gauges {
                gauge.set(f64::NAN);
            }
        }
        for lane in &self.lanes {
            lane.publish(None, None);
        }
    }

    /// `transceiver_info` carries the module's identity in its labels and the value 1, with the
    /// fabric agent's label names where it has the same fact. A module swap changes the labels, so
    /// the old series is set to 0 rather than left claiming the module is still there; an unchanged
    /// module keeps its series untouched.
    fn publish_info(&mut self, module: Option<&Module>) {
        let identity = module.map(|module| {
            let inventory = &module.inventory;
            let rx_power = match module.monitors.rx_power_kind {
                RxPowerKind::Average => "average",
                RxPowerKind::Oma => "oma",
            };
            let [a, b, c] = inventory.oui;
            let (firmware, cmis_rev) = match &module.detail {
                transceiver::Detail::Cmis(cmis) => (
                    format!("{}.{}", cmis.firmware.major, cmis.firmware.minor),
                    format!("{}.{}", cmis.revision.major, cmis.revision.minor),
                ),
                _ => (String::new(), String::new()),
            };
            vec![
                module.identifier.name().to_string(),
                inventory.vendor.clone(),
                inventory.part_number.clone(),
                inventory.serial_number.clone(),
                inventory.revision.clone(),
                format!("{a:02x}:{b:02x}:{c:02x}"),
                firmware,
                inventory.connector.name().to_string(),
                cmis_rev,
                rx_power.to_string(),
            ]
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
            "form_factor",
            "vendor",
            "vendor_part",
            "serial",
            "vendor_rev",
            "vendor_oui",
            "firmware",
            "conn_type",
            "cmis_rev",
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

    /// The crate's directory, read at run time rather than with `env!`: test archives built in the
    /// nix sandbox run on the host, where the build path does not exist. nextest's
    /// `--workspace-remap` (and plain `cargo test`) set it to where the sources are.
    fn manifest_dir() -> String {
        std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string())
    }

    /// A module captured in the lab, decoded.
    fn captured(dir: &str, regions: &[(Region, &str)]) -> Module {
        let mut image = Image::new();
        for (region, file) in regions {
            let path = format!(
                "{}/../transceiver/tests/fixtures/{dir}/{file}",
                manifest_dir()
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
        let mut all = vec![(PORT_LABEL, "eth0")];
        all.extend_from_slice(labels);
        scrape.get(&format!("{TRANSCEIVER_METRIC_BASE}_{suffix}"), &all)
    }

    /// dBm comes from `log10`, which is not exact: Miri deliberately varies it from call to call,
    /// so a value computed here may differ from the published one in the last bits.
    #[track_caller]
    fn assert_close(published: Option<f64>, expected: f64) {
        let published = published.expect("published");
        assert!(
            (published - expected).abs() <= 1e-9 * expected.abs().max(1.0),
            "dBm: published {published}, expected {expected}"
        );
    }

    fn info(scrape: &Scrape) -> Vec<(String, f64)> {
        scrape
            .series(&format!("{TRANSCEIVER_METRIC_BASE}_info"))
            .into_iter()
            .map(|(labels, value)| (labels["serial"].clone(), value))
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
        assert_eq!(get(&scrape, "temperature", &[]), Some(temperature));
        for (i, lane) in module.monitors.lanes.iter().enumerate() {
            let lane_label = (i + 1).to_string();
            let labels = [("lane", lane_label.as_str())];
            let bias = lane.tx_bias.unwrap().milliamps();
            assert_eq!(get(&scrape, "bias", &labels), Some(bias), "mA");
            let rx = lane.rx_power.unwrap().dbm();
            assert_close(get(&scrape, "in_power", &labels), rx);
            let tx = lane.tx_power.unwrap().dbm();
            assert_close(get(&scrape, "out_power", &labels), tx);
            let crossed = [
                ("lane", lane_label.as_str()),
                ("quantity", "rx_power"),
                ("level", "high_alarm"),
            ];
            assert_eq!(get(&scrape, "crossed", &crossed), Some(0.0));
        }
        assert_eq!(get(&scrape, "bias", &[("lane", "5")]), None, "only 4 lanes");
        let high_alarm = module
            .thresholds
            .unwrap()
            .temperature
            .unwrap()
            .high_alarm
            .celsius();
        assert_eq!(get(&scrape, "alarm_temp_hi", &[]), Some(high_alarm));
        let rx_low_warning = module
            .thresholds
            .unwrap()
            .rx_power
            .unwrap()
            .low_warning
            .dbm();
        assert_close(get(&scrape, "warning_rx_power_lo", &[]), rx_low_warning);
    }

    #[test]
    fn a_cable_publishes_gaps_not_zeros() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            TransceiverMetrics::new("eth0").publish(&cable())
        });

        assert_eq!(get(&scrape, "present", &[]), Some(1.0));
        assert!(get(&scrape, "temperature", &[]).unwrap().is_nan());
        assert!(get(&scrape, "alarm_rx_power_lo", &[]).unwrap().is_nan());
        assert_eq!(get(&scrape, "bias", &[("lane", "1")]), None, "no lanes");
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
        assert!(get(&scrape, "temperature", &[]).unwrap().is_nan());
        assert!(get(&scrape, "in_power", &[("lane", "3")]).unwrap().is_nan());
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
            get(&scrape, "out_power", &[("lane", "1")])
                .unwrap()
                .is_nan()
        );
    }

    /// The optic with no light on lane 1's receiver, which raises its low power alarm and LOS.
    fn dark_lane_1() -> Module {
        let mut module = optic();
        module.monitors.lanes[0].rx_power = Some(transceiver::Power::from_raw(0));
        let flags = module.flags.as_mut().unwrap();
        flags.lanes[0].rx_power.low_alarm = true;
        flags.lanes[0].rx_los = Some(true);
        module
    }

    #[test]
    fn no_light_is_minus_infinity_not_a_gap() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            TransceiverMetrics::new("eth0").publish(&dark_lane_1());
        });
        assert_eq!(
            get(&scrape, "in_power", &[("lane", "1")]),
            Some(f64::NEG_INFINITY)
        );
        assert!(
            get(&scrape, "in_power", &[("lane", "2")])
                .unwrap()
                .is_finite()
        );
    }

    /// The counters count polls that found a flag set: three polls with the alarm up and one
    /// without make three, however long the condition actually lasted.
    #[test]
    fn readings_out_of_tolerance_count_polls_not_excursions() {
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            let mut metrics = TransceiverMetrics::new("eth0");
            for module in [dark_lane_1(), dark_lane_1(), optic(), dark_lane_1()] {
                metrics.publish(&module);
            }
            metrics.absent();
        });
        let counter = |suffix: &str, labels: &[(&str, &str)]| {
            let mut all = vec![(PORT_LABEL, "eth0")];
            all.extend_from_slice(labels);
            scrape.counter(&format!("{TRANSCEIVER_METRIC_BASE}_{suffix}"), &all)
        };
        let low_alarm = [
            ("lane", "1"),
            ("quantity", "rx_power"),
            ("level", "low_alarm"),
        ];
        assert_eq!(
            counter("out_of_tolerance_readings_total", &low_alarm),
            Some(3)
        );
        // The gauge says only what the last poll found: nothing, once the module is gone.
        assert!(get(&scrape, "crossed", &low_alarm).unwrap().is_nan());
        let los = [("lane", "1"), ("fault", "rx_los")];
        assert_eq!(counter("lane_fault_readings_total", &los), Some(3));
        let other_lane = [
            ("lane", "2"),
            ("quantity", "rx_power"),
            ("level", "low_alarm"),
        ];
        assert_eq!(
            counter("out_of_tolerance_readings_total", &other_lane),
            Some(0)
        );
    }
}
