// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Decode memory captured from real modules (see `fixtures/capture.sh`) and check the result
//! against what `ethtool --json -m` made of the same module at the same moment.

#![allow(clippy::unwrap_used, clippy::float_cmp)]

use std::path::{Path, PathBuf};

use dataplane_transceiver::{
    Block, Capture, Detail, Eeprom, HALF, I2cAddress, Image, Module, Region, RxPowerKind, read,
};
use serde_json::Value;

/// Module memory served from a fixture directory, remembering what was asked for.
struct Fixture {
    dir: PathBuf,
    asked: Vec<Region>,
}

#[derive(Debug)]
struct NotCaptured;

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        Self {
            dir,
            asked: Vec::new(),
        }
    }

    fn ethtool(&self) -> Value {
        let text = std::fs::read_to_string(self.dir.join("ethtool.json")).unwrap();
        let mut modules: Vec<Value> = serde_json::from_str(&text).unwrap();
        modules.remove(0)
    }
}

impl Eeprom for Fixture {
    type Error = NotCaptured;

    fn read(&mut self, region: Region) -> Result<Block, NotCaptured> {
        self.asked.push(region);
        let file = match region {
            Region::Lower(I2cAddress::A0) => "lower.bin".to_owned(),
            Region::Lower(I2cAddress::A2) => "a2-lower.bin".to_owned(),
            Region::Upper {
                address: I2cAddress::A0,
                bank: 0,
                page,
            } => format!("page-{page:02x}.bin"),
            Region::Upper { .. } => return Err(NotCaptured),
        };
        let bytes = std::fs::read(self.dir.join(file)).map_err(|_| NotCaptured)?;
        Block::try_from(bytes.as_slice()).map_err(|_| NotCaptured)
    }
}

fn number(value: &Value) -> f64 {
    value.as_f64().unwrap()
}

/// Whether `ours` rounds to what ethtool printed, which it does to 4 decimal places.
fn close(ours: f64, theirs: &Value) {
    let theirs = number(theirs);
    assert!((ours - theirs).abs() < 0.000_051, "{ours} != {theirs}");
}

/// Whether a live reading is near what ethtool read moments later; monitors drift between reads.
fn near(ours: f64, theirs: &Value) {
    let theirs = number(theirs);
    assert!(
        (ours - theirs).abs() <= theirs.abs() * 0.03 + 0.000_051,
        "{ours} !~ {theirs}"
    );
}

fn check_against_ethtool(module: &Module, ethtool: &Value) {
    let inventory = &module.inventory;
    assert_eq!(
        u64::from(module.identifier.raw()),
        ethtool["identifier"].as_u64().unwrap()
    );
    assert_eq!(inventory.vendor, ethtool["vendor_name"]);
    assert_eq!(inventory.part_number, ethtool["vendor_pn"]);
    assert_eq!(inventory.revision, ethtool["vendor_rev"]);
    assert_eq!(inventory.serial_number, ethtool["vendor_sn"]);
    assert!(
        inventory
            .date_code
            .starts_with(ethtool["date_code"].as_str().unwrap())
    );
    let oui: Vec<u64> = inventory.oui.iter().map(|b| u64::from(*b)).collect();
    assert_eq!(serde_json::to_value(oui).unwrap(), ethtool["vendor_oui"]);
    assert_eq!(
        u64::from(inventory.connector.raw()),
        ethtool["connector"].as_u64().unwrap()
    );
    close(
        inventory.wavelength.unwrap().nanometres(),
        &ethtool["laser_wavelength"],
    );

    let monitors = &module.monitors;
    near(
        monitors.temperature.unwrap().celsius(),
        &ethtool["module_temperature_measurement"],
    );
    near(
        monitors.supply.unwrap().volts(),
        &ethtool["module_voltage_measurement"],
    );
    assert_eq!(monitors.rx_power_kind, RxPowerKind::Average);
    for (lane, readings) in monitors.lanes.iter().enumerate() {
        near(
            readings.tx_bias.unwrap().milliamps(),
            &ethtool["laser_tx_bias_current"][lane],
        );
        near(
            readings.tx_power.unwrap().milliwatts(),
            &ethtool["transmit_avg_optical_power"][lane],
        );
        near(
            readings.rx_power.unwrap().milliwatts(),
            &ethtool["rx_power"]["values"][lane],
        );
    }

    let thresholds = module.thresholds.unwrap();
    let temperature = thresholds.temperature.unwrap();
    close(
        temperature.high_alarm.celsius(),
        &ethtool["module_temperature"]["high_alarm_threshold"],
    );
    close(
        temperature.low_warning.celsius(),
        &ethtool["module_temperature"]["low_warning_threshold"],
    );
    let supply = thresholds.supply.unwrap();
    close(
        supply.low_alarm.volts(),
        &ethtool["module_voltage"]["low_alarm_threshold"],
    );
    let bias = thresholds.tx_bias.unwrap();
    close(
        bias.high_warning.milliamps(),
        &ethtool["laser_bias_current"]["high_warning_threshold"],
    );
    let tx_power = thresholds.tx_power.unwrap();
    close(
        tx_power.low_alarm.milliwatts(),
        &ethtool["laser_output_power"]["low_alarm_threshold"],
    );
    let rx_power = thresholds.rx_power.unwrap();
    close(
        rx_power.high_alarm.milliwatts(),
        &ethtool["laser_rx_power"]["high_alarm_threshold"],
    );

    let flags = module.flags.as_ref().unwrap();
    for (lane, lane_flags) in flags.lanes.iter().enumerate() {
        assert_eq!(
            lane_flags.rx_los,
            ethtool["rx_loss_of_signal"][lane].as_bool()
        );
        assert_eq!(lane_flags.tx_fault, ethtool["tx_fault"][lane].as_bool());
        assert_eq!(
            lane_flags.rx_power.high_alarm,
            ethtool["laser_rx_power_high_alarm"][lane]
                .as_bool()
                .unwrap()
        );
    }
}

#[test]
fn qsfp112_matches_ethtool() {
    for name in ["qsfp112-sr4-fs-port0", "qsfp112-sr4-fs-port1"] {
        let mut fixture = Fixture::new(name);
        let (module, _) = read(&mut fixture, Capture::new()).unwrap();
        check_against_ethtool(&module, &fixture.ethtool());

        assert_eq!(
            module.monitors.lanes.len(),
            4,
            "{name}: byte 00h:210 leaves 4 lanes"
        );
        let Detail::Cmis(cmis) = &module.detail else {
            panic!("{name}: not decoded as CMIS")
        };
        assert!(!cmis.flat_memory);
        assert_eq!((cmis.revision.major, cmis.revision.minor), (5, 2));
        assert_eq!(cmis.power_class, 8);
        assert_eq!(cmis.max_power_milliwatts, 9_000);
        assert_eq!(cmis.media_type, 0x01, "multimode fibre");
        assert_eq!(cmis.data_path.len(), 4);
        assert!(!cmis.applications.is_empty());
        assert_eq!(cmis.applications[0].media_lanes, 4);
    }
}

#[test]
fn only_advertised_pages_are_read() {
    let mut fixture = Fixture::new("qsfp112-sr4-fs-port0");
    read(&mut fixture, Capture::new()).unwrap();
    // The module answers every page, so reading an unadvertised one would go unnoticed otherwise.
    assert_eq!(
        fixture.asked,
        [
            Region::Lower(I2cAddress::A0),
            Region::upper(0x00),
            Region::upper(0x01),
            Region::upper(0x02),
            Region::banked(0, 0x11),
        ]
    );
}

#[test]
fn a_refresh_reads_only_what_changes() {
    let mut fixture = Fixture::new("qsfp112-sr4-fs-port0");
    let (first, image) = read(&mut fixture, Capture::new()).unwrap();
    fixture.asked.clear();
    let (second, _) = read(&mut fixture, Capture::refresh(image)).unwrap();
    assert_eq!(
        fixture.asked,
        [Region::Lower(I2cAddress::A0), Region::banked(0, 0x11)]
    );
    assert_eq!(first, second);
}

#[test]
fn flat_memory_needs_only_page_zero() {
    let mut fixture = Fixture::new("qsfp112-sr4-fs-port0");
    let mut lower = fixture.read(Region::Lower(I2cAddress::A0)).unwrap();
    lower[2] |= 0x80; // 00h:2.7, flat memory
    let page00 = fixture.read(Region::upper(0x00)).unwrap();
    let mut capture = Capture::new();
    let mut asked = Vec::new();
    while let Some(region) = capture.next_region() {
        asked.push(region);
        match region {
            Region::Lower(I2cAddress::A0) => capture.provide(region, lower),
            Region::Upper { page: 0, .. } => capture.provide(region, page00),
            _ => capture.unreadable(region),
        }
    }
    assert_eq!(asked, [Region::Lower(I2cAddress::A0), Region::upper(0x00)]);
    let (module, _) = capture.finish().unwrap();
    assert!(module.monitors.lanes.is_empty());
    assert_eq!(module.monitors.temperature, None);
    assert_eq!(module.thresholds, None);
    assert_eq!(module.flags, None);
}

#[test]
fn arbitrary_memory_never_panics() {
    bolero::check!()
        .with_type::<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>()
        .for_each(|(lower, page00, page01, page02, page11)| {
            let block = |bytes: &Vec<u8>| {
                let mut block = [0u8; HALF];
                for (to, from) in block.iter_mut().zip(bytes) {
                    *to = *from;
                }
                block
            };
            let mut image = Image::new();
            let mut lower = block(lower);
            lower[0] = 0x1e; // keep it CMIS
            image.insert(Region::Lower(I2cAddress::A0), lower);
            image.insert(Region::upper(0x00), block(page00));
            image.insert(Region::upper(0x01), block(page01));
            image.insert(Region::upper(0x02), block(page02));
            for bank in 0..4 {
                image.insert(Region::banked(bank, 0x11), block(page11));
            }
            let module = dataplane_transceiver::decode(&image).unwrap();
            assert!(module.monitors.lanes.len() <= 32);
        });
}
