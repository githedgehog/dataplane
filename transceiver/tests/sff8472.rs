// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Decode synthetic SFF-8472 memory, built field by field at the specification's offsets.
//!
//! No SFP capture is available yet, so these modules are written by hand: a 10GBASE-SR SFP+ with
//! internal calibration, the same module externally calibrated with constants whose results are
//! worked out below from the formulas in SFF-8472 section 9.3, and a passive copper cable.

#![allow(clippy::unwrap_used, clippy::float_cmp, clippy::panic)]

use dataplane_transceiver::sff8472::{CableKind, Calibration, Links, SignalingRate, Status};
use dataplane_transceiver::{
    Block, Bounds, Capture, Crossings, Current, Detail, Eeprom, HALF, I2cAddress, Image, Length,
    Module, Power, Reach, Region, RxPowerKind, Temperature, Voltage, read,
};

/// An SFP's memory, remembering what was asked for.
#[derive(Debug, Clone)]
struct Sfp {
    a0: Block,
    a0_upper: Block,
    a2: Block,
    asked: Vec<Region>,
}

#[derive(Debug)]
struct NoSuchRegion;

impl Eeprom for Sfp {
    type Error = NoSuchRegion;

    fn read(&mut self, region: Region) -> Result<Block, NoSuchRegion> {
        self.asked.push(region);
        match region {
            Region::Lower(I2cAddress::A0) => Ok(self.a0),
            Region::Lower(I2cAddress::A2) => Ok(self.a2),
            r if r == Region::upper(0) => Ok(self.a0_upper),
            Region::Upper { .. } => Err(NoSuchRegion),
        }
    }
}

fn put(block: &mut Block, at: usize, bytes: &[u8]) {
    block[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put_u16(block: &mut Block, at: usize, value: u16) {
    put(block, at, &value.to_be_bytes());
}

fn put_i16(block: &mut Block, at: usize, value: i16) {
    put(block, at, &value.to_be_bytes());
}

fn put_f32(block: &mut Block, at: usize, value: f32) {
    put(block, at, &value.to_be_bytes());
}

/// A space-padded ASCII field.
fn put_text(block: &mut Block, at: usize, len: usize, text: &str) {
    let mut field = vec![b' '; len];
    field[..text.len()].copy_from_slice(text.as_bytes());
    put(block, at, &field);
}

/// Four thresholds in Table 9-5 order: high alarm, low alarm, high warning, low warning.
fn put_bounds(block: &mut Block, at: usize, values: [u16; 4]) {
    for (i, value) in values.into_iter().enumerate() {
        put_u16(block, at + 2 * i, value);
    }
}

impl Sfp {
    /// A 10GBASE-SR SFP+, internally calibrated, with every soft status and flag implemented.
    fn sr() -> Self {
        let mut a0 = [0u8; HALF];
        a0[0] = 0x03; // SFP
        a0[1] = 0x04;
        a0[2] = 0x07; // LC
        a0[3] = 0x10; // 10GBASE-SR
        a0[11] = 0x06; // 64B/66B
        a0[12] = 103; // 10.3 GBd
        a0[16] = 8; // OM2, 80 m
        a0[17] = 3; // OM1, 30 m
        a0[18] = 15; // OM4, 150 m
        a0[19] = 30; // OM3, 300 m
        put_text(&mut a0, 20, 16, "FS");
        a0[36] = 0x00;
        put(&mut a0, 37, &[0x00, 0x90, 0x65]);
        put_text(&mut a0, 40, 16, "SFP-10GSR-85");
        put_text(&mut a0, 56, 4, "A");
        put_u16(&mut a0, 60, 850);
        // TX_DISABLE, TX_FAULT and standard LOS implemented (Table 8-3)
        put(&mut a0, 64, &[0x00, 0x1a]);
        put_text(&mut a0, 68, 16, "F2030512345");
        put_text(&mut a0, 84, 8, "230115");
        a0[92] = 0x68; // DDM, internally calibrated, average power
        a0[93] = 0xf0; // A/W flags, soft TX_DISABLE, TX_FAULT, RX_LOS
        a0[94] = 0x08; // rev 12.3

        let mut a2 = [0u8; HALF];
        put_bounds(&mut a2, 0, [0x4b00, 0xfb00, 0x4600, 0x0000]); // 75, -5, 70, 0 C
        put_bounds(&mut a2, 8, [36_300, 29_700, 34_650, 31_350]);
        put_bounds(&mut a2, 16, [6_000, 1_000, 5_500, 1_500]);
        put_bounds(&mut a2, 24, [10_000, 1_000, 7_943, 1_259]);
        put_bounds(&mut a2, 32, [10_000, 50, 7_943, 100]);
        put_i16(&mut a2, 96, 0x2780); // 39.5 C
        put_u16(&mut a2, 98, 32_874);
        put_u16(&mut a2, 100, 3_427);
        put_u16(&mut a2, 102, 5_012);
        put_u16(&mut a2, 104, 4_000);
        a2[110] = 0b0100_0010; // soft TX disable selected, RX_LOS, data ready
        a2[112] = 0b0000_0010; // TX power high alarm
        a2[113] = 0b0100_0000; // RX power low alarm
        a2[116] = 0b1000_0000; // temperature high warning
        a2[117] = 0b0100_0000; // RX power low warning

        Self {
            a0,
            a0_upper: [0; HALF],
            a2,
            asked: Vec::new(),
        }
    }

    /// The same module externally calibrated, with no optional flags or soft status.
    ///
    /// Expected values, each `slope * AD + offset` rounded to the nearest unit (section 9.3):
    ///
    /// | quantity    | slope         | offset | AD      | result              |
    /// |-------------|---------------|--------|---------|---------------------|
    /// | temperature | 1.5           | -512   | 6656    | 9472 = 37.0 C       |
    /// | supply      | 0.5           | 100    | 65000   | 32600 = 3.26 V      |
    /// | bias        | 2.00390625    | -10    | 1700    | 3396.64 x 2 uA = 6793 uA |
    /// | tx power    | 0.75          | 3      | 6000    | 4503 = 0.4503 mW    |
    ///
    /// Receive power is `2^-48 * -AD^4 + 2^-32 * AD^3 + 2^-16 * AD^2 + 0.5 * AD + 2`; at AD 2000
    /// that is -0.0568 + 1.8626 + 61.0352 + 1000 + 2 = 1064.84, so 1065 = 0.1065 mW.
    fn externally_calibrated() -> Self {
        let mut sfp = Self::sr();
        sfp.a0[92] = 0x58; // DDM, externally calibrated, average power
        sfp.a0[93] = 0x00;
        let a2 = &mut sfp.a2;
        put_f32(a2, 56, -(2f32.powi(-48))); // Rx_PWR(4)
        put_f32(a2, 60, 2f32.powi(-32)); // Rx_PWR(3)
        put_f32(a2, 64, 2f32.powi(-16)); // Rx_PWR(2)
        put_f32(a2, 68, 0.5); // Rx_PWR(1)
        put_f32(a2, 72, 2.0); // Rx_PWR(0)
        put(a2, 76, &[0x02, 0x01, 0xff, 0xf6]); // bias: 2 + 1/256, -10
        put(a2, 80, &[0x00, 0xc0, 0x00, 0x03]); // tx power: 0.75, 3
        put(a2, 84, &[0x01, 0x80, 0xfe, 0x00]); // temperature: 1.5, -512
        put(a2, 88, &[0x00, 0x80, 0x00, 0x64]); // supply: 0.5, 100

        // Thresholds, calibrated like readings (section 9.3):
        // temperature 12288, -2560, 11264, 0 -> 17920, -4352, 16384, -512 = 70, -17, 64, -2 C
        put_bounds(a2, 0, [0x3000, 0xf600, 0x2c00, 0x0000]);
        // supply 65535 -> 32867.5, rounded away from zero to 32868; 58000, 64000, 60000 ->
        // 29100, 32100, 30100
        put_bounds(a2, 8, [65_535, 58_000, 64_000, 60_000]);
        // bias 6000, 0, 5000, 500 -> 2 uA x (12013.44, -10, 10009.53, 991.95) -> 24027,
        // 0 (saturated), 20019, 1984 uA
        put_bounds(a2, 16, [6_000, 0, 5_000, 500]);
        // tx power 65535, 100, 40000, 1000 -> 49154.25, 78, 30003, 753
        put_bounds(a2, 24, [65_535, 100, 40_000, 1_000]);
        // rx power 65535, 10, 8000, 20 -> 98304.5 (saturates at 65535), 7.0, 5083.2, 12.0
        put_bounds(a2, 32, [65_535, 10, 8_000, 20]);

        put_i16(a2, 96, 6_656);
        put_u16(a2, 98, 65_000);
        put_u16(a2, 100, 1_700);
        put_u16(a2, 102, 6_000);
        put_u16(a2, 104, 2_000);
        sfp
    }

    /// A 3 m passive direct attach copper cable.
    fn passive_copper() -> Self {
        let mut sfp = Self::sr();
        let a0 = &mut sfp.a0;
        a0[2] = 0x21; // copper pigtail
        a0[3] = 0x00;
        a0[8] = 0x04; // passive cable
        a0[12] = 0xff;
        a0[66] = 103; // 25.75 GBd
        a0[14] = 0;
        a0[15] = 9; // 9 dB at 25.78 GHz
        a0[16] = 0;
        a0[17] = 0;
        a0[18] = 3; // 3 m
        a0[19] = 0b00_011110; // 30 x 0.1 m
        put_u16(a0, 60, 0x0100); // SFF-8431 Appendix E
        a0[92] = 0x00; // no diagnostics
        a0[93] = 0x00;
        sfp
    }

    fn read(&mut self) -> Module {
        read(self, Capture::new()).unwrap().0
    }
}

fn sff8472(module: &Module) -> &dataplane_transceiver::sff8472::Detail {
    let Detail::Sff8472(detail) = &module.detail else {
        panic!("not decoded as SFF-8472")
    };
    detail
}

#[test]
fn an_sr_module_decodes() {
    let module = Sfp::sr().read();
    assert_eq!(module.identifier.raw(), 0x03);

    let inventory = &module.inventory;
    assert_eq!(inventory.vendor, "FS");
    assert_eq!(inventory.oui, [0x00, 0x90, 0x65]);
    assert_eq!(inventory.part_number, "SFP-10GSR-85");
    assert_eq!(inventory.revision, "A");
    assert_eq!(inventory.serial_number, "F2030512345");
    assert_eq!(inventory.date_code, "230115");
    assert_eq!(inventory.connector.raw(), 0x07);
    assert_eq!(inventory.wavelength.unwrap().nanometres(), 850.0);

    let monitors = &module.monitors;
    assert_eq!(monitors.temperature.unwrap().celsius(), 39.5);
    assert_eq!(monitors.supply, Some(Voltage::from_raw(32_874)));
    assert_eq!(monitors.rx_power_kind, RxPowerKind::Average);
    assert_eq!(monitors.lanes.len(), 1);
    let lane = monitors.lanes[0];
    assert_eq!(lane.tx_bias.unwrap().microamps(), 6_854);
    assert_eq!(lane.tx_power, Some(Power::from_raw(5_012)));
    assert_eq!(lane.rx_power, Some(Power::from_raw(4_000)));

    let thresholds = module.thresholds.unwrap();
    let temperature = thresholds.temperature.unwrap();
    assert_eq!(temperature.high_alarm.celsius(), 75.0);
    assert_eq!(temperature.low_alarm.celsius(), -5.0);
    assert_eq!(temperature.high_warning.celsius(), 70.0);
    assert_eq!(temperature.low_warning.celsius(), 0.0);
    assert_eq!(
        thresholds.supply,
        Some(Bounds {
            high_alarm: Voltage::from_raw(36_300),
            low_alarm: Voltage::from_raw(29_700),
            high_warning: Voltage::from_raw(34_650),
            low_warning: Voltage::from_raw(31_350),
        })
    );
    assert_eq!(thresholds.tx_bias.unwrap().high_alarm.milliamps(), 12.0);
    assert_eq!(thresholds.tx_bias.unwrap().low_warning.milliamps(), 3.0);
    assert_eq!(
        thresholds.tx_power.unwrap().high_warning,
        Power::from_raw(7_943)
    );
    assert_eq!(thresholds.rx_power.unwrap().low_alarm, Power::from_raw(50));

    let flags = module.flags.as_ref().unwrap();
    assert_eq!(
        flags.temperature,
        Crossings {
            high_warning: true,
            ..Crossings::default()
        }
    );
    assert!(!flags.supply.any());
    assert_eq!(flags.lanes.len(), 1);
    let lane = flags.lanes[0];
    assert_eq!(lane.tx_fault, Some(false));
    assert_eq!(lane.rx_los, Some(true));
    assert_eq!((lane.tx_los, lane.tx_lol, lane.rx_lol), (None, None, None));
    assert!(!lane.tx_bias.any());
    assert_eq!(
        lane.tx_power,
        Crossings {
            high_alarm: true,
            ..Crossings::default()
        }
    );
    assert_eq!(
        lane.rx_power,
        Crossings {
            low_alarm: true,
            low_warning: true,
            ..Crossings::default()
        }
    );

    let detail = sff8472(&module);
    assert_eq!(detail.compliance, [0x10, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(detail.encoding, 0x06);
    assert_eq!(
        detail.nominal_rate,
        Some(SignalingRate::from_megabaud(10_300))
    );
    let Links::Optical(links) = detail.links else {
        panic!("an SR module is optical")
    };
    assert_eq!(links.single_mode_km, None);
    assert_eq!(links.single_mode, None);
    assert_eq!(links.om2, Some(Reach::UpTo(Length::from_decimetres(800))));
    assert_eq!(links.om1, Some(Reach::UpTo(Length::from_decimetres(300))));
    assert_eq!(links.om4.map(|_| ()), Some(()));
    assert_eq!(links.om3, Some(Reach::UpTo(Length::from_decimetres(3_000))));
    assert_eq!(detail.options, 0x001a);
    assert!(detail.diagnostics.implemented);
    assert_eq!(detail.diagnostics.calibration, Calibration::Internal);
    assert!(!detail.diagnostics.address_change_required);
    assert!(detail.enhanced_options.alarm_warning_flags);
    assert!(detail.enhanced_options.soft_rx_los);
    assert_eq!(detail.compliance_revision.revision(), Some("12.3"));
    assert_eq!(
        detail.status,
        Some(Status {
            tx_disable: Some(false),
            soft_tx_disable: Some(true),
            tx_fault: Some(false),
            rx_los: Some(true),
            data_ready: true,
        })
    );
}

#[test]
fn external_calibration_applies_the_constants() {
    let module = Sfp::externally_calibrated().read();
    let monitors = &module.monitors;
    assert_eq!(monitors.temperature, Some(Temperature::from_raw(9_472)));
    assert_eq!(monitors.temperature.unwrap().celsius(), 37.0);
    assert_eq!(monitors.supply, Some(Voltage::from_raw(32_600)));
    let lane = monitors.lanes[0];
    assert_eq!(lane.tx_bias, Some(Current::from_microamps(6_793)));
    assert_eq!(lane.tx_power, Some(Power::from_raw(4_503)));
    assert_eq!(lane.rx_power, Some(Power::from_raw(1_065)));

    let thresholds = module.thresholds.unwrap();
    let celsius = thresholds.temperature.unwrap();
    assert_eq!(
        [
            celsius.high_alarm,
            celsius.low_alarm,
            celsius.high_warning,
            celsius.low_warning
        ]
        .map(Temperature::celsius),
        [70.0, -17.0, 64.0, -2.0]
    );
    assert_eq!(
        thresholds.supply.unwrap(),
        Bounds {
            high_alarm: Voltage::from_raw(32_868),
            low_alarm: Voltage::from_raw(29_100),
            high_warning: Voltage::from_raw(32_100),
            low_warning: Voltage::from_raw(30_100),
        }
    );
    assert_eq!(
        thresholds.tx_bias.unwrap(),
        Bounds {
            high_alarm: Current::from_microamps(24_027),
            low_alarm: Current::from_microamps(0),
            high_warning: Current::from_microamps(20_019),
            low_warning: Current::from_microamps(1_984),
        }
    );
    assert_eq!(
        thresholds.tx_power.unwrap(),
        Bounds {
            high_alarm: Power::from_raw(49_154),
            low_alarm: Power::from_raw(78),
            high_warning: Power::from_raw(30_003),
            low_warning: Power::from_raw(753),
        }
    );
    assert_eq!(
        thresholds.rx_power.unwrap(),
        Bounds {
            high_alarm: Power::from_raw(u16::MAX),
            low_alarm: Power::from_raw(7),
            high_warning: Power::from_raw(5_083),
            low_warning: Power::from_raw(12),
        }
    );

    let detail = sff8472(&module);
    assert_eq!(detail.diagnostics.calibration, Calibration::External);
    // No flags and no soft status advertised (A0h:93 = 0).
    assert_eq!(module.flags, None);
    assert_eq!(
        detail.status,
        Some(Status {
            tx_disable: None,
            soft_tx_disable: None,
            tx_fault: None,
            rx_los: None,
            data_ready: true,
        })
    );
}

#[test]
fn non_finite_rx_power_constants_leave_rx_power_unknown() {
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut sfp = Sfp::externally_calibrated();
        put_f32(&mut sfp.a2, 64, bad); // Rx_PWR(2)
        let module = sfp.read();
        let lane = module.monitors.lanes[0];
        assert_eq!(lane.rx_power, None, "{bad}");
        assert_eq!(module.thresholds.unwrap().rx_power, None, "{bad}");
        // Everything else is calibrated as before.
        assert_eq!(lane.tx_power, Some(Power::from_raw(4_503)));
        assert_eq!(
            module.monitors.temperature,
            Some(Temperature::from_raw(9_472))
        );
    }
}

#[test]
fn a_module_with_diagnostics_is_read_in_full() {
    let mut sfp = Sfp::sr();
    sfp.read();
    assert_eq!(
        sfp.asked,
        [Region::Lower(I2cAddress::A0), Region::Lower(I2cAddress::A2),]
    );
}

fn without_diagnostics(sfp: &mut Sfp) {
    let module = sfp.read();
    assert_eq!(
        sfp.asked,
        [Region::Lower(I2cAddress::A0)],
        "A2h must not be read"
    );
    assert_eq!(module.monitors.temperature, None);
    assert_eq!(module.monitors.supply, None);
    assert!(module.monitors.lanes.is_empty());
    assert_eq!(module.thresholds, None);
    assert_eq!(module.flags, None);
    assert_eq!(sff8472(&module).status, None);
    assert_eq!(module.inventory.part_number, "SFP-10GSR-85");
}

#[test]
fn a_module_without_diagnostics_is_not_asked_for_them() {
    let mut sfp = Sfp::sr();
    sfp.a0[92] &= !0x40; // A0h:92.6
    without_diagnostics(&mut sfp);
}

#[test]
fn a_module_needing_an_address_change_is_not_asked_for_diagnostics() {
    let mut sfp = Sfp::sr();
    sfp.a0[92] |= 0x04; // A0h:92.2
    without_diagnostics(&mut sfp);
    let module = sfp.read();
    assert!(sff8472(&module).diagnostics.address_change_required);
}

#[test]
fn unreadable_diagnostics_still_decode() {
    let sfp = Sfp::sr();
    let mut capture = Capture::new();
    while let Some(region) = capture.next_region() {
        match region {
            Region::Lower(I2cAddress::A0) => capture.provide(region, sfp.a0),
            Region::Lower(I2cAddress::A2) => capture.unreadable(region),
            _ => capture.provide(region, sfp.a0_upper),
        }
    }
    let (module, _) = capture.finish().unwrap();
    assert!(module.monitors.lanes.is_empty());
    assert_eq!(module.thresholds, None);
    assert_eq!(module.flags, None);
}

#[test]
fn a_refresh_reads_only_the_diagnostics() {
    let mut sfp = Sfp::sr();
    let (first, image) = read(&mut sfp, Capture::new()).unwrap();
    sfp.asked.clear();
    let (second, image) = read(&mut sfp, Capture::refresh(image)).unwrap();
    assert_eq!(sfp.asked, [Region::Lower(I2cAddress::A2)]);
    assert_eq!(first, second);

    put_i16(&mut sfp.a2, 96, 0x2900); // 41 C
    sfp.asked.clear();
    let (third, _) = read(&mut sfp, Capture::refresh(image)).unwrap();
    assert_eq!(sfp.asked, [Region::Lower(I2cAddress::A2)]);
    assert_eq!(third.monitors.temperature.unwrap().celsius(), 41.0);
}

#[test]
fn a_refresh_without_diagnostics_reads_nothing() {
    let mut sfp = Sfp::passive_copper();
    let (first, image) = read(&mut sfp, Capture::new()).unwrap();
    sfp.asked.clear();
    let (second, _) = read(&mut sfp, Capture::refresh(image)).unwrap();
    assert!(sfp.asked.is_empty());
    assert_eq!(first, second);
}

#[test]
fn a_copper_cable_has_no_wavelength() {
    let module = Sfp::passive_copper().read();
    assert_eq!(module.inventory.wavelength, None);
    let detail = sff8472(&module);
    assert_eq!(
        detail.nominal_rate,
        Some(SignalingRate::from_megabaud(25_750))
    );
    let Links::Cable(cable) = detail.links else {
        panic!("a DAC is a cable")
    };
    assert_eq!(cable.kind, CableKind::Passive);
    assert_eq!(cable.attenuation_12_9_ghz_db, None);
    assert_eq!(cable.attenuation_25_78_ghz_db, Some(9));
    assert_eq!(cable.length, Some(Reach::UpTo(Length::from_decimetres(30))));
    assert_eq!(cable.length_additional.unwrap().metres(), 3.0);
    assert_eq!(cable.compliance, 0x0100);
}

#[test]
fn long_reach_saturates() {
    let mut sfp = Sfp::sr();
    sfp.a0[14] = 0xff;
    sfp.a0[15] = 0xff;
    let module = sfp.read();
    let Links::Optical(links) = sff8472(&module).links else {
        panic!("optical")
    };
    assert_eq!(
        links.single_mode_km,
        Some(Reach::Beyond(Length::from_decimetres(2_540_000)))
    );
    assert_eq!(
        links.single_mode,
        Some(Reach::Beyond(Length::from_decimetres(254_000)))
    );
}

#[test]
fn an_inverted_los_pin_still_reports_loss_of_signal() {
    let mut sfp = Sfp::sr();
    sfp.a0[65] = 0x1c; // TX_DISABLE, TX_FAULT, inverted LOS ("signal detect")
    sfp.a2[110] = 0b0000_0010; // the pin is high: signal detected
    let module = sfp.read();
    assert_eq!(module.flags.unwrap().lanes[0].rx_los, Some(false));
}

fn block(bytes: &[u8]) -> Block {
    let mut block = [0u8; HALF];
    for (to, from) in block.iter_mut().zip(bytes) {
        *to = *from;
    }
    block
}

fn image(a0: Block, a2: Block) -> Image {
    let mut image = Image::new();
    image.insert(Region::Lower(I2cAddress::A0), a0);
    image.insert(Region::Lower(I2cAddress::A2), a2);
    image
}

#[test]
fn unit_slope_and_zero_offset_change_nothing() {
    // Table 9-6 gives the constants an internally calibrated module should carry: slopes of 1,
    // offsets of 0, Rx_PWR(1) of 1 and the other Rx_PWR coefficients 0. Applying them to any
    // reading must give the reading back.
    bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
        let a2 = block(bytes);
        let internal = Sfp::sr().a0;
        let mut external = internal;
        external[92] = (external[92] & !0x20) | 0x10;
        let mut calibrated = a2;
        for at in [56, 60, 64, 72] {
            put_f32(&mut calibrated, at, 0.0);
        }
        put_f32(&mut calibrated, 68, 1.0);
        for at in [76, 80, 84, 88] {
            put(&mut calibrated, at, &[0x01, 0x00, 0x00, 0x00]);
        }
        let ours = dataplane_transceiver::decode(&image(internal, a2)).unwrap();
        let theirs = dataplane_transceiver::decode(&image(external, calibrated)).unwrap();
        assert_eq!(ours.monitors, theirs.monitors);
        assert_eq!(ours.thresholds, theirs.thresholds);
    });
}

#[test]
fn sff8472_arbitrary_memory_never_panics() {
    bolero::check!()
        .with_type::<(Vec<u8>, Vec<u8>, u8)>()
        .for_each(|(a0, a2, poison)| {
            let mut a0 = block(a0);
            a0[0] = 0x03; // keep it SFF-8472
            let mut a2 = block(a2);
            // Arbitrary bytes rarely spell a non-finite float, so plant some on purpose.
            let poisons = [
                f32::NAN,
                f32::INFINITY,
                f32::NEG_INFINITY,
                f32::MAX,
                f32::MIN,
            ];
            if let Some(value) = poisons.get(usize::from(poison & 0x0f)) {
                put_f32(&mut a2, 56 + 4 * usize::from((poison >> 4) % 5), *value);
            }
            let module = dataplane_transceiver::decode(&image(a0, a2)).unwrap();
            assert!(module.monitors.lanes.len() <= 1);
            if let Some(flags) = &module.flags {
                assert_eq!(flags.lanes.len(), 1);
            }
            let rx_finite = [56, 60, 64, 68, 72]
                .iter()
                .all(|at| f32::from_be_bytes(a2[*at..*at + 4].try_into().unwrap()).is_finite());
            let external = a0[92] & 0x10 != 0;
            if let Some(lane) = module.monitors.lanes.first() {
                assert_eq!(lane.rx_power.is_some(), rx_finite || !external);
            }
        });
}
