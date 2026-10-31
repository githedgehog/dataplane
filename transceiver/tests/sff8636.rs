// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Decode SFF-8636 memory built field by field at the specification's offsets.
//!
//! No QSFP28 was at hand to capture, so these modules are synthetic: a 100GBASE-SR4 optic with
//! paged memory and every monitor, and a flat memory passive copper cable.

#![allow(clippy::unwrap_used, clippy::panic)]

use dataplane_transceiver::sff8636::{self, TransmitterTechnology};
use dataplane_transceiver::{
    Block, Capture, Crossings, Detail, Eeprom, HALF, I2cAddress, Image, Module, Region,
    RxPowerKind, read,
};

/// Module memory laid out by spec byte number, remembering what was asked for.
#[derive(Debug, Clone)]
struct Memory {
    lower: Block,
    page00: Block,
    page03: Block,
    /// Whether page 03h answers; a flat module's does not.
    paged: bool,
    asked: Vec<Region>,
}

#[derive(Debug)]
struct NoSuchPage;

impl Memory {
    fn new(paged: bool) -> Self {
        Self {
            lower: [0; HALF],
            page00: [0; HALF],
            page03: [0; HALF],
            paged,
            asked: Vec::new(),
        }
    }

    fn lower(&mut self, at: u8, bytes: &[u8]) -> &mut Self {
        let at = usize::from(at);
        self.lower[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }

    fn page00(&mut self, at: u8, bytes: &[u8]) -> &mut Self {
        let at = usize::from(at) - HALF;
        self.page00[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }

    fn page03(&mut self, at: u8, bytes: &[u8]) -> &mut Self {
        let at = usize::from(at) - HALF;
        self.page03[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }

    /// A space-padded ASCII field on page 00h.
    fn text(&mut self, at: u8, len: u8, text: &str) -> &mut Self {
        let mut field = vec![b' '; usize::from(len)];
        field[..text.len()].copy_from_slice(text.as_bytes());
        self.page00(at, &field)
    }

    /// Four lanes of 16-bit lower memory values starting at `at`.
    fn lanes(&mut self, at: u8, values: [u16; 4]) -> &mut Self {
        for (lane, value) in (0u8..).zip(values) {
            self.lower(at + 2 * lane, &value.to_be_bytes());
        }
        self
    }

    /// High alarm, low alarm, high warning, low warning on page 03h starting at `at`.
    fn bounds(&mut self, at: u8, values: [u16; 4]) -> &mut Self {
        for (i, value) in (0u8..).zip(values) {
            self.page03(at + 2 * i, &value.to_be_bytes());
        }
        self
    }

    fn image(&self) -> Image {
        let mut image = Image::new();
        image.insert(Region::Lower(I2cAddress::A0), self.lower);
        image.insert(Region::upper(0x00), self.page00);
        if self.paged {
            image.insert(Region::upper(0x03), self.page03);
        }
        image
    }
}

impl Eeprom for Memory {
    type Error = NoSuchPage;

    fn read(&mut self, region: Region) -> Result<Block, NoSuchPage> {
        self.asked.push(region);
        match region {
            Region::Lower(I2cAddress::A0) => Ok(self.lower),
            Region::Upper {
                address: I2cAddress::A0,
                bank: 0,
                page: 0x00,
            } => Ok(self.page00),
            Region::Upper {
                address: I2cAddress::A0,
                bank: 0,
                page: 0x03,
            } if self.paged => Ok(self.page03),
            _ => Err(NoSuchPage),
        }
    }
}

const RX_POWER: [u16; 4] = [6_000, 6_100, 6_200, 6_300];
const TX_BIAS: [u16; 4] = [3_300, 3_400, 3_500, 3_600];
const TX_POWER: [u16; 4] = [7_000, 7_100, 7_200, 7_300];

/// A 100GBASE-SR4 QSFP28 with paged memory and every monitor.
fn sr4() -> Memory {
    let mut memory = Memory::new(true);
    memory
        // Identifier QSFP28, rev 2.8-2.10, paged and ready (0-2).
        .lower(0, &[0x11, 0x08, 0x00])
        // Latched flags, a different one on each lane (3-5, Table 6-5).
        .lower(3, &[0b1000_0001, 0b0000_0010, 0b1000_0100])
        // Temperature high warning, supply low alarm (6-7, Table 6-6).
        .lower(6, &[0b0010_0000, 0b0100_0000])
        // Rx1 power high alarm, Rx2 power low warning (9); Tx3 bias high warning (12); Tx4 power
        // low alarm (14) (Table 6-7).
        .lower(9, &[0b1000_0001, 0, 0, 0b0010_0000, 0, 0b0000_0100])
        // 35.5 C, 3.29 V (22-27).
        .lower(22, &[0x23, 0x80])
        .lower(26, &32_900u16.to_be_bytes())
        .lanes(34, RX_POWER)
        .lanes(42, TX_BIAS)
        .lanes(50, TX_POWER)
        // Lane 3's transmitter disabled (86); power override, classes 5-7 enabled (93).
        .lower(86, &[0b0000_0100])
        .lower(93, &[0b0000_0101])
        // 3.5 W (107).
        .lower(107, &[35])
        // Identifier; power class 5 with CDRs both ways; MPO 1x12 (128-130).
        .page00(128, &[0x11, 0b1100_1101, 0x0c])
        // Extended compliance in use (131); 64B/66B; above 25.4 GBd (139-140).
        .page00(131, &[0x80])
        .page00(139, &[0x06, 0xff])
        // 70 m of OM3, 100 m of OM4, 850 nm VCSEL (142-147).
        .page00(142, &[0, 35, 0, 0, 50, 0x00])
        .text(148, 16, "FS")
        .page00(165, &[0x64, 0x9d, 0x99])
        .text(168, 16, "QSFP28-SR4-100G")
        .text(184, 2, "A")
        // 850 nm, +/- 10 nm (186-189).
        .page00(186, &17_000u16.to_be_bytes())
        .page00(188, &2_000u16.to_be_bytes())
        // 100GBASE-SR4 (192, SFF-8024 Table 4-4).
        .page00(192, &[0x02])
        // CDR LOL flags; Tx disable, Tx fault and Tx LOS implemented (193-195).
        .page00(193, &[0x00, 0b0011_0000, 0b0001_1010])
        .text(196, 16, "F2130010001")
        .text(212, 8, "250817")
        // Temperature, supply, average rx power and tx power monitors; init complete flag; 103 x
        // 250 MBd (220-222).
        .page00(220, &[0b0011_1100, 0b0001_0000, 103])
        .bounds(128, [0x4b00, 0xfb00, 0x4600, 0x0000])
        .bounds(144, [36_300, 29_700, 34_650, 31_350])
        .bounds(176, [34_673, 513, 17_378, 1_288])
        .bounds(184, [6_000, 1_000, 5_500, 1_500])
        .bounds(192, [31_623, 1_259, 15_849, 2_512]);
    memory
}

/// A flat memory passive copper cable: no monitors, no thresholds, no wavelength.
fn dac() -> Memory {
    let mut memory = Memory::new(false);
    memory
        .lower(0, &[0x11, 0x08, 0b0000_0100])
        .page00(128, &[0x11, 0x00, 0x23])
        .page00(131, &[0x80])
        .page00(139, &[0x06, 0xff])
        // 20 dB at 25.78 GHz; 3 m; copper, unequalized (145-147).
        .page00(145, &[20, 3, 0xa0])
        .text(148, 16, "Mellanox")
        .text(168, 16, "MCP1600-C003")
        // 5, 8, 10 and 13 dB at 2.5, 5, 7 and 12.9 GHz (186-189).
        .page00(186, &[5, 8, 10, 13])
        // 100GBASE-CR4 (192).
        .page00(192, &[0x0b])
        .text(196, 16, "MT1234")
        .text(212, 8, "240102")
        .page00(222, &[103]);
    memory
}

fn sff8636(module: &Module) -> &sff8636::Detail {
    match &module.detail {
        Detail::Sff8636(detail) => detail,
        other => panic!("not decoded as SFF-8636: {other:?}"),
    }
}

#[test]
fn sr4_decodes_fully() {
    let mut memory = sr4();
    let (module, _) = read(&mut memory, Capture::new()).unwrap();

    assert_eq!(module.identifier.raw(), 0x11);
    let inventory = &module.inventory;
    assert_eq!(inventory.vendor, "FS");
    assert_eq!(inventory.oui, [0x64, 0x9d, 0x99]);
    assert_eq!(inventory.part_number, "QSFP28-SR4-100G");
    assert_eq!(inventory.revision, "A");
    assert_eq!(inventory.serial_number, "F2130010001");
    assert_eq!(inventory.date_code, "250817");
    assert_eq!(inventory.connector.raw(), 0x0c);
    assert_eq!(inventory.wavelength.unwrap().nanometres(), 850.0);

    let monitors = &module.monitors;
    assert_eq!(monitors.temperature.unwrap().celsius(), 35.5);
    assert_eq!(monitors.supply.unwrap().raw(), 32_900);
    assert_eq!(monitors.rx_power_kind, RxPowerKind::Average);
    assert_eq!(monitors.lanes.len(), 4);
    for (lane, readings) in monitors.lanes.iter().enumerate() {
        assert_eq!(readings.rx_power.unwrap().raw(), RX_POWER[lane]);
        assert_eq!(
            readings.tx_bias.unwrap().microamps(),
            u32::from(TX_BIAS[lane]) * 2
        );
        assert_eq!(readings.tx_power.unwrap().raw(), TX_POWER[lane]);
    }

    let thresholds = module.thresholds.unwrap();
    let temperature = thresholds.temperature.unwrap();
    assert_eq!(temperature.high_alarm.celsius(), 75.0);
    assert_eq!(temperature.low_alarm.celsius(), -5.0);
    assert_eq!(temperature.high_warning.celsius(), 70.0);
    assert_eq!(temperature.low_warning.celsius(), 0.0);
    let supply = thresholds.supply.unwrap();
    assert_eq!(
        [
            supply.high_alarm,
            supply.low_alarm,
            supply.high_warning,
            supply.low_warning
        ]
        .map(|v| v.raw()),
        [36_300, 29_700, 34_650, 31_350]
    );
    let rx = thresholds.rx_power.unwrap();
    assert_eq!(
        [rx.high_alarm, rx.low_alarm, rx.high_warning, rx.low_warning].map(|p| p.raw()),
        [34_673, 513, 17_378, 1_288]
    );
    let bias = thresholds.tx_bias.unwrap();
    assert_eq!(
        [
            bias.high_alarm,
            bias.low_alarm,
            bias.high_warning,
            bias.low_warning
        ]
        .map(|c| c.microamps()),
        [12_000, 2_000, 11_000, 3_000]
    );
    let tx = thresholds.tx_power.unwrap();
    assert_eq!(
        [tx.high_alarm, tx.low_alarm, tx.high_warning, tx.low_warning].map(|p| p.raw()),
        [31_623, 1_259, 15_849, 2_512]
    );

    let flags = module.flags.as_ref().unwrap();
    assert_eq!(
        flags.temperature,
        Crossings {
            high_warning: true,
            ..Crossings::default()
        }
    );
    assert_eq!(
        flags.supply,
        Crossings {
            low_alarm: true,
            ..Crossings::default()
        }
    );
    assert_eq!(flags.lanes.len(), 4);
    let rx_los: Vec<_> = flags.lanes.iter().map(|l| l.rx_los).collect();
    let tx_los: Vec<_> = flags.lanes.iter().map(|l| l.tx_los).collect();
    let tx_fault: Vec<_> = flags.lanes.iter().map(|l| l.tx_fault).collect();
    let rx_lol: Vec<_> = flags.lanes.iter().map(|l| l.rx_lol).collect();
    let tx_lol: Vec<_> = flags.lanes.iter().map(|l| l.tx_lol).collect();
    let no = Some(false);
    let yes = Some(true);
    assert_eq!(rx_los, [yes, no, no, no]);
    assert_eq!(tx_fault, [no, yes, no, no]);
    assert_eq!(rx_lol, [no, no, yes, no]);
    assert_eq!(tx_los, [no, no, no, yes]);
    assert_eq!(tx_lol, [no, no, no, yes]);
    let crossed: Vec<_> = flags
        .lanes
        .iter()
        .map(|l| (l.rx_power, l.tx_bias, l.tx_power))
        .collect();
    let none = Crossings::default();
    assert_eq!(
        crossed,
        [
            (
                Crossings {
                    high_alarm: true,
                    ..none
                },
                none,
                none
            ),
            (
                Crossings {
                    low_warning: true,
                    ..none
                },
                none,
                none
            ),
            (
                none,
                Crossings {
                    high_warning: true,
                    ..none
                },
                none
            ),
            (
                none,
                none,
                Crossings {
                    low_alarm: true,
                    ..none
                }
            ),
        ]
    );

    let detail = sff8636(&module);
    assert_eq!(detail.revision.raw(), 0x08);
    assert!(!detail.flat_memory);
    assert!(!detail.data_not_ready);
    assert_eq!(detail.extended_identifier.power_class(), 5);
    assert!(detail.extended_identifier.tx_cdr());
    assert!(detail.extended_identifier.rx_cdr());
    assert!(!detail.extended_identifier.clei_present());
    assert_eq!(detail.max_power_milliwatts, Some(3_500));
    assert_eq!(detail.compliance, [0x80, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(detail.extended_compliance, Some(0x02));
    assert_eq!(detail.encoding, 0x06);
    assert_eq!(detail.nominal_megabaud, Some(25_750));
    assert_eq!(detail.lengths.smf_km, None);
    assert_eq!(detail.lengths.om3_metres, Some(70));
    assert_eq!(detail.lengths.om4_metres, Some(100));
    assert_eq!(detail.lengths.cable_metres, None);
    assert_eq!(
        detail.technology.transmitter,
        TransmitterTechnology::from_raw(0)
    );
    assert_eq!(detail.wavelength_tolerance_picometres, Some(10_000));
    assert_eq!(detail.copper_attenuation, None);
    assert_eq!(detail.max_case_celsius, 70);
    assert!(detail.options.tx_lol_flag() && detail.options.rx_lol_flag());
    assert!(detail.options.tx_disable() && detail.options.tx_fault());
    assert!(detail.options.tx_los() && !detail.options.page_02h());
    assert!(detail.diagnostics.tx_power());
    assert!(detail.enhanced_options.initialization_complete_flag());
    assert_eq!(detail.tx_disabled, [false, false, true, false]);
    assert!(detail.power_control.power_override);
    assert!(!detail.power_control.low_power);
    assert!(detail.power_control.high_power_class_enable);
    assert!(!detail.power_control.class_8_enable);
}

#[test]
fn paged_modules_read_page_three() {
    let mut memory = sr4();
    read(&mut memory, Capture::new()).unwrap();
    assert_eq!(
        memory.asked,
        [
            Region::Lower(I2cAddress::A0),
            Region::upper(0x00),
            Region::upper(0x03),
        ]
    );
}

#[test]
fn flat_modules_read_only_page_zero() {
    let mut memory = dac();
    let (module, _) = read(&mut memory, Capture::new()).unwrap();
    assert_eq!(
        memory.asked,
        [Region::Lower(I2cAddress::A0), Region::upper(0x00)]
    );

    assert_eq!(module.inventory.vendor, "Mellanox");
    assert_eq!(module.inventory.wavelength, None, "186-187 are attenuation");
    assert_eq!(module.monitors.temperature, None);
    assert_eq!(module.monitors.supply, None);
    assert!(module.monitors.lanes.is_empty());
    assert_eq!(module.thresholds, None);
    let flags = module.flags.as_ref().unwrap();
    assert_eq!(flags.lanes.len(), 4);
    for lane in &flags.lanes {
        assert_eq!(lane.rx_los, None, "a passive cable cannot detect LOS");
        assert_eq!(lane.tx_fault, None);
        assert_eq!(lane.tx_lol, None);
    }

    let detail = sff8636(&module);
    assert!(detail.flat_memory);
    assert_eq!(detail.extended_identifier.power_class(), 1);
    assert_eq!(detail.max_power_milliwatts, None);
    assert_eq!(detail.extended_compliance, Some(0x0b));
    assert!(detail.technology.transmitter.is_passive_copper());
    assert_eq!(detail.lengths.cable_metres, Some(3));
    assert_eq!(detail.lengths.om1_metres, None, "145 is attenuation");
    assert_eq!(detail.wavelength_tolerance_picometres, None);
    let attenuation = detail.copper_attenuation.unwrap();
    assert_eq!(
        [
            attenuation.at_2_5_ghz,
            attenuation.at_5_ghz,
            attenuation.at_7_ghz,
            attenuation.at_12_9_ghz,
            attenuation.at_25_78_ghz,
        ],
        [Some(5), Some(8), Some(10), Some(13), Some(20)]
    );
}

#[test]
fn a_refresh_rereads_only_lower_memory() {
    let mut memory = sr4();
    let (first, image) = read(&mut memory, Capture::new()).unwrap();
    memory.asked.clear();
    // The module warms up and the laser on lane 2 drifts.
    memory
        .lower(22, &[0x28, 0x00])
        .lanes(42, [3_300, 3_450, 3_500, 3_600]);
    let (second, _) = read(&mut memory, Capture::refresh(image)).unwrap();
    assert_eq!(memory.asked, [Region::Lower(I2cAddress::A0)]);
    assert_eq!(second.monitors.temperature.unwrap().celsius(), 40.0);
    assert_eq!(second.monitors.lanes[1].tx_bias.unwrap().microamps(), 6_900);
    assert_eq!(first.inventory, second.inventory);
    assert_eq!(first.thresholds, second.thresholds);
}

#[test]
fn legacy_modules_without_monitor_advertisement_still_report_temperature() {
    let mut memory = sr4();
    // SFF-8636 rev 2.0, before 00h:220.5-4 existed, and the bits clear accordingly.
    memory.lower(1, &[0x06]).page00(220, &[0b0000_1100]);
    let module = dataplane_transceiver::decode(&memory.image()).unwrap();
    assert_eq!(module.monitors.temperature.unwrap().celsius(), 35.5);
    assert_eq!(module.monitors.supply.unwrap().raw(), 32_900);
    assert_eq!(module.monitors.lanes.len(), 4);

    // The same module from rev 2.8 on is taken at its word.
    memory.lower(1, &[0x08]);
    let module = dataplane_transceiver::decode(&memory.image()).unwrap();
    assert_eq!(module.monitors.temperature, None);
    assert_eq!(module.monitors.supply, None);
    // Transmit power is still advertised.
    assert_eq!(module.monitors.lanes.len(), 4);
    assert!(module.monitors.lanes.iter().all(|l| l.rx_power.is_none()));
}

#[test]
fn lane_readings_land_on_their_lane() {
    bolero::check!()
        .with_type::<([u16; 4], [u16; 4], [u16; 4])>()
        .for_each(|(rx, bias, tx)| {
            let mut memory = sr4();
            memory.lanes(34, *rx).lanes(42, *bias).lanes(50, *tx);
            let module = dataplane_transceiver::decode(&memory.image()).unwrap();
            assert_eq!(module.monitors.lanes.len(), 4);
            for (lane, readings) in module.monitors.lanes.iter().enumerate() {
                assert_eq!(readings.rx_power.unwrap().raw(), rx[lane]);
                assert_eq!(
                    readings.tx_bias.unwrap().microamps(),
                    u32::from(bias[lane]) * 2
                );
                assert_eq!(readings.tx_power.unwrap().raw(), tx[lane]);
            }
        });
}

#[test]
fn sff8636_arbitrary_memory_never_panics() {
    bolero::check!()
        .with_type::<(Vec<u8>, Vec<u8>, Vec<u8>)>()
        .for_each(|(lower, page00, page03)| {
            let block = |bytes: &Vec<u8>| {
                let mut block = [0u8; HALF];
                for (to, from) in block.iter_mut().zip(bytes) {
                    *to = *from;
                }
                block
            };
            let mut image = Image::new();
            let mut lower = block(lower);
            lower[0] = 0x11; // keep it SFF-8636
            image.insert(Region::Lower(I2cAddress::A0), lower);
            image.insert(Region::upper(0x00), block(page00));
            image.insert(Region::upper(0x03), block(page03));
            let module = dataplane_transceiver::decode(&image).unwrap();
            assert!(matches!(module.monitors.lanes.len(), 0 | 4));
            assert_eq!(module.flags.as_ref().unwrap().lanes.len(), 4);
            let class = sff8636(&module).extended_identifier.power_class();
            assert!((1..=8).contains(&class));
        });
}
