// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The Common Management Interface Specification (OIF-CMIS-05.2): QSFP-DD, OSFP, QSFP112.
//!
//! Byte numbers below are the specification's; `01h:142` means page 01h, byte 142.

use crate::capture::DecodeError;
use crate::memory::{Bytes, I2cAddress, Image, Lower, Region, Upper};
use crate::module::{
    Bounds, Crossings, Flags, Inventory, LaneFlags, LaneMonitors, Module, Monitors, RxPowerKind,
    Thresholds, Wavelength,
};
use crate::sff8024::{Connector, Identifier};
use crate::units::{BiasMultiplier, Current, Power, Temperature, Voltage};

/// Lanes covered by one bank of a banked page (Table 8-2).
const LANES_PER_BANK: u8 = 8;

/// What only CMIS says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    /// The CMIS revision the module implements (00h:1).
    pub revision: Version,
    /// Whether the module has only page 00h (00h:2.7); passive copper cables usually do.
    pub flat_memory: bool,
    /// The module state machine's state (00h:3).
    pub state: ModuleState,
    /// The running firmware (00h:39-40).
    pub firmware: Version,
    /// Why the module entered [`ModuleState::Fault`], as coded in 00h:41 (0 when it has not).
    pub fault_cause: u8,
    /// Which interface code table the applications' media codes come from (00h:85, Table 8-17).
    pub media_type: u8,
    /// The applications the module supports, in `AppSel` order (00h:86-117, 01h:223-250).
    pub applications: Vec<Application>,
    /// The power class, 1 to 8 (00h:200).
    pub power_class: u8,
    /// The most the module draws, in milliwatts (00h:201).
    pub max_power_milliwatts: u32,
    /// Module-level events latched since the last read (00h:8).
    pub events: ModuleEvents,
    /// The data path state of each host lane (11h:128-131), when the module pages.
    pub data_path: Vec<DataPathState>,
}

/// A major.minor version number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// The major number.
    pub major: u8,
    /// The minor number.
    pub minor: u8,
}

/// One application: a combination of host and media interface the module can run (Table 8-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Application {
    /// The host electrical interface code (SFF-8024 Table 4-5).
    pub host_interface: u8,
    /// The media interface code, from the table [`Detail::media_type`] selects.
    pub media_interface: u8,
    /// Host lanes used; 0 means the interface code implies it.
    pub host_lanes: u8,
    /// Media lanes used; 0 means the interface code implies it.
    pub media_lanes: u8,
    /// Bit `i` set means the application may start on host lane `i + 1`.
    pub host_lane_options: u8,
}

/// The module state machine's state (Table 8-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleState {
    /// Powered but held in low power.
    LowPower,
    /// Powering up.
    PoweringUp,
    /// Ready; the only state flat memory modules report.
    Ready,
    /// Powering down.
    PoweringDown,
    /// Faulted; see [`Detail::fault_cause`].
    Fault,
    /// A reserved code.
    Reserved(u8),
}

impl ModuleState {
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::LowPower,
            2 => Self::PoweringUp,
            3 => Self::Ready,
            4 => Self::PoweringDown,
            5 => Self::Fault,
            other => Self::Reserved(other),
        }
    }
}

/// A data path state machine's state (Table 8-77).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataPathState {
    /// Deactivated, or the lane is unused.
    Deactivated,
    /// Initializing.
    Initializing,
    /// Deinitializing.
    Deinitializing,
    /// Activated: passing traffic.
    Activated,
    /// Turning the transmitter on.
    TxTurningOn,
    /// Turning the transmitter off.
    TxTurningOff,
    /// Initialized but not activated.
    Initialized,
    /// A reserved code.
    Reserved(u8),
}

impl DataPathState {
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Deactivated,
            2 => Self::Initializing,
            3 => Self::Deinitializing,
            4 => Self::Activated,
            5 => Self::TxTurningOn,
            6 => Self::TxTurningOff,
            7 => Self::Initialized,
            other => Self::Reserved(other),
        }
    }
}

/// Module-level events, latched until read (Table 8-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModuleEvents {
    /// The module state changed.
    pub state_changed: bool,
    /// The module's own firmware failed self-supervision.
    pub firmware_error: bool,
    /// Firmware in a data path device (a DSP, say) failed.
    pub data_path_firmware_error: bool,
}

/// The facts about a module that decide which pages exist and which fields are meaningful.
struct Layout {
    flat: bool,
    banks: u8,
}

impl Layout {
    fn of(lower: Lower<'_>, page01: Option<Upper<'_>>) -> Self {
        // 00h:2.7, Table 8-5
        let flat = lower.bit(2, 7);
        // 01h:142.1-0, Table 8-41; 11b is reserved, so treat it as the one bank every module has.
        let banks = match page01.map(|page| page.u8(142) & 0b11) {
            Some(0b01) => 2,
            Some(0b10) => 4,
            _ => 1,
        };
        Self { flat, banks }
    }

    fn banks(&self) -> impl Iterator<Item = u8> {
        0..self.banks
    }
}

/// The regions a full decode reads, given what has been read so far.
pub(crate) fn wanted(image: &Image) -> Vec<Region> {
    let Some(lower) = image.lower(I2cAddress::A0) else {
        return vec![Region::Lower(I2cAddress::A0)];
    };
    let mut wanted = vec![Region::upper(0x00)];
    let layout = Layout::of(lower, image.upper(Region::upper(0x01)));
    if layout.flat {
        return wanted;
    }
    wanted.extend([Region::upper(0x01), Region::upper(0x02)]);
    // Banks are advertised on page 01h, so the banked pages wait until it is in.
    if image.attempted(Region::upper(0x01)) {
        wanted.extend(layout.banks().map(|bank| Region::banked(bank, 0x11)));
    }
    wanted
}

/// The regions whose contents change while the module runs: monitors, flags and states.
pub(crate) fn live(image: &Image) -> Vec<Region> {
    let mut live = vec![Region::Lower(I2cAddress::A0)];
    if let Some(lower) = image.lower(I2cAddress::A0) {
        let layout = Layout::of(lower, image.upper(Region::upper(0x01)));
        if !layout.flat {
            live.extend(layout.banks().map(|bank| Region::banked(bank, 0x11)));
        }
    }
    live
}

/// Decode a CMIS module.
pub(crate) fn decode(image: &Image) -> Result<Module, DecodeError> {
    let lower = image
        .lower(I2cAddress::A0)
        .ok_or(DecodeError::Missing(Region::Lower(I2cAddress::A0)))?;
    let page00 = image
        .upper(Region::upper(0x00))
        .ok_or(DecodeError::Missing(Region::upper(0x00)))?;
    let page01 = image.upper(Region::upper(0x01));
    let page02 = image.upper(Region::upper(0x02));
    let layout = Layout::of(lower, page01);
    // Everything past page 00h is conditional on paging; ignore stray pages from a flat module.
    let (page01, page02) = if layout.flat {
        (None, None)
    } else {
        (page01, page02)
    };
    let page11 = |bank: u8| image.upper(Region::banked(bank, 0x11));
    let advertised = page01.map(Advertised::of).unwrap_or_default();
    let lanes = lane_count(page00, &layout);

    let monitors = Monitors {
        temperature: advertised
            .temperature
            .then(|| Temperature::from_raw(lower.i16(14))),
        supply: advertised.supply.then(|| Voltage::from_raw(lower.u16(16))),
        rx_power_kind: advertised.rx_power_kind,
        lanes: (0..lanes)
            .filter_map(|lane| {
                let page = page11(lane / LANES_PER_BANK)?;
                Some(lane_monitors(page, lane % LANES_PER_BANK, &advertised))
            })
            .collect(),
    };

    let thresholds = page02.map(|page| thresholds(page, &advertised));

    let flags = (!layout.flat).then(|| Flags {
        temperature: crossings(lower.u8(9), [0, 1, 2, 3]),
        supply: crossings(lower.u8(9), [4, 5, 6, 7]),
        lanes: (0..lanes)
            .filter_map(|lane| {
                let page = page11(lane / LANES_PER_BANK)?;
                Some(lane_flags(page, lane % LANES_PER_BANK, &advertised))
            })
            .collect(),
    });

    let host_lanes = host_lane_count(lower, &layout);
    let data_path = (0..host_lanes)
        .filter_map(|lane| {
            let page = page11(lane / LANES_PER_BANK)?;
            let lane = lane % LANES_PER_BANK;
            let byte = page.u8(128 + lane / 2);
            let code = if lane.is_multiple_of(2) {
                byte & 0x0f
            } else {
                byte >> 4
            };
            Some(DataPathState::from_code(code))
        })
        .collect();

    let inventory = Inventory {
        vendor: page00.text(129, 16),
        oui: [page00.u8(145), page00.u8(146), page00.u8(147)],
        part_number: page00.text(148, 16),
        revision: page00.text(164, 2),
        serial_number: page00.text(166, 16),
        date_code: page00.text(182, 8),
        connector: Connector::from_raw(page00.u8(203)),
        // 01h:138-139, Table 8-40; zero means not specified (copper, say).
        wavelength: page01
            .map(|page| page.u16(138))
            .filter(|twentieths| *twentieths != 0)
            .map(|twentieths| Wavelength::from_twentieths(u32::from(twentieths))),
    };

    let detail = Detail {
        revision: Version {
            major: lower.u8(1) >> 4,
            minor: lower.u8(1) & 0x0f,
        },
        flat_memory: layout.flat,
        state: ModuleState::from_code((lower.u8(3) >> 1) & 0b111),
        firmware: Version {
            major: lower.u8(39),
            minor: lower.u8(40),
        },
        fault_cause: lower.u8(41),
        media_type: lower.u8(85),
        applications: applications(lower, page01),
        power_class: (page00.u8(200) >> 5) + 1,
        max_power_milliwatts: u32::from(page00.u8(201)) * 250,
        events: ModuleEvents {
            state_changed: lower.bit(8, 0),
            firmware_error: lower.bit(8, 1),
            data_path_firmware_error: lower.bit(8, 2),
        },
        data_path,
    };

    Ok(Module {
        identifier: Identifier::from_raw(lower.u8(0)),
        inventory,
        monitors,
        thresholds,
        flags,
        detail: crate::module::Detail::Cmis(detail),
    })
}

/// Which monitors and flags the module implements (01h:157-160, Tables 8-46 and 8-47).
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)] // one per advertisement bit
struct Advertised {
    temperature: bool,
    supply: bool,
    tx_bias: bool,
    tx_power: bool,
    rx_power: bool,
    bias_multiplier: BiasMultiplier,
    rx_power_kind: RxPowerKind,
    tx_fault: bool,
    tx_los: bool,
    tx_lol: bool,
    rx_los: bool,
    rx_lol: bool,
}

impl Advertised {
    fn of(page: Upper<'_>) -> Self {
        Self {
            temperature: page.bit(159, 0),
            supply: page.bit(159, 1),
            tx_bias: page.bit(160, 0),
            tx_power: page.bit(160, 1),
            rx_power: page.bit(160, 2),
            bias_multiplier: match (page.u8(160) >> 3) & 0b11 {
                0b01 => BiasMultiplier::Two,
                0b10 => BiasMultiplier::Four,
                _ => BiasMultiplier::One,
            },
            // 01h:151.4, Table 8-44
            rx_power_kind: if page.bit(151, 4) {
                RxPowerKind::Average
            } else {
                RxPowerKind::Oma
            },
            tx_fault: page.bit(157, 0),
            tx_los: page.bit(157, 1),
            tx_lol: page.bit(157, 2),
            rx_los: page.bit(158, 1),
            rx_lol: page.bit(158, 2),
        }
    }
}

/// Media lanes, which the lane monitors and most lane flags are indexed by.
fn lane_count(page00: Upper<'_>, layout: &Layout) -> u8 {
    if layout.flat {
        return 0;
    }
    // 00h:210, Table 8-32: a set bit marks an unsupported lane; only meaningful up to 8 lanes.
    let supported = !page00.u8(210);
    if layout.banks == 1 && supported != 0 {
        // A u8 has at most 8 leading zeros, so this cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        let lanes = 8 - supported.leading_zeros() as u8;
        lanes
    } else {
        layout.banks * LANES_PER_BANK
    }
}

/// Host lanes, which the data path states are indexed by: those of the first application.
fn host_lane_count(lower: Lower<'_>, layout: &Layout) -> u8 {
    if layout.flat {
        return 0;
    }
    match lower.u8(88) >> 4 {
        0 => layout.banks * LANES_PER_BANK,
        lanes => lanes.min(layout.banks * LANES_PER_BANK),
    }
}

fn applications(lower: Lower<'_>, page01: Option<Upper<'_>>) -> Vec<Application> {
    // AppSel 1-8 in lower memory (Table 8-20), 9-15 on page 01h (Table 8-53).
    let first = (0..8u8).map(|i| descriptor(&lower, 86 + 4 * i));
    let rest = page01
        .into_iter()
        .flat_map(|page| (0..7u8).map(move |i| descriptor(&page, 223 + 4 * i)));
    // A host interface code of FFh marks the first unused descriptor and the end of the list.
    first
        .chain(rest)
        .take_while(|app| app.host_interface != 0xff && app.host_interface != 0x00)
        .collect()
}

fn descriptor(page: &impl Bytes, at: u8) -> Application {
    Application {
        host_interface: page.u8(at),
        media_interface: page.u8(at + 1),
        host_lanes: page.u8(at + 2) >> 4,
        media_lanes: page.u8(at + 2) & 0x0f,
        host_lane_options: page.u8(at + 3),
    }
}

fn lane_monitors(page: Upper<'_>, lane: u8, advertised: &Advertised) -> LaneMonitors {
    // 11h:154-201, Table 8-82
    LaneMonitors {
        tx_power: advertised
            .tx_power
            .then(|| Power::from_raw(page.u16(154 + 2 * lane))),
        tx_bias: advertised
            .tx_bias
            .then(|| Current::from_raw(page.u16(170 + 2 * lane), advertised.bias_multiplier)),
        rx_power: advertised
            .rx_power
            .then(|| Power::from_raw(page.u16(186 + 2 * lane))),
    }
}

fn lane_flags(page: Upper<'_>, lane: u8, advertised: &Advertised) -> LaneFlags {
    let flag = |byte: u8, supported: bool| supported.then(|| page.bit(byte, lane));
    let across = |first: u8, supported: bool| {
        if supported {
            Crossings {
                high_alarm: page.bit(first, lane),
                low_alarm: page.bit(first + 1, lane),
                high_warning: page.bit(first + 2, lane),
                low_warning: page.bit(first + 3, lane),
            }
        } else {
            Crossings::default()
        }
    };
    // 11h:135-152, Tables 8-80 and 8-81
    LaneFlags {
        tx_fault: flag(135, advertised.tx_fault),
        tx_los: flag(136, advertised.tx_los),
        tx_lol: flag(137, advertised.tx_lol),
        tx_power: across(139, advertised.tx_power),
        tx_bias: across(143, advertised.tx_bias),
        rx_los: flag(147, advertised.rx_los),
        rx_lol: flag(148, advertised.rx_lol),
        rx_power: across(149, advertised.rx_power),
    }
}

/// Map four flag bits (high alarm, low alarm, high warning, low warning) of `byte` to crossings.
fn crossings(byte: u8, [high_alarm, low_alarm, high_warning, low_warning]: [u8; 4]) -> Crossings {
    let set = |bit: u8| byte & (1 << bit) != 0;
    Crossings {
        high_alarm: set(high_alarm),
        low_alarm: set(low_alarm),
        high_warning: set(high_warning),
        low_warning: set(low_warning),
    }
}

fn thresholds(page: Upper<'_>, advertised: &Advertised) -> Thresholds {
    fn bounds<T>(page: Upper<'_>, first: u8, value: impl Fn(Upper<'_>, u8) -> T) -> Bounds<T> {
        Bounds {
            high_alarm: value(page, first),
            low_alarm: value(page, first + 2),
            high_warning: value(page, first + 4),
            low_warning: value(page, first + 6),
        }
    }
    let power = |page: Upper<'_>, at: u8| Power::from_raw(page.u16(at));
    // 02h:128-143 (Table 8-55) and 02h:176-199 (Table 8-56)
    Thresholds {
        temperature: advertised
            .temperature
            .then(|| bounds(page, 128, |page, at| Temperature::from_raw(page.i16(at)))),
        supply: advertised
            .supply
            .then(|| bounds(page, 136, |page, at| Voltage::from_raw(page.u16(at)))),
        tx_power: advertised.tx_power.then(|| bounds(page, 176, power)),
        tx_bias: advertised.tx_bias.then(|| {
            bounds(page, 184, |page, at| {
                Current::from_raw(page.u16(at), advertised.bias_multiplier)
            })
        }),
        rx_power: advertised.rx_power.then(|| bounds(page, 192, power)),
    }
}
