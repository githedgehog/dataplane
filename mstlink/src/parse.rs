// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Turning `mstlink --json` output into types.

use serde_json::{Map, Value};

/// Why `mstlink` output could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The output is not JSON: `mstlink` reports some failures (an unknown device, say) as
    /// coloured text whatever `--json` asked for.
    #[error("mstlink did not answer in JSON: {text}")]
    NotJson {
        /// The output, trimmed and stripped of terminal colours.
        text: String,
    },
    /// `mstlink` answered, with a failure.
    #[error("mstlink failed with status {code}: {message}")]
    Failed {
        /// Its status code.
        code: i64,
        /// Its explanation.
        message: String,
    },
    /// The JSON is not shaped like `mstlink`'s.
    #[error("mstlink's JSON has no result.output")]
    Unrecognised,
}

/// What `mstlink -c -e` says about a port.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PortReport {
    /// The link's state ("Operational Info").
    pub operational: Operational,
    /// The firmware's own diagnosis ("Troubleshooting Info").
    pub troubleshooting: Troubleshooting,
    /// Physical layer counters and bit error rates, if reported.
    pub counters: Option<Counters>,
    /// The receiver's eye, if reported.
    pub eye: Option<Eye>,
}

/// The link's state, as `mstlink` words it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Operational {
    /// `Active` when the link is up.
    pub state: Option<String>,
    /// The physical layer's state machine, e.g. `LinkUp` or `ETH_AN_FSM_ENABLE`.
    pub physical_state: Option<String>,
    /// e.g. `400G`.
    pub speed: Option<String>,
    /// Lanes in use, e.g. `4x`.
    pub width: Option<String>,
    /// The FEC in use, e.g. `Standard_RS-FEC - (544,514)` or `No FEC`.
    pub fec: Option<String>,
    /// `ON` or `OFF`.
    pub auto_negotiation: Option<String>,
}

/// The firmware's diagnosis of the link.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Troubleshooting {
    /// 0 when the firmware sees no issue.
    pub status_opcode: Option<u32>,
    /// The group the status belongs to.
    pub group_opcode: Option<String>,
    /// What the firmware suggests, e.g. `No issue was observed`.
    pub recommendation: Option<String>,
}

/// Physical layer counters, cumulative since they were last cleared.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Counters {
    /// Bit error rate after FEC.
    pub effective_ber: Option<f64>,
    /// Bit error rate before FEC.
    pub raw_ber: Option<f64>,
    /// Bit error rate before FEC, per lane.
    pub raw_ber_per_lane: Vec<Option<f64>>,
    /// Bit errors before FEC, per lane.
    pub raw_errors_per_lane: Vec<Option<u64>>,
    /// Bit errors FEC could not correct.
    pub effective_errors: Option<u64>,
    /// Times the link went down.
    pub link_down: Option<u64>,
    /// Times the link recovered from errors without going down.
    pub link_error_recovery: Option<u64>,
    /// Minutes since the counters were last cleared.
    pub minutes_since_clear: Option<f64>,
}

/// The receiver's eye opening, per lane.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Eye {
    /// How the figure of merit is measured, e.g. `SLRG_FOM_MODE_EYEO`.
    pub fom_mode: Option<String>,
    /// Each lane's measurements, in lane order.
    pub lanes: Vec<EyeLane>,
}

/// One lane's eye. Figures of merit are the firmware's own scale: larger is a wider eye.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EyeLane {
    /// The lane, from 0 as `mstlink` numbers it.
    pub lane: u32,
    /// The figure of merit when the link came up.
    pub initial_fom: Option<u32>,
    /// The latest figure of merit.
    pub last_fom: Option<u32>,
    /// PAM4's upper eye grade; absent on NRZ links.
    pub upper_grade: Option<u32>,
    /// PAM4's middle eye grade.
    pub mid_grade: Option<u32>,
    /// PAM4's lower eye grade.
    pub lower_grade: Option<u32>,
}

/// How many FEC codewords needed how many symbols corrected.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FecHistogram {
    /// Each bin's range of corrected symbols (as `mstlink` prints it, e.g. `[3]`) and its
    /// count, in bin order.
    pub bins: Vec<(String, u64)>,
}

/// The PCIe link between the device and its host.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Pcie {
    /// The generation the link runs at.
    pub generation_active: Option<u8>,
    /// The generation it is enabled for.
    pub generation_enabled: Option<u8>,
    /// Lanes in use.
    pub width_active: Option<u8>,
    /// Lanes it is enabled for; more than [`Pcie::width_active`] means it trained down.
    pub width_enabled: Option<u8>,
    /// Data link layer packets that failed their CRC.
    pub crc_errors_dllp: Option<u64>,
    /// Transaction layer packets that failed their CRC.
    pub crc_errors_tlp: Option<u64>,
    /// Receiver errors.
    pub rx_errors: Option<u64>,
    /// Transmitter errors.
    pub tx_errors: Option<u64>,
    /// Bit error rate.
    pub effective_ber: Option<f64>,
}

impl PortReport {
    /// Parse the output of [`crate::Query::Port`].
    ///
    /// # Errors
    ///
    /// Fails if the output is not `mstlink` JSON or reports a failure.
    pub fn parse(output: &str) -> Result<Self, ParseError> {
        let sections = sections(output)?;
        let operational = section(&sections, "Operational Info");
        let troubleshooting = section(&sections, "Troubleshooting Info");
        Ok(PortReport {
            operational: Operational {
                state: text(operational, "State"),
                physical_state: text(operational, "Physical state"),
                speed: text(operational, "Speed"),
                width: text(operational, "Width"),
                fec: text(operational, "FEC"),
                auto_negotiation: text(operational, "Auto Negotiation"),
            },
            troubleshooting: Troubleshooting {
                status_opcode: number(troubleshooting, "Status Opcode"),
                group_opcode: text(troubleshooting, "Group Opcode"),
                recommendation: text(troubleshooting, "Recommendation"),
            },
            counters: section(&sections, "Physical Counters and BER Info").map(|counters| {
                Counters {
                    effective_ber: number(Some(counters), "Effective Physical BER"),
                    raw_ber: number(Some(counters), "Raw Physical BER"),
                    raw_ber_per_lane: numbers(counters, "Raw Physical BER Per Lane"),
                    raw_errors_per_lane: numbers(counters, "Raw Physical Errors Per Lane"),
                    effective_errors: number(Some(counters), "Effective Physical Errors"),
                    link_down: number(Some(counters), "Link Down Counter"),
                    link_error_recovery: number(Some(counters), "Link Error Recovery Counter"),
                    minutes_since_clear: number(Some(counters), "Time Since Last Clear [Min]"),
                }
            }),
            eye: section(&sections, "EYE Opening Info").map(eye),
        })
    }
}

impl FecHistogram {
    /// Parse the output of [`crate::Query::FecHistogram`].
    ///
    /// # Errors
    ///
    /// Fails if the output is not `mstlink` JSON or reports a failure, as it does for a link
    /// without FEC.
    pub fn parse(output: &str) -> Result<Self, ParseError> {
        let sections = sections(output)?;
        let Some(histogram) = section(&sections, "Histogram of FEC Errors") else {
            return Ok(FecHistogram::default());
        };
        let mut bins: Vec<(u32, String, u64)> = histogram
            .iter()
            .filter_map(|(name, bin)| {
                let index = name.strip_prefix("Bin ")?.parse().ok()?;
                let values = list(bin)?;
                let range = values.first()?.as_str()?.to_string();
                let count = values.get(1)?.as_str()?.trim().parse().ok()?;
                Some((index, range, count))
            })
            .collect();
        bins.sort_by_key(|(index, ..)| *index);
        Ok(FecHistogram {
            bins: bins
                .into_iter()
                .map(|(_, range, count)| (range, count))
                .collect(),
        })
    }
}

impl Pcie {
    /// Parse the output of [`crate::Query::Pcie`].
    ///
    /// # Errors
    ///
    /// Fails if the output is not `mstlink` JSON or reports a failure.
    pub fn parse(output: &str) -> Result<Self, ParseError> {
        let sections = sections(output)?;
        let link = section(&sections, "PCIe Operational (Enabled) Info");
        let counters = section(&sections, "Management PCIe Performance Counters Info");
        // Both read "<active> (<enabled>)", e.g. "32G-Gen 5 (32G-Gen 5)" and "8X (16X)".
        let pair = |key| {
            let value = text(link, key)?;
            let (active, enabled) = value.split_once('(')?;
            Some((
                active.trim().to_string(),
                enabled.trim_end_matches(')').trim().to_string(),
            ))
        };
        let generation = |speed: &str| speed.rsplit("Gen").next()?.trim().parse().ok();
        let lanes = |width: &str| width.trim_end_matches(['X', 'x']).trim().parse().ok();
        let speeds = pair("Link Speed Active (Enabled)");
        let widths = pair("Link Width Active (Enabled)");
        Ok(Pcie {
            generation_active: speeds.as_ref().and_then(|(active, _)| generation(active)),
            generation_enabled: speeds.as_ref().and_then(|(_, enabled)| generation(enabled)),
            width_active: widths.as_ref().and_then(|(active, _)| lanes(active)),
            width_enabled: widths.as_ref().and_then(|(_, enabled)| lanes(enabled)),
            crc_errors_dllp: number(counters, "CRC Error dllp"),
            crc_errors_tlp: number(counters, "CRC Error tlp"),
            rx_errors: number(counters, "RX Errors"),
            tx_errors: number(counters, "TX Errors"),
            effective_ber: number(counters, "Effective ber"),
        })
    }
}

fn eye(eye: &Map<String, Value>) -> Eye {
    let lanes = numbers::<u32>(eye, "Lane");
    let field = |key| numbers::<u32>(eye, key);
    let (initial, last) = (field("Initial FOM"), field("Last FOM"));
    let (upper, mid, lower) = (
        field("Upper Grades"),
        field("Mid Grades"),
        field("Lower Grades"),
    );
    let at = |values: &[Option<u32>], i: usize| values.get(i).copied().flatten();
    Eye {
        fom_mode: list(eye.get("FOM Mode").unwrap_or(&Value::Null))
            .and_then(|values| values.first()?.as_str().map(str::to_string)),
        lanes: lanes
            .iter()
            .enumerate()
            .filter_map(|(i, lane)| {
                Some(EyeLane {
                    lane: (*lane)?,
                    initial_fom: at(&initial, i),
                    last_fom: at(&last, i),
                    upper_grade: at(&upper, i),
                    mid_grade: at(&mid, i),
                    lower_grade: at(&lower, i),
                })
            })
            .collect(),
    }
}

/// The sections of `result.output`, after checking `status`.
fn sections(output: &str) -> Result<Map<String, Value>, ParseError> {
    let json: Value = serde_json::from_str(output).map_err(|_| ParseError::NotJson {
        text: strip_colours(output.trim()),
    })?;
    if let Some(status) = json.get("status") {
        let code = status.get("code").and_then(Value::as_i64).unwrap_or(0);
        if code != 0 {
            let message = status.get("message").and_then(Value::as_str).unwrap_or("");
            return Err(ParseError::Failed {
                code,
                message: message.trim().to_string(),
            });
        }
    }
    match json.pointer("/result/output") {
        Some(Value::Object(sections)) => Ok(sections.clone()),
        _ => Err(ParseError::Unrecognised),
    }
}

fn section<'a>(sections: &'a Map<String, Value>, name: &str) -> Option<&'a Map<String, Value>> {
    sections.get(name)?.as_object()
}

/// A field's text, unless `mstlink` says it is not available.
fn text(section: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    let value = section?.get(key)?.as_str()?.trim();
    (!value.is_empty() && value != "N/A").then(|| value.to_string())
}

fn number<T: std::str::FromStr>(section: Option<&Map<String, Value>>, key: &str) -> Option<T> {
    text(section, key)?.parse().ok()
}

/// A list field, which `mstlink` renders as `{"values": [...]}`.
fn list(value: &Value) -> Option<&Vec<Value>> {
    value.get("values")?.as_array()
}

/// A list field of numbers, each [`None`] where it is not a number.
fn numbers<T: std::str::FromStr>(section: &Map<String, Value>, key: &str) -> Vec<Option<T>> {
    section
        .get(key)
        .and_then(list)
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_str()?.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Drop ANSI escape sequences, which `mstlink` prints around its errors.
fn strip_colours(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // ESC [ ... final byte in @..~
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) && c != '[' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out.trim().to_string()
}
