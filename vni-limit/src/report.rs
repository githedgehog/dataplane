// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The periodic counter report: a plain table per port, for a terminal or a file.

use std::fmt::Write;

use dpdk::flow::template::Counts;

use crate::config::Config;
use crate::pipeline::PortCounts;

/// The Ethernet header `COUNT` includes and the meters do not: they count IP bytes.
///
/// Exact for an untagged underlay, which is what the root rules match.
const ETH_HEADER: u64 = 14;

/// Outer IP bytes in `counts`, the unit the limits are configured in.
fn ip_bytes(counts: Counts) -> u64 {
    counts
        .bytes
        .saturating_sub(counts.packets.saturating_mul(ETH_HEADER))
}

/// Per-second rate of a counter between two readings.
#[allow(clippy::cast_precision_loss)] // A rate for people to read.
fn per_second(before: u64, now: u64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    now.saturating_sub(before) as f64 / seconds
}

/// Megabits per second of outer IP traffic between two readings.
fn mbit(before: Counts, now: Counts, seconds: f64) -> f64 {
    per_second(ip_bytes(before), ip_bytes(now), seconds) * 8e-6
}

/// One row: rates over the interval, then totals.
fn row(
    out: &mut String,
    label: &str,
    limit: &str,
    passed: (Counts, Counts),
    dropped: Option<(Counts, Counts)>,
    seconds: f64,
) {
    let (pb, pn) = passed;
    let drop_cells = match dropped {
        Some((db, dn)) => format!(
            "{:>12.0} {:>12.3} {:>14}",
            per_second(db.packets, dn.packets, seconds),
            mbit(db, dn, seconds),
            dn.packets
        ),
        None => format!("{:>12} {:>12} {:>14}", "-", "-", "-"),
    };
    // Writing to a `String` cannot fail.
    let _ = writeln!(
        out,
        "{label:<36} {limit:>10} {:>12.0} {:>12.3} {drop_cells} {:>14}",
        per_second(pb.packets, pn.packets, seconds),
        mbit(pb, pn, seconds),
        pn.packets,
    );
}

/// The table for one port: every limit, then all VXLAN traffic and the traffic no limit matched.
///
/// Rates are over the `seconds` between `before` and `now`; totals are since the rules were
/// installed. Mbit/s count outer IP bytes, as the limits do.
#[must_use]
pub fn render(
    port: &str,
    config: &Config,
    before: &PortCounts,
    now: &PortCounts,
    seconds: f64,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "port {port}, last {seconds:.1} s");
    let _ = writeln!(
        out,
        "{:<36} {:>10} {:>12} {:>12} {:>12} {:>12} {:>14} {:>14}",
        "traffic",
        "limit Mb/s",
        "passed pps",
        "passed Mb/s",
        "dropped pps",
        "dropped Mb/s",
        "dropped total",
        "passed total",
    );
    let zero = crate::pipeline::LimitCounts::default();
    for (index, limit) in config.limits.iter().enumerate() {
        let b = before.limits.get(index).unwrap_or(&zero);
        let n = now.limits.get(index).unwrap_or(&zero);
        #[allow(clippy::cast_precision_loss)] // A rate for people to read.
        let configured = format!("{:.3}", limit.cir_bytes as f64 * 8e-6);
        row(
            &mut out,
            &limit.to_string(),
            &configured,
            (b.passed, n.passed),
            Some((b.dropped, n.dropped)),
            seconds,
        );
    }
    row(
        &mut out,
        "all VXLAN",
        "",
        (before.vxlan, now.vxlan),
        None,
        seconds,
    );
    row(
        &mut out,
        "VXLAN no limit matched",
        "",
        (before.unlimited, now.unlimited),
        None,
        seconds,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::LimitCounts;

    fn counts(packets: u64, frame: u64) -> Counts {
        Counts {
            packets,
            bytes: packets * frame,
        }
    }

    #[test]
    fn rates_are_in_outer_ip_bytes_over_the_interval() {
        let config = Config::parse("limits: [{vni: 100, rate_bps: 5000000}]").unwrap();
        let before = PortCounts::default();
        // 110-byte frames carry 96-byte IP packets: 6510 of them a second is 5 Mbit/s of IP.
        let now = PortCounts {
            vxlan: counts(65_100 + 1_000_000, 110),
            unlimited: counts(0, 110),
            limits: vec![LimitCounts {
                passed: counts(65_100, 110),
                dropped: counts(1_000_000, 110),
            }],
        };
        let table = render("0000:02:00.0", &config, &before, &now, 10.0);
        let line = table.lines().find(|l| l.starts_with("vni 100")).unwrap();
        let cells: Vec<_> = line.split_whitespace().collect();
        assert_eq!(
            cells,
            [
                "vni", "100", "5.000", "6510", "5.000", "100000", "76.800", "1000000", "65100"
            ]
        );
        assert!(table.lines().any(|l| l.starts_with("all VXLAN")));
        assert!(
            table
                .lines()
                .any(|l| l.starts_with("VXLAN no limit matched"))
        );
    }

    #[test]
    fn counters_that_went_backwards_read_as_zero() {
        assert_eq!(per_second(10, 5, 1.0), 0.0);
        assert_eq!(per_second(0, 5, 0.0), 0.0);
        assert_eq!(
            ip_bytes(Counts {
                packets: 10,
                bytes: 50
            }),
            0
        );
    }
}
