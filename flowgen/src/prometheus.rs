// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reading a gateway's telemetry the way an operator's Prometheus does: from its text exposition.
//!
//! In a loopback test the text comes from the in-process exporter; against a gateway in vlab or on
//! hardware, from its `/metrics` endpoint. Either way the generator learns nothing about what a
//! metric means: every counter and gauge becomes a report path, `<prefix>.<name>` followed by
//! `.<label>=<value>` for each label in order, so a family the gateway adds later appears in
//! reports with no change here.
//!
//! Histograms and summaries are skipped; untyped series are taken for gauges.

use std::collections::BTreeMap;

use flowgen_report::Sample;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Counter,
    Gauge,
    Other,
}

/// `sample`, with every counter and gauge in the exposition `text` under `prefix`.
///
/// Values are rounded to whole numbers; negative and non-finite ones are skipped. Lines that do not
/// parse are skipped too: a scrape is best effort, and a partial one is better than none.
#[must_use]
pub fn sample(text: &str, prefix: &str, sample: Sample) -> Sample {
    let mut kinds = BTreeMap::new();
    let mut sample = sample;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut words = rest.split_whitespace();
            if let (Some(name), Some(kind)) = (words.next(), words.next()) {
                let kind = match kind {
                    "counter" => Kind::Counter,
                    "gauge" | "untyped" => Kind::Gauge,
                    _ => Kind::Other,
                };
                kinds.insert(name.to_string(), kind);
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, labels, value)) = series(line) else {
            continue;
        };
        let kind = kind_of(&kinds, name);
        if kind == Kind::Other || !value.is_finite() || value < 0.0 {
            continue;
        }
        let mut path = format!("{prefix}.{name}");
        for (key, value) in labels {
            path = format!("{path}.{key}={value}");
        }
        // Rounded and saturated: `as` from a finite, non-negative float does both.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let value = value.round() as u64;
        sample = match kind {
            Kind::Counter => sample.counter(path, value),
            _ => sample.gauge(path, value),
        };
    }
    sample
}

/// A series' kind: its family's declared type, where a histogram's or summary's series carry a
/// suffix on the family's name; a gauge if nothing was declared.
fn kind_of(kinds: &BTreeMap<String, Kind>, name: &str) -> Kind {
    if let Some(kind) = kinds.get(name) {
        return *kind;
    }
    let family = ["_bucket", "_sum", "_count", "_created"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix));
    match family.and_then(|family| kinds.get(family)) {
        Some(Kind::Other) => Kind::Other,
        _ => Kind::Gauge,
    }
}

/// A label's name and value.
type Label = (String, String);

/// One series line's name, labels in order, and value; any timestamp is ignored.
fn series(line: &str) -> Option<(&str, Vec<Label>, f64)> {
    let (name, rest) = line.split_at(line.find(['{', ' '])?);
    let (labels, rest) = match rest.strip_prefix('{') {
        Some(rest) => labels(rest)?,
        None => (Vec::new(), rest),
    };
    let value = rest.split_whitespace().next()?;
    let value = match value {
        "+Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        value => value.parse().ok()?,
    };
    Some((name, labels, value))
}

/// The labels at the start of `text`, just past its `{`, and what follows their `}`.
fn labels(text: &str) -> Option<(Vec<Label>, &str)> {
    let mut labels = Vec::new();
    let mut rest = text.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix('}') {
            return Some((labels, after));
        }
        let (key, after) = rest.split_once('=')?;
        let after = after.strip_prefix('"')?;
        // The value runs to the first quote that is not escaped.
        let mut value = String::new();
        let mut chars = after.char_indices();
        let end = loop {
            match chars.next()? {
                (_, '\\') => match chars.next()? {
                    (_, 'n') => value.push('\n'),
                    (_, c) => value.push(c),
                },
                (at, '"') => break at,
                (_, c) => value.push(c),
            }
        };
        labels.push((key.trim().to_string(), value));
        rest = after[end + 1..].trim_start();
        rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPOSITION: &str = r#"
# HELP pipeline_packets packets the pipeline finished with
# TYPE pipeline_packets counter
pipeline_packets{reason="Delivered"} 6
pipeline_packets{reason="Unroutable"} 0
# TYPE flow_table_entries gauge
flow_table_entries 1234
# TYPE worker_rx_packets counter
worker_rx_packets{port="eth0",worker="1"} 3 1700000000000
# TYPE request_seconds histogram
request_seconds_bucket{le="0.1"} 4
request_seconds_sum 0.3
# TYPE odd counter
odd{label="a \"quoted\", comma\\here"} 2.6
broken{label="unterminated} 1
"#;

    #[test]
    fn counters_and_gauges_become_paths() {
        let s = sample(EXPOSITION, "dataplane", Sample::new());
        assert_eq!(s.counters["dataplane.pipeline_packets.reason=Delivered"], 6);
        assert_eq!(
            s.counters["dataplane.pipeline_packets.reason=Unroutable"],
            0
        );
        assert_eq!(s.gauges["dataplane.flow_table_entries"], 1234);
        assert_eq!(
            s.counters["dataplane.worker_rx_packets.port=eth0.worker=1"],
            3
        );
        assert_eq!(
            s.counters[r#"dataplane.odd.label=a "quoted", comma\here"#], 3,
            "escapes are undone and values rounded"
        );
        assert!(
            s.counters
                .keys()
                .chain(s.gauges.keys())
                .all(|path| !path.contains("request_seconds")),
            "histograms are skipped"
        );
        assert!(
            s.counters
                .keys()
                .chain(s.gauges.keys())
                .all(|path| !path.contains("broken")),
            "a line that does not parse is skipped"
        );
    }
}
