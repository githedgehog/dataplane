// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! How much of masquerade's public space is in use.
//!
//! [`MasqueradeMetrics`] publishes, per region of public addresses, per destination VPC and per
//! protocol, the addresses and how many of the 256-port blocks the addresses in use have handed
//! out and have left, as `nat_masquerade_*` gauges labelled `protocol`, `dst_vpc` and `region`.
//! Pools toward different VPCs may share public addresses, each with an allocator of its own, so
//! the region alone does not name one. A region a new configuration no longer has is set to zero
//! rather than left at its last values.

use std::collections::BTreeMap;

use metrics::Unit;

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;

/// Base id of the masquerade family. Every series is `{BASE}_{suffix}`.
pub(crate) const MASQUERADE_METRIC_BASE: &str = "nat_masquerade";

/// One region's usage, for one protocol, as the `nat` crate's `MasqueradeUsage` reports it,
/// which documents the counts; the labels are its protocol, destination VPC (by VNI) and region
/// as text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MasqueradeRegion<'a> {
    pub protocol: &'a str,
    pub dst_vpc: &'a str,
    pub region: &'a str,
    pub addresses: u64,
    pub addresses_in_use: u64,
    pub port_blocks_in_use: u64,
    pub port_blocks_free: u64,
}

/// A series' suffix, its description, and the field it carries.
type Series = (&'static str, &'static str, fn(&MasqueradeRegion<'_>) -> u64);

/// Every series.
const SERIES: [Series; 4] = [
    ("addresses", "public addresses in the region", |r| {
        r.addresses
    }),
    (
        "addresses_in_use",
        "public addresses in the region that ports are allocated from",
        |r| r.addresses_in_use,
    ),
    (
        "port_blocks_in_use",
        "256-port blocks handed out from the addresses in use; a block counts whole",
        |r| r.port_blocks_in_use,
    ),
    (
        "port_blocks_free",
        "256-port blocks the addresses in use have left; addresses not in use have all of theirs",
        |r| r.port_blocks_free,
    ),
];

/// Masquerade's usage gauges, registered as each region first appears.
#[derive(Debug, Default)]
pub struct MasqueradeMetrics {
    /// By protocol, destination VPC and region.
    regions: BTreeMap<(String, String, String), [Registered<metrics::Gauge>; 4]>,
}

impl MasqueradeMetrics {
    #[must_use]
    pub fn new() -> MasqueradeMetrics {
        MasqueradeMetrics::default()
    }

    /// Publish the usage of every region there is now, and zero the ones there no longer are.
    #[allow(clippy::cast_precision_loss)] // exact up to 2^53, past any address count that matters
    pub fn publish(&mut self, regions: &[MasqueradeRegion<'_>]) {
        let mut published = std::collections::BTreeSet::new();
        for region in regions {
            let key = (
                region.protocol.to_string(),
                region.dst_vpc.to_string(),
                region.region.to_string(),
            );
            let gauges = self.regions.entry(key.clone()).or_insert_with(|| {
                SERIES.map(|(suffix, description, _)| {
                    let mut spec = MetricSpec::new(
                        format!("{MASQUERADE_METRIC_BASE}_{suffix}"),
                        Unit::Count,
                        vec![
                            ("protocol".to_string(), region.protocol.to_string()),
                            ("dst_vpc".to_string(), region.dst_vpc.to_string()),
                            ("region".to_string(), region.region.to_string()),
                        ],
                    );
                    spec.description = description.to_string();
                    spec.register()
                })
            });
            for (gauge, (_, _, field)) in gauges.iter().zip(SERIES) {
                gauge.metric.set(field(region) as f64);
            }
            published.insert(key);
        }
        for (key, gauges) in &self.regions {
            if !published.contains(key) {
                gauges.iter().for_each(|gauge| gauge.metric.set(0.0));
            }
        }
    }
}

#[cfg(test)]
mod exported {
    use super::*;
    use crate::scrape::Scrape;

    /// Each region's usage reaches its own series, and a region that goes away drops to zero.
    #[test]
    fn regions_come_and_go() {
        let region = |region, in_use| MasqueradeRegion {
            protocol: "tcp",
            dst_vpc: "200",
            region,
            addresses: 4,
            addresses_in_use: in_use,
            port_blocks_in_use: 10,
            port_blocks_free: 500,
        };
        let scrape = Scrape::default();
        let get = |suffix: &str, region| {
            scrape.get(
                &format!("{MASQUERADE_METRIC_BASE}_{suffix}"),
                &[("protocol", "tcp"), ("dst_vpc", "200"), ("region", region)],
            )
        };
        metrics::with_local_recorder(&scrape, || {
            let mut metrics = MasqueradeMetrics::new();
            metrics.publish(&[region("a", 1), region("b", 2)]);
            assert_eq!(get("addresses_in_use", "a"), Some(1.0));
            assert_eq!(get("addresses_in_use", "b"), Some(2.0));
            assert_eq!(get("port_blocks_free", "b"), Some(500.0));
            metrics.publish(&[region("b", 3)]);
        });
        assert_eq!(get("addresses", "a"), Some(0.0));
        assert_eq!(get("port_blocks_in_use", "a"), Some(0.0));
        assert_eq!(get("addresses_in_use", "b"), Some(3.0));
    }

    /// One region toward two destination VPCs is two sets of series: neither hides the other.
    #[test]
    fn destinations_apart() {
        let toward = |dst_vpc, in_use| MasqueradeRegion {
            protocol: "tcp",
            dst_vpc,
            region: "10.1.0.0-10.1.0.3",
            addresses: 4,
            addresses_in_use: in_use,
            port_blocks_in_use: in_use,
            port_blocks_free: 1024 - in_use,
        };
        let scrape = Scrape::default();
        metrics::with_local_recorder(&scrape, || {
            MasqueradeMetrics::new().publish(&[toward("200", 3), toward("300", 0)]);
        });
        let get = |dst_vpc| {
            scrape.get(
                &format!("{MASQUERADE_METRIC_BASE}_addresses_in_use"),
                &[
                    ("protocol", "tcp"),
                    ("dst_vpc", dst_vpc),
                    ("region", "10.1.0.0-10.1.0.3"),
                ],
            )
        };
        assert_eq!((get("200"), get("300")), (Some(3.0), Some(0.0)));
    }
}
