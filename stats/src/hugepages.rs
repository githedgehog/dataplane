// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Init's hugepage plan for EAL.

use crate::register::{Register, Registered};
use crate::spec::MetricSpec;
use metrics::Unit;

/// The size of the hugepages set aside for EAL.
pub const HUGEPAGE_SIZE: &str = "dpdk_hugepage_size_bytes";
/// The hugepage memory set aside for EAL, by `node`.
pub const HUGEPAGES_RESERVED: &str = "dpdk_hugepages_reserved_bytes";

/// `dpdk_hugepage_size_bytes`, and `dpdk_hugepages_reserved_bytes{node}` for each node memory was
/// set aside on, registered once and published again with every scrape.
///
/// Set aside means init made sure the kernel's pools hold it. EAL preallocates a numbered node's
/// share at start; the share on `node="any"`, set aside when the NICs' NUMA placement is unknown,
/// it maps only as it needs it. `dpdk_heap_bytes` reports what the heaps hold now.
#[derive(Debug)]
pub struct HugepageMetrics {
    page_size: (Registered<metrics::Gauge>, u64),
    reserved: Vec<(Registered<metrics::Gauge>, u64)>,
}

impl HugepageMetrics {
    /// Register `page_size_bytes`, and the bytes set aside on each node of `reserved`, which
    /// should name each node once.
    #[must_use]
    pub fn new(
        page_size_bytes: u64,
        reserved: impl IntoIterator<Item = (String, u64)>,
    ) -> HugepageMetrics {
        let mut size = MetricSpec::new(HUGEPAGE_SIZE, Unit::Bytes, Vec::new());
        size.description = "size of the hugepages init set aside for EAL".to_string();
        let reserved = reserved
            .into_iter()
            .map(|(node, bytes)| {
                let mut spec = MetricSpec::new(
                    HUGEPAGES_RESERVED,
                    Unit::Bytes,
                    vec![("node".to_string(), node)],
                );
                spec.description = "hugepage memory init set aside for EAL on a NUMA node; EAL \
                                    preallocates a numbered node's at start, and maps node \
                                    \"any\"'s as it needs it"
                    .to_string();
                (spec.register(), bytes)
            })
            .collect();
        let metrics = HugepageMetrics {
            page_size: (size.register(), page_size_bytes),
            reserved,
        };
        metrics.publish();
        metrics
    }

    /// Publish the configured hugepage values.
    #[allow(clippy::cast_precision_loss)] // far below 2^52 bytes
    pub fn publish(&self) {
        for (gauge, value) in std::iter::once(&self.page_size).chain(&self.reserved) {
            gauge.metric.set(*value as f64);
        }
    }
}

#[cfg(test)]
mod exported {
    use super::*;
    use crate::scrape::Scrape;
    use std::collections::BTreeMap;

    /// Whatever the plan, each node's bytes reach its own series, and nothing else is published.
    #[test]
    #[allow(clippy::cast_precision_loss)] // shifted below 2^52 first
    fn each_node_reaches_its_own_series() {
        bolero::check!()
            .with_type::<(u64, BTreeMap<u32, u64>, Option<u64>)>()
            .for_each(|(page_size, nodes, any)| {
                // Below 2^52, where an f64 holds every value exactly.
                let page_size = page_size >> 12;
                let reserved: Vec<(String, u64)> = nodes
                    .iter()
                    .map(|(node, bytes)| (node.to_string(), bytes >> 12))
                    .chain(any.map(|bytes| ("any".to_string(), bytes >> 12)))
                    .collect();
                let scrape = Scrape::default();
                metrics::with_local_recorder(&scrape, || {
                    HugepageMetrics::new(page_size, reserved.clone()).publish();
                });
                assert_eq!(scrape.get(HUGEPAGE_SIZE, &[]), Some(page_size as f64));
                for (node, bytes) in &reserved {
                    assert_eq!(
                        scrape.get(HUGEPAGES_RESERVED, &[("node", node)]),
                        Some(*bytes as f64),
                        "node {node}"
                    );
                }
                assert_eq!(scrape.series(HUGEPAGES_RESERVED).len(), reserved.len());
                assert_eq!(scrape.registrations(), 1 + reserved.len());
            });
    }
}
