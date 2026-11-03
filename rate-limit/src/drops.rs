// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What drop rules dropped, by source VPC.

use std::collections::BTreeMap;

use concurrency::sync::atomic::{AtomicU64, Ordering};
use concurrency::sync::{Arc, Mutex};
use net::vxlan::Vni;

/// One worker's count of one source VPC's dropped packets. Only that worker writes it, so a
/// flood dropped on many workers never contends on a counter.
#[derive(Debug, Default)]
pub(crate) struct Dropped(AtomicU64);

impl Dropped {
    /// Count a dropped packet; only the owning worker calls this.
    pub(crate) fn add(&self) {
        let n = self.0.load(Ordering::Relaxed);
        self.0.store(n + 1, Ordering::Relaxed);
    }
}

/// The packets drop rules dropped, by source VPC, across workers, since the process started:
/// the counts outlive the rules, so a total never goes back.
#[derive(Debug, Default)]
pub(crate) struct Drops {
    workers: Mutex<BTreeMap<Vni, Vec<Arc<Dropped>>>>,
    /// Held while publishing, so that concurrent scrapes publish one after the other.
    publishing: Mutex<()>,
}

impl Drops {
    /// A new count of `vni`'s drops, for one worker.
    pub(crate) fn counter(&self, vni: Vni) -> Arc<Dropped> {
        let counter = Arc::new(Dropped::default());
        self.workers
            .lock()
            .entry(vni)
            .or_default()
            .push(Arc::clone(&counter));
        counter
    }

    /// The total by source VPC.
    pub(crate) fn totals(&self) -> BTreeMap<Vni, u64> {
        self.workers
            .lock()
            .iter()
            .map(|(vni, workers)| {
                (
                    *vni,
                    workers.iter().map(|w| w.0.load(Ordering::Relaxed)).sum(),
                )
            })
            .collect()
    }

    /// Publish the totals to the installed metrics recorder, as absolute values: the totals only
    /// grow, and scrapes publish one at a time, each what it read, so none sets an older total
    /// after a newer one.
    pub(crate) fn publish_metrics(&self) {
        let _publishing = self.publishing.lock();
        let totals = self.totals();
        if totals.is_empty() {
            return;
        }
        metrics::describe_counter!(
            "ingress_policy_dropped_packets_total",
            metrics::Unit::Count,
            "Packets the ingress policy's drop rules dropped in software, by source VNI"
        );
        for (vni, total) in totals {
            metrics::counter!("ingress_policy_dropped_packets_total", "vni" => vni.as_u32().to_string())
                .absolute(total);
        }
    }
}
