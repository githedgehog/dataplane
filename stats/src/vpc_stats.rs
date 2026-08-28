// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VPC statistics store
//! Maintains per-VPC and per-VPC-pair counters and rates.
//! Iteratable for gRPC exposure.

use concurrency::sync::Arc;
use concurrency::sync::RwLock as StdRwLock;
use std::collections::HashMap;
use tokio::sync::RwLock;
use vpcmap::VpcDiscriminant;

use std::collections::HashSet;

pub type VpcId = VpcDiscriminant;
pub type VpcPairKey = (VpcId, VpcId);

#[derive(Debug, Clone, Copy, Default)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Rates {
    pub pps: f64,
    pub bps: f64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlowStats {
    pub ctr: Counters,   // monotonic counters
    pub rate: Rates,     // latest snapshot of rates
    pub drops: Counters, // drops (packets + optional bytes)
}

/// Everything the store holds, read at one instant. See [`VpcStatsStore::snapshot`].
#[derive(Debug, Default)]
pub struct StatsSnapshot {
    pub names: HashMap<VpcId, String>,
    pub pairs: Vec<(VpcPairKey, FlowStats)>,
    pub vpcs: Vec<(VpcId, FlowStats)>,
}

#[derive(Debug, Default)]
pub struct VpcStatsStore {
    /// Directional (src -> dst)
    pair_stats: RwLock<HashMap<VpcPairKey, FlowStats>>,
    /// Per-VPC totals (by src)
    vpc_stats: RwLock<HashMap<VpcId, FlowStats>>,
    /// Human-friendly names keyed by discriminant (seeded from config / refreshed by dpstats)
    vpc_names: StdRwLock<HashMap<VpcId, String>>,
}

impl VpcStatsStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_many_vpc_names_sync(&self, pairs: Vec<(VpcId, String)>) {
        let mut m = self.vpc_names.write();
        for (id, name) in pairs {
            m.insert(id, name);
        }
    }

    pub fn set_vpc_name_sync(&self, id: VpcId, name: String) {
        let mut m = self.vpc_names.write();
        m.insert(id, name);
    }

    pub fn name_of(&self, id: VpcId) -> Option<String> {
        self.vpc_names.read().get(&id).cloned()
    }

    // ---------- Pair (src -> dst) ----------
    pub async fn add_pair_counts(&self, src: VpcId, dst: VpcId, add_packets: u64, add_bytes: u64) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
    }

    pub async fn set_pair_rates(&self, src: VpcId, dst: VpcId, pps: f64, bps: f64) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    pub async fn add_pair_drops(&self, src: VpcId, dst: VpcId, add_packets: u64, add_bytes: u64) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.drops.packets = e.drops.packets.saturating_add(add_packets);
        e.drops.bytes = e.drops.bytes.saturating_add(add_bytes);
    }

    pub async fn record_pair(
        &self,
        src: VpcId,
        dst: VpcId,
        add_packets: u64,
        add_bytes: u64,
        pps: f64,
        bps: f64,
    ) {
        let mut map = self.pair_stats.write().await;
        let e = map.entry((src, dst)).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    // ---------- Per-VPC (src) totals ----------
    pub async fn add_vpc_counts(&self, vpc: VpcId, add_packets: u64, add_bytes: u64) {
        let mut map = self.vpc_stats.write().await;
        let e = map.entry(vpc).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
    }

    pub async fn add_vpc_drops(&self, vpc: VpcId, add_packets: u64, add_bytes: u64) {
        let mut map = self.vpc_stats.write().await;
        let e = map.entry(vpc).or_default();
        e.drops.packets = e.drops.packets.saturating_add(add_packets);
        e.drops.bytes = e.drops.bytes.saturating_add(add_bytes);
    }

    pub async fn set_vpc_rates(&self, vpc: VpcId, pps: f64, bps: f64) {
        let mut map = self.vpc_stats.write().await;
        let e = map.entry(vpc).or_default();
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    pub async fn record_vpc(
        &self,
        vpc: VpcId,
        add_packets: u64,
        add_bytes: u64,
        pps: f64,
        bps: f64,
    ) {
        let mut map = self.vpc_stats.write().await;
        let e = map.entry(vpc).or_default();
        e.ctr.packets = e.ctr.packets.saturating_add(add_packets);
        e.ctr.bytes = e.ctr.bytes.saturating_add(add_bytes);
        e.rate.pps = pps;
        e.rate.bps = bps;
    }

    /// Hand each of these VNIs to a new tenant: drop what the outgoing one accumulated, then
    /// publish the incoming one's name.
    ///
    /// Both halves and *that order*, in one place, because the order is the whole point and it is
    /// not visible from either half alone. A discriminant is recycled when one tenant leaves and
    /// the next is given the same VNI, and if that happens in a single configuration change the
    /// discriminant is never absent -- only its name changes -- so [`Self::prune_to_vpcs`], which
    /// keys on absence, cannot see it. Without the forget, the incoming tenant's first scrape
    /// reports every packet the outgoing one ever sent.
    ///
    /// The order matters because a reader takes the names and the counters as two separate
    /// snapshots -- `handle_get_dataplane_status` does exactly that -- and there is no lock held
    /// across both. A read landing between them pairs one with stale data from the other, so
    /// whichever is written first decides what the worst such read looks like. Counters first
    /// means an old name against no counters. Names first would mean the incoming tenant's name
    /// against the outgoing tenant's traffic, which is the thing this exists to prevent.
    pub async fn hand_over(&self, handovers: &[(VpcId, String)]) {
        let forget: HashSet<VpcId> = handovers.iter().map(|(id, _)| *id).collect();
        {
            let mut pairs = self.pair_stats.write().await;
            pairs.retain(|(src, dst), _| !forget.contains(src) && !forget.contains(dst));
        }
        {
            let mut vpcs = self.vpc_stats.write().await;
            vpcs.retain(|vpc, _| !forget.contains(vpc));
        }
        let mut names = self.vpc_names.write();
        for (id, name) in handovers {
            names.insert(*id, name.clone());
        }
    }

    pub async fn prune_to_vpcs(&self, alive: &HashSet<VpcId>) {
        {
            let mut pairs = self.pair_stats.write().await;
            pairs.retain(|(src, dst), _| alive.contains(src) && alive.contains(dst));
        }
        {
            let mut vpcs = self.vpc_stats.write().await;
            vpcs.retain(|vpc, _| alive.contains(vpc));
        }
        {
            let mut names = self.vpc_names.write();
            names.retain(|vpc, _| alive.contains(vpc));
        }
    }

    /// Names and counters as they were at one instant.
    ///
    /// The three maps live behind three locks, so taking them one at a time gives a reader a
    /// name from one moment and counters from another -- and during a handover that means one
    /// tenant's name against another tenant's traffic. Reversing the reader's order does not help:
    /// whichever it reads first is the one that can be stale. Nor does reversing the *writer's*,
    /// which only decides which of the two mispairings a reader gets. There is no ordering of two
    /// separate reads that makes them agree; the read has to be one thing.
    ///
    /// It is safe to hold all three at once because every site in this file acquires them in this
    /// same order -- pairs, then vpcs, then names -- so there is no cycle to wait on. Keep it that
    /// way. `vpc_names` is a synchronous lock and is taken last for that reason: nothing awaits
    /// while it is held.
    pub async fn snapshot(&self) -> StatsSnapshot {
        let pairs = self.pair_stats.read().await;
        let vpcs = self.vpc_stats.read().await;
        let names = self.vpc_names.read();
        StatsSnapshot {
            pairs: pairs.iter().map(|(k, v)| (*k, *v)).collect(),
            vpcs: vpcs.iter().map(|(k, v)| (*k, *v)).collect(),
            names: names.clone(),
        }
    }

    // ---------- Snapshots ----------
    pub async fn snapshot_pairs(&self) -> Vec<(VpcPairKey, FlowStats)> {
        let map = self.pair_stats.read().await;
        map.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub async fn snapshot_vpcs(&self) -> Vec<(VpcId, FlowStats)> {
        let map = self.vpc_stats.read().await;
        map.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Snapshot all VPC names. Declared async to match callers that `.await` it,
    /// but it does not perform any awaits internally.
    pub async fn snapshot_names(&self) -> HashMap<VpcId, String> {
        self.vpc_names.read().clone()
    }
}

/// What a reader of the store can observe while it is being written.
///
/// # Why a race and not a model
///
/// The store's counters live behind `tokio::sync::RwLock`, which neither shuttle nor loom can
/// drive, so this is a stress test rather than a model check and it says so. What makes it worth
/// having anyway is that the thing under test is an *ordering*, and an ordering is exactly what a
/// comment cannot enforce: swap the two halves of [`VpcStatsStore::hand_over`] and nothing else in
/// the tree notices.
///
/// Deadlock is not what is being looked for and would not be found here. Every lock in the store is
/// taken and released on its own -- nothing is ever held across the acquisition of another, in the
/// store or in `mgmt`'s handler -- so there is no cycle to construct. The hazard is the benign
/// looking one: a reader takes the names and the counters as two snapshots, so it can pair a name
/// from after a write with counters from before it.
#[cfg(test)]
mod under_readers {
    use super::{VpcId, VpcStatsStore};
    use concurrency::sync::Arc;
    use concurrency::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use net::vxlan::Vni;
    use vpcmap::VpcDiscriminant;

    /// Handovers the writer performs.
    ///
    /// This is a race, so the number is a detection rate rather than a taste. Measured against the
    /// two-snapshot reader this replaced: 2000 caught it in 2 runs out of 3, 20000 in 10 out of 10,
    /// for about a fifth of a second.
    const HANDOVERS: u64 = 20_000;
    /// Packets each tenant is credited with before it hands the VNI on.
    const SENT: u64 = 1_000;

    fn vpc(vni: u32) -> VpcId {
        VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap_or_else(|_| unreachable!()))
    }

    /// A reader never sees a tenant's name against the previous tenant's traffic.
    ///
    /// The reader is shaped like `handle_get_dataplane_status`, which is what reads this store in
    /// production.
    ///
    /// **Every tenant is credited with a different number of packets**, and that is not
    /// decoration. The first version had them all send the same amount, so a count inherited whole
    /// from the previous tenant was arithmetically indistinguishable from the tenant's own, and the
    /// test passed with the store's writes in either order. Tenant `t` sends `SENT + t`, so a
    /// credited count names its owner.
    ///
    /// That fixed test then failed against correct code, which is what produced
    /// [`VpcStatsStore::snapshot`]: reading names and counters as two snapshots pairs a name from
    /// one instant with counters from another, and no ordering of the two reads -- or of the two
    /// writes -- makes them agree. Observed directly: tenant 7's name exported carrying tenant 8's
    /// traffic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reader_never_sees_a_name_against_the_previous_tenants_traffic() {
        /// What tenant `t` sends, distinct for every tenant.
        fn sent_by(tenant: u64) -> u64 {
            SENT + tenant
        }

        let store = VpcStatsStore::new();
        let (src, dst) = (vpc(100), vpc(200));
        let done = Arc::new(AtomicBool::new(false));
        // Reads that saw a tenant's name before it had been credited with anything: the gap
        // between the handover and the incoming tenant's first packets.
        let saw_the_window = Arc::new(AtomicU64::new(0));
        // Reads that saw a tenant's name against that tenant's own traffic.
        let saw_a_tenant_settled = Arc::new(AtomicU64::new(0));

        let reader = tokio::spawn({
            let store = Arc::clone(&store);
            let done = Arc::clone(&done);
            let saw_the_window = Arc::clone(&saw_the_window);
            let saw_a_tenant_settled = Arc::clone(&saw_a_tenant_settled);
            async move {
                while !done.load(Ordering::Relaxed) {
                    let taken = store.snapshot().await;
                    let (names, pairs) = (taken.names, taken.pairs);

                    let Some(name) = names.get(&dst) else {
                        continue;
                    };
                    let tenant: u64 = name.parse().unwrap_or_else(|e| unreachable!("{e:?}"));
                    let credited = pairs
                        .iter()
                        .find(|&&((from, to), _)| from == src && to == dst)
                        .map_or(0, |&(_, stats)| stats.ctr.packets);

                    if credited == 0 {
                        saw_the_window.fetch_add(1, Ordering::Relaxed);
                    } else if credited == sent_by(tenant) {
                        saw_a_tenant_settled.fetch_add(1, Ordering::Relaxed);
                    } else {
                        panic!(
                            "tenant {tenant} sends {}, but is exported carrying {credited} -- \
                             which is what tenant {} sent",
                            sent_by(tenant),
                            credited.saturating_sub(SENT)
                        );
                    }
                }
            }
        });

        for tenant in 0..HANDOVERS {
            store.hand_over(&[(dst, tenant.to_string())]).await;
            tokio::task::yield_now().await;
            store
                .add_pair_counts(src, dst, sent_by(tenant), sent_by(tenant) * 500)
                .await;
            tokio::task::yield_now().await;
        }
        done.store(true, Ordering::Relaxed);
        reader.await.unwrap_or_else(|e| unreachable!("{e:?}"));

        // Both states have to have been reached, or the run says nothing: never seeing the window
        // means the interleaving never happened, and never seeing a settled tenant means the
        // reader was only ever looking at empty counters.
        assert!(
            saw_the_window.load(Ordering::Relaxed) > 0,
            "no read landed between a handover and the incoming tenant's first packets"
        );
        assert!(
            saw_a_tenant_settled.load(Ordering::Relaxed) > 0,
            "no read ever saw a tenant against its own traffic"
        );
    }

    /// The counters really are dropped, rather than the name change being all that happens.
    ///
    /// Without this the property above is satisfied by a `hand_over` that forgets nothing, so long
    /// as no tenant ever sends anything.
    #[tokio::test]
    async fn a_handover_drops_what_the_outgoing_tenant_accumulated() {
        let store = VpcStatsStore::new();
        let (src, dst) = (vpc(100), vpc(200));
        store.add_pair_counts(src, dst, SENT, SENT * 500).await;
        store.add_vpc_counts(dst, SENT, SENT * 500).await;
        assert_eq!(
            store
                .snapshot_pairs()
                .await
                .first()
                .map(|&(_, fs)| (fs.ctr.packets, fs.ctr.bytes)),
            Some((SENT, SENT * 500))
        );

        store.hand_over(&[(dst, "next".to_string())]).await;

        assert!(
            store.snapshot_pairs().await.is_empty(),
            "the outgoing tenant's pair counters survived the handover"
        );
        assert!(
            store.snapshot_vpcs().await.is_empty(),
            "the outgoing tenant's totals survived the handover"
        );
        assert_eq!(store.name_of(dst).as_deref(), Some("next"));
    }
}
