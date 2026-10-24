// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A worker's handle on the shared flow table.

use super::expiry::{ExpirySweep, FlowTimers, Schedule, SideTimer, TimerRegistry, WorkerTimer};
use super::table::{FlowTable, FlowTableError, Insertion, PairInsertion};
use concurrency::sync::Arc;
use net::flows::FlowInfo;
use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;
use std::time::Instant;

/// One worker's handle on the shared [`FlowTable`], and the only way to put flows in it.
///
/// Every flow inserted through a handle is put on the handle's timer wheel, which expires it. The
/// wheel belongs to the thread that created the handle: clones share it, and the type is not
/// `Send`. The owning thread drives expiry by calling [`WorkerFlowTable::expire`] regularly, for
/// example once per poll loop. Other threads may invalidate flows at any time; the removal happens
/// on the owner's next call.
///
/// Lookups and every other read go through [`Deref`] to the shared table.
#[derive(Debug, Clone)]
pub struct WorkerFlowTable {
    table: Arc<FlowTable>,
    timers: Rc<RefCell<FlowTimers>>,
}

impl WorkerFlowTable {
    /// A handle on `table` for the calling thread, with an empty timer wheel.
    #[must_use]
    pub fn new(table: Arc<FlowTable>) -> Self {
        Self {
            table,
            timers: Rc::new(RefCell::new(FlowTimers::new())),
        }
    }

    /// A handle on `table` for the calling thread, whose wheel also takes the [`SideTimer`]s other
    /// threads schedule through `registry`.
    #[must_use]
    pub fn registered(table: Arc<FlowTable>, registry: &TimerRegistry) -> Self {
        let handle = Self::new(table);
        registry.register(handle.timers.borrow().remote());
        handle
    }

    /// The shared table this handle points at.
    #[must_use]
    pub fn shared(&self) -> &Arc<FlowTable> {
        &self.table
    }

    /// Expire up to `budget` flows that are due at `now` or were invalidated, and remove them from
    /// the table. Work left over carries over to the next call ([`ExpirySweep::behind`]).
    #[allow(clippy::must_use_candidate, reason = "workers sweep for the effect")]
    pub fn expire(&self, now: Instant, budget: usize) -> ExpirySweep {
        self.timers.borrow_mut().sweep(&self.table, now, budget)
    }

    /// Expire everything that is due at `now`, however long it takes.
    #[allow(
        clippy::must_use_candidate,
        reason = "callers may sweep for the effect"
    )]
    pub fn expire_all(&self, now: Instant) -> usize {
        let mut removed = 0;
        loop {
            let sweep = self.expire(now, usize::MAX);
            removed += sweep.removed;
            if !sweep.behind() {
                return removed;
            }
            if sweep.removed == 0 && sweep.pending > 0 {
                // The table is busy (resharding or admitting a pair on another thread).
                std::thread::yield_now();
            }
        }
    }

    /// The number of flows on this handle's wheel.
    #[must_use]
    pub fn timers(&self) -> usize {
        self.timers.borrow().len()
    }

    /// Add a flow to the table. See [`FlowTable`] for the semantics of each insertion.
    ///
    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] when the table has reached its hard limit.
    pub fn insert(&self, flow_info: FlowInfo) -> Result<Option<Arc<FlowInfo>>, FlowTableError> {
        self.table
            .insert_timed(&mut self.timers.borrow_mut(), flow_info)
    }

    /// Add a flow to the table from a shared [`FlowInfo`].
    ///
    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] when the table has reached its hard limit.
    pub fn insert_from_arc(
        &self,
        flow_info: &Arc<FlowInfo>,
    ) -> Result<Option<Arc<FlowInfo>>, FlowTableError> {
        self.table
            .insert_from_arc_timed(&mut self.timers.borrow_mut(), flow_info)
    }

    /// Add a flow unless a live flow holds its key.
    ///
    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] if the key is free and the table is full.
    pub fn insert_if_absent(&self, val: &Arc<FlowInfo>) -> Result<Insertion, FlowTableError> {
        self.table
            .insert_if_absent_timed(&mut self.timers.borrow_mut(), val)
    }

    /// Install a fresh related pair without replacing a live owner of either key.
    ///
    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] if the forward key is free and the table is full.
    ///
    /// # Panics
    ///
    /// Panics if the flows are not distinct, detached, and related to each other.
    pub fn insert_pair_if_absent(
        &self,
        forward: &Arc<FlowInfo>,
        reverse: &Arc<FlowInfo>,
    ) -> Result<PairInsertion, FlowTableError> {
        self.table
            .insert_pair_if_absent_timed(&mut self.timers.borrow_mut(), forward, reverse)
    }

    /// As [`WorkerFlowTable::insert_pair_if_absent`], but let `admit` veto the insertion.
    ///
    /// # Errors
    ///
    /// Returns [`FlowTableError::CapacityExceeded`] if the forward key is free and the table is full.
    ///
    /// # Panics
    ///
    /// Panics if the flows are not distinct, detached, and related to each other, or if `admit`
    /// inserts through this handle.
    pub fn insert_pair_if_admitted(
        &self,
        forward: &Arc<FlowInfo>,
        reverse: &Arc<FlowInfo>,
        admit: impl FnOnce() -> bool,
    ) -> Result<Option<PairInsertion>, FlowTableError> {
        self.table.insert_pair_if_admitted_timed(
            &mut self.timers.borrow_mut(),
            forward,
            reverse,
            admit,
        )
    }
}

impl Schedule for WorkerFlowTable {
    /// Put `timer` on this handle's wheel, on the calling thread.
    fn schedule(&self, timer: Box<dyn SideTimer>) {
        self.timers.borrow_mut().insert(WorkerTimer::Side(timer));
    }
}

impl Deref for WorkerFlowTable {
    type Target = FlowTable;

    fn deref(&self) -> &FlowTable {
        &self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_table::TimerRegistry;
    use net::FlowKey;
    use net::flows::FlowStatus;
    use net::flows::flow_key::FlowAddrs;
    use net::ipv4::UnicastIpv4Addr;
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;
    use net::{IpProtoKey, TcpProtoKey};
    use std::time::Duration;

    fn key(port: u16) -> FlowKey {
        FlowKey::new(
            Some(VpcDiscriminant::VNI(Vni::new_checked(7).unwrap())),
            FlowAddrs::V4 {
                src: UnicastIpv4Addr::new("10.1.0.1".parse().unwrap()).unwrap(),
                dst: UnicastIpv4Addr::new("10.2.0.1".parse().unwrap()).unwrap(),
            },
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(port).unwrap(),
                dst_port: TcpPort::new_checked(443).unwrap(),
            }),
        )
    }

    fn flows() -> WorkerFlowTable {
        WorkerFlowTable::new(Arc::new(FlowTable::default()))
    }

    /// Publication and timer binding are separate: invalidation or removal on another thread can
    /// reach a flow before its worker has bound the timer. Neither ordering may lose cancellation.
    #[concurrency::test]
    fn binding_a_timer_races_invalidation_and_detachment() {
        for detach in [false, true] {
            let flow = Arc::new(FlowInfo::new(
                key(6),
                clock::now() + Duration::from_secs(60),
            ));
            flow.update_status(FlowStatus::Active);
            let elsewhere = Arc::clone(&flow);
            let cancel = concurrency::thread::spawn(move || {
                if detach {
                    elsewhere.detach();
                } else {
                    elsewhere.invalidate();
                }
            });
            let mut timers = FlowTimers::new();
            timers.schedule(&flow);
            cancel.join().unwrap();

            timers.sweep(&FlowTable::default(), clock::now(), usize::MAX);
            assert_eq!(
                timers.len(),
                0,
                "a cancelled flow must not wait for its deadline"
            );
        }
    }

    /// A flow inserted after a longer-lived one, but due before it, still expires within a tick of
    /// its own deadline: the wheel is anchored when the first flow goes on it, not at that flow's
    /// deadline.
    #[tokio::test(start_paused = true)]
    async fn a_shorter_flow_inserted_later_expires_on_time() {
        let flows = flows();
        let now = clock::now();
        flows
            .insert(FlowInfo::new(key(1), now + Duration::from_secs(60)))
            .unwrap();
        flows
            .insert(FlowInfo::new(key(2), now + Duration::from_secs(1)))
            .unwrap();
        // A worker sweeps all the time: here once before the short flow is due, which moves its
        // timer to a later bucket, and once just after.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(flows.expire_all(clock::now()), 0);
        tokio::time::sleep(Duration::from_millis(520)).await;
        assert_eq!(flows.expire_all(clock::now()), 1);
        assert!(flows.lookup(&key(2)).is_none());
        assert!(flows.lookup(&key(1)).is_some());
        assert_eq!(flows.timers(), 1);
    }

    /// A flow invalidated on another thread leaves the table on its owner's next sweep, long before
    /// its deadline, and takes its timer with it.
    #[tokio::test(start_paused = true)]
    async fn a_flow_invalidated_elsewhere_is_removed_by_its_owner() {
        let flows = flows();
        let flow = Arc::new(FlowInfo::new(
            key(3),
            clock::now() + Duration::from_mins(30),
        ));
        flows.insert_from_arc(&flow).unwrap();
        let elsewhere = Arc::clone(&flow);
        std::thread::spawn(move || elsewhere.invalidate())
            .join()
            .unwrap();
        assert_eq!(flows.expire_all(clock::now()), 1);
        assert_eq!(flow.status(), FlowStatus::Cancelled);
        assert!(flows.lookup(&key(3)).is_none());
        assert_eq!(flows.live_len(), 0);
        assert_eq!(flows.timers(), 0);
    }

    /// A pair whose admission is refused is not put on the wheel.
    #[tokio::test(start_paused = true)]
    async fn a_refused_pair_leaves_no_timers() {
        let flows = flows();
        let (forward, reverse) = FlowInfo::related_pair(
            clock::now() + Duration::from_secs(5),
            key(4),
            net::flows::FlowInfoFlags::INITIATOR,
            key(5),
            net::flows::FlowInfoFlags::default(),
        )
        .unwrap();
        assert!(
            flows
                .insert_pair_if_admitted(&forward, &reverse, || false)
                .unwrap()
                .is_none()
        );
        assert_eq!(flows.timers(), 0);
        assert!(!forward.has_timer());
    }

    /// A side timer that counts its firings and stays on the wheel `rearm` times.
    struct Counting {
        deadline: Instant,
        fired: Arc<concurrency::sync::atomic::AtomicUsize>,
        rearm: usize,
    }

    impl SideTimer for Counting {
        fn deadline(&self) -> Instant {
            self.deadline
        }

        fn fire(&mut self, now: Instant) -> bool {
            self.fired
                .fetch_add(1, concurrency::sync::atomic::Ordering::Relaxed);
            if self.rearm == 0 {
                return false;
            }
            self.rearm -= 1;
            self.deadline = now + Duration::from_secs(1);
            true
        }
    }

    fn counting(
        after: Duration,
        rearm: usize,
    ) -> (Box<Counting>, Arc<concurrency::sync::atomic::AtomicUsize>) {
        let fired = Arc::new(concurrency::sync::atomic::AtomicUsize::new(0));
        let timer = Box::new(Counting {
            deadline: clock::now() + after,
            fired: fired.clone(),
            rearm,
        });
        (timer, fired)
    }

    /// Timers scheduled before any worker registered wait for the first one; later ones go to the
    /// registered workers in turn, are adopted on each worker's next sweep and fire there.
    #[tokio::test(start_paused = true)]
    async fn remote_side_timers_reach_a_worker_and_fire_there() {
        use concurrency::sync::atomic::Ordering::Relaxed;
        let registry = TimerRegistry::new();
        let (early, early_fired) = counting(Duration::from_secs(1), 0);
        registry.schedule(early);
        assert_eq!(registry.parked(), 1);

        let table = Arc::new(FlowTable::default());
        let first = WorkerFlowTable::registered(table.clone(), &registry);
        assert_eq!(registry.parked(), 0);
        let second = WorkerFlowTable::registered(table, &registry);
        assert_eq!(registry.workers(), 2);
        let (a, a_fired) = counting(Duration::from_secs(1), 0);
        let (b, b_fired) = counting(Duration::from_secs(1), 0);
        registry.schedule(a);
        registry.schedule(b);

        first.expire_all(clock::now());
        second.expire_all(clock::now());
        assert_eq!(
            first.timers() + second.timers(),
            3,
            "every timer was adopted by some worker"
        );
        assert!(
            first.timers() >= 1 && second.timers() >= 1,
            "the workers took turns"
        );

        tokio::time::sleep(Duration::from_millis(1020)).await;
        first.expire_all(clock::now());
        second.expire_all(clock::now());
        let fired = [&early_fired, &a_fired, &b_fired].map(|f| f.load(Relaxed));
        assert_eq!(fired, [1, 1, 1]);
        assert_eq!(first.timers() + second.timers(), 0);
    }

    /// A side timer that asks to stay goes back on the wheel at its new deadline, and fires again.
    #[tokio::test(start_paused = true)]
    async fn a_side_timer_can_stay_on_the_wheel() {
        use concurrency::sync::atomic::Ordering::Relaxed;
        let flows = flows();
        let (timer, fired) = counting(Duration::from_secs(1), 2);
        flows.schedule(timer);
        for expected in 1..=3 {
            tokio::time::sleep(Duration::from_millis(1020)).await;
            flows.expire_all(clock::now());
            assert_eq!(fired.load(Relaxed), expected);
        }
        assert_eq!(flows.timers(), 0, "done after its last firing");
    }
}
