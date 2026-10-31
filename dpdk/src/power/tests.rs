// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::time::Duration;

use super::*;
use crate::dev::{DevConfig, Ownership, PortClaim, RxOffload, TxOffloadConfig};
use crate::queue::rx::{RxQueueConfig, RxQueueIndex};
use crate::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use crate::socket::{Preference, SocketId};
use crate::test_support::{RingPort, packet_pool, start_eal};

static OWNER: concurrency::process_global::LazyLock<Ownership> =
    concurrency::process_global::LazyLock::new(|| Ownership::new().unwrap());

/// Run `body` on a thread registered as an lcore, over a started ring port whose transmit queue
/// feeds its own receive queue.
///
/// The EAL is started first, here: the thread that starts it is the main lcore, which cannot
/// register again.
fn on_a_ring(body: impl FnOnce(&LCore, &mut RxQueue<'_>, &mut TxQueue<'_>, Ring) + Send) {
    let _eal = start_eal();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let lcore = LCore::register().unwrap();
                let ring = RingPort::new();
                let config = DevConfig {
                    rx_interrupts: false,
                    num_rx_queues: 1,
                    num_tx_queues: 1,
                    num_hairpin_queues: 0,
                    tx_offloads: TxOffloadConfig::none(),
                    rx_offloads: RxOffload::NONE,
                    mtu: None,
                    rss: None,
                };
                let claim =
                    PortClaim::new(&OWNER, start_eal().dev().info(ring.index).unwrap()).unwrap();
                let mut dev = config.apply(claim).unwrap();
                dev.new_rx_queue(RxQueueConfig {
                    queue_index: RxQueueIndex(0),
                    num_descriptors: 128,
                    socket_preference: Preference::Id(SocketId::ANY),
                    offloads: RxOffload::NONE,
                    pool: packet_pool(127),
                })
                .unwrap();
                dev.new_tx_queue(TxQueueConfig {
                    queue_index: TxQueueIndex(0),
                    num_descriptors: 128,
                    socket_preference: Preference::Id(SocketId::ANY),
                    config: (),
                })
                .unwrap();
                let dev = dev.start().unwrap();
                let mut queues = dev.take_queues().unwrap();
                let mut rx = queues.take_rx(RxQueueIndex(0)).unwrap();
                let mut tx = queues.take_tx(TxQueueIndex(0)).unwrap();
                body(&lcore, &mut rx, &mut tx, Ring(ring.ring()));
            })
            .join()
            .unwrap();
    });
}

/// The ring behind a ring port, which another thread can write to.
#[derive(Clone, Copy)]
struct Ring(*mut dpdk_sys::rte_ring);

// SAFETY: a DPDK ring is multi-producer, multi-consumer, safe to use from any thread.
unsafe impl Send for Ring {}

/// Select the capabilities needed by the test, reporting why they are unavailable.
fn sleeper(lcore: &LCore, watching: bool) -> Option<Sleeper> {
    let Some(sleeper) = Sleeper::new(lcore) else {
        eprintln!("this CPU offers no power-optimized wait; nothing to test");
        return None;
    };
    if watching && !sleeper.intrinsics().monitor {
        eprintln!("this CPU cannot watch a queue; nothing to test");
        return None;
    }
    Some(sleeper)
}

/// The median of `n` runs of `f`.
fn median(n: usize, mut f: impl FnMut() -> Duration) -> Duration {
    let mut runs: Vec<Duration> = (0..n).map(|_| f()).collect();
    runs.sort();
    runs[n / 2]
}

/// The ring driver says what to watch, so a CPU that can watch anything watches it.
#[test]
fn an_idle_ring_queue_is_watched_if_the_cpu_can() {
    on_a_ring(|lcore, rx, _, _| {
        let Some(sleeper) = sleeper(lcore, false) else {
            return;
        };
        let slept = sleeper
            .sleep(lcore, [&*rx], Duration::from_micros(20))
            .unwrap();
        if sleeper.intrinsics().monitor {
            assert_eq!(slept, Slept::Watched(1));
        } else {
            assert_eq!(slept, Slept::Paused);
        }
    });
}

/// The timeout must bound an idle wait without relying on an external interrupt.
/// The lower bound allows faster hardware timers, including Zen 4's timer at twice the TSC rate,
/// while rejecting waits that return immediately.
#[test]
fn an_idle_wait_sleeps_until_its_deadline() {
    on_a_ring(|lcore, rx, _, _| {
        let Some(sleeper) = sleeper(lcore, false) else {
            return;
        };
        let took = median(101, || {
            let start = clock::now();
            sleeper
                .sleep(lcore, [&*rx], Duration::from_micros(20))
                .unwrap();
            clock::elapsed(start)
        });
        assert!(
            (Duration::from_micros(5)..Duration::from_micros(200)).contains(&took),
            "a 20 us wait took {took:?} at the median"
        );
    });
}

/// A packet already in the queue ends the wait before it starts.
#[test]
fn a_waiting_packet_cuts_a_long_wait_short() {
    on_a_ring(|lcore, rx, tx, _| {
        let Some(sleeper) = sleeper(lcore, true) else {
            return;
        };
        let unsent = tx.transmit(packet_pool(127).alloc_bulk(1).unwrap());
        assert!(unsent.is_empty());
        let took = median(11, || {
            let start = clock::now();
            sleeper
                .sleep(lcore, [&*rx], Duration::from_secs(1))
                .unwrap();
            clock::elapsed(start)
        });
        assert!(
            took < Duration::from_millis(10),
            "a one second wait on a queue holding a packet took {took:?}"
        );
        assert_eq!(rx.receive().len(), 1);
    });
}

/// A write to the watched queue wakes the core promptly, before the sleep deadline.
#[test]
#[cfg_attr(
    sanitized,
    ignore = "ThreadSanitizer reports DPDK itself: the ring orders its producer and consumer with \
              compiler barriers it cannot see, and a monitor wait reads the very address another \
              thread writes, by design"
)]
fn a_packet_from_another_thread_wakes_a_watched_queue() {
    on_a_ring(|lcore, rx, _, ring| {
        let Some(sleeper) = sleeper(lcore, true) else {
            return;
        };
        let late = median(21, || {
            let (when, sent) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let ring = ring;
                    std::thread::sleep(Duration::from_millis(3));
                    when.send(clock::now()).unwrap();
                    // A token, not an mbuf: the test takes it back off the ring itself, and the
                    // receive queue never sees it.
                    // SAFETY: the ring outlives this thread, which the scope joins.
                    assert_eq!(
                        unsafe { dpdk_sys::rte_ring_enqueue(ring.0, core::ptr::dangling_mut()) },
                        0
                    );
                });
                // SAFETY: the ring outlives the port.
                while unsafe { dpdk_sys::rte_ring_count(ring.0) } == 0 {
                    sleeper
                        .sleep(lcore, [&*rx], Duration::from_secs(1))
                        .unwrap();
                }
                let woke = clock::now();
                let mut token = core::ptr::null_mut();
                // SAFETY: as above; this takes back the one token the other thread put there.
                assert_eq!(
                    unsafe { dpdk_sys::rte_ring_dequeue(ring.0, &raw mut token) },
                    0
                );
                woke.duration_since(sent.recv().unwrap())
            })
        });
        // Far short of the one second deadline, but loose enough for a loaded, instrumented CI
        // runner, where a median of 100-450 µs has been seen.
        assert!(
            late < Duration::from_millis(1),
            "the watched queue woke the core {late:?} after the write, at the median"
        );
    });
}

/// A wait the CPU cannot have is not slept at all.
#[test]
fn no_wait_is_no_sleeper() {
    on_a_ring(|lcore, _, _, _| {
        assert!(Sleeper::with(lcore, Intrinsics::default()).is_none());
    });
}
