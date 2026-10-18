// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK ports for a generator: bringing one up, and its queues as a [`Wire`].

use dpdk::dev::{Dev, DevConfig, DevIndex, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::mem::{MbufArray, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket::Preference;
use flowgen_report::Sample;
use net::buffer::Append;

use crate::drive::Wire;
use crate::ledger::Ledger;
use crate::schedule::Slot;
use crate::sender::{Clock, Sender};

/// How a generator's port is set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSetup {
    /// Receive and transmit queues each.
    pub queues: u16,
    /// Descriptors per queue.
    pub descriptors: u16,
    /// Mbufs in the port's pool: enough for every descriptor and every frame in flight.
    pub pool_size: u32,
    /// The MTU, or the device's default.
    pub mtu: Option<u16>,
}

/// Why a generator's port could not be brought up.
#[derive(Debug, thiserror::Error)]
#[error("port {index}: {what}")]
pub struct PortError {
    /// The port.
    pub index: DevIndex,
    /// What went wrong.
    pub what: String,
}

/// Claim, configure and start port `index` with `setup`: no RSS, no offloads, every queue
/// unsteered. Returns the started device and the pool its queues use.
///
/// # Errors
///
/// If the port cannot be claimed, configured, given its queues or started.
pub fn start(
    eal: &Eal,
    index: DevIndex,
    setup: PortSetup,
) -> Result<(Dev<'_, Started>, Pool<'_>), PortError> {
    let fail = |what: String| PortError { index, what };
    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new(
                format!("flowgen_{index}"),
                PoolParams {
                    size: setup.pool_size,
                    ..Default::default()
                },
            )
            .map_err(|e| fail(format!("invalid pool: {e:?}")))?,
        )
        .map_err(|e| fail(format!("no pool: {e:?}")))?;
    let claim = eal
        .claim(index)
        .map_err(|e| fail(format!("cannot claim: {e}")))?;
    let mut dev = DevConfig {
        num_rx_queues: setup.queues,
        num_tx_queues: setup.queues,
        num_hairpin_queues: 0,
        tx_offloads: TxOffloadConfig::none(),
        rx_offloads: RxOffload::NONE,
        mtu: setup.mtu,
        rss: None,
    }
    .apply(claim)
    .map_err(|e| fail(format!("cannot configure: {e}")))?;
    for queue in 0..setup.queues {
        dev.new_rx_queue(RxQueueConfig {
            queue_index: RxQueueIndex(queue),
            num_descriptors: setup.descriptors,
            socket_preference: Preference::Dev(index),
            offloads: RxOffload::NONE,
            pool: pool.clone(),
        })
        .map_err(|e| fail(format!("no rx queue {queue}: {e:?}")))?;
        dev.new_tx_queue(TxQueueConfig {
            queue_index: TxQueueIndex(queue),
            num_descriptors: setup.descriptors,
            socket_preference: Preference::Dev(index),
            config: (),
        })
        .map_err(|e| fail(format!("no tx queue {queue}: {e:?}")))?;
    }
    let dev = dev
        .start()
        .map_err(|e| fail(format!("cannot start: {e}")))?;
    Ok((dev, pool))
}

/// Every queue of a started port, taken from it.
pub struct Owned<'d> {
    /// Receive queues.
    pub rx: Vec<RxQueue<'d>>,
    /// Transmit queues.
    pub tx: Vec<TxQueue<'d>>,
}

/// Take `queues` receive and transmit queues each from `dev`.
///
/// # Errors
///
/// If the queues were taken already, or the device has fewer.
pub fn take<'d>(dev: &'d Dev<'_, Started>, queues: u16) -> Result<Owned<'d>, PortError> {
    let index = dev.info().index();
    let fail = |what: String| PortError { index, what };
    let mut taken = dev
        .take_queues()
        .ok_or_else(|| fail("queues already taken".to_string()))?;
    let rx = (0..queues)
        .map(|q| {
            taken
                .take_rx(RxQueueIndex(q))
                .ok_or_else(|| fail(format!("no rx queue {q}")))
        })
        .collect::<Result<_, _>>()?;
    let tx = (0..queues)
        .map(|q| {
            taken
                .take_tx(TxQueueIndex(q))
                .ok_or_else(|| fail(format!("no tx queue {q}")))
        })
        .collect::<Result<_, _>>()?;
    Ok(Owned { rx, tx })
}

/// `sample`, with `dev`'s device counters under `port.<name>.`.
#[must_use]
pub fn counters(dev: &Dev<'_, Started>, name: &str, sample: Sample) -> Sample {
    let Ok(stats) = dev.stats() else {
        return sample;
    };
    [
        ("rx_packets", stats.ipackets),
        ("tx_packets", stats.opackets),
        ("rx_bytes", stats.ibytes),
        ("tx_bytes", stats.obytes),
        ("rx_missed", stats.imissed),
        ("rx_errors", stats.ierrors),
        ("tx_errors", stats.oerrors),
        ("rx_no_mbuf", stats.rx_nombuf),
    ]
    .into_iter()
    .fold(sample, |sample, (counter, n)| {
        sample.counter(format!("port.{name}.{counter}"), n)
    })
}

/// The queues a stream is sent and received on, and the pool its frames come from.
pub struct Queues<'q, 'd> {
    /// Where frames are sent.
    pub tx: &'q mut [TxQueue<'d>],
    /// Where they come back.
    pub rx: &'q mut [RxQueue<'d>],
    /// What they are built in.
    pub pool: &'q Pool<'d>,
}

impl Wire for Queues<'_, '_> {
    /// Offer what `sender` would send now, from the pool, spreading flows over the transmit
    /// queues; count what the queues took. Nothing is sent if the pool has nothing to spare,
    /// which is back-pressure from frames still in flight, not an error.
    fn send(&mut self, sender: &mut Sender, ledger: &mut Ledger, clock: &Clock) -> usize {
        let packets = sender.plan(ledger.total_offered());
        if packets.is_empty() {
            return 0;
        }
        let Ok(mut mbufs) = self.pool.alloc_bulk(packets.len()) else {
            sender.deferred(&packets);
            return 0;
        };
        let queues = &mut *self.tx;
        let mut by_queue: Vec<(MbufArray<'_>, Vec<Slot>)> = (0..queues.len())
            .map(|_| (MbufArray::new_empty(), Vec::new()))
            .collect();
        for (mbuf, &slot) in mbufs.drain_all().zip(&packets) {
            let mut mbuf = mbuf;
            let (bytes, queue) = sender.stamp(slot, clock.now_ns());
            let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
            match mbuf.append(len) {
                Ok(room) => room.copy_from_slice(bytes),
                Err(_) => continue, // the template outgrew the mbuf: a misconfigured stream
            }
            let queue = queue.min(queues.len().saturating_sub(1));
            let (batch, sent) = &mut by_queue[queue];
            if batch.try_push(mbuf).is_ok() {
                sent.push(slot);
            }
        }
        let mut total = 0;
        for (queue, (batch, packets)) in queues.iter_mut().zip(by_queue) {
            let offered = batch.len();
            let refused = queue.transmit(batch).len();
            let accepted = offered - refused;
            for &slot in &packets[..accepted] {
                sender.accepted(slot, ledger);
            }
            sender.refused(&packets[accepted..], ledger);
            total += accepted;
        }
        total
    }

    /// Send `frame` on the first transmit queue.
    fn send_frame(&mut self, frame: &[u8]) -> bool {
        let (Some(queue), Ok(len)) = (self.tx.first_mut(), u16::try_from(frame.len())) else {
            return false;
        };
        let Ok(mut burst) = self.pool.alloc_bulk(1) else {
            return false;
        };
        for mbuf in &mut burst {
            match mbuf.append(len) {
                Ok(room) => room.copy_from_slice(frame),
                Err(_) => return false,
            }
        }
        queue.transmit(burst).is_empty()
    }

    fn receive(&mut self, deliver: &mut dyn FnMut(&[u8])) -> usize {
        let mut total = 0;
        for queue in self.rx.iter_mut() {
            let burst = queue.receive();
            for mbuf in &burst {
                deliver(mbuf.raw_data());
                total += 1;
            }
        }
        total
    }
}
