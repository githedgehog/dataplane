// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bringing DPDK ports up, and the queue split that gives each worker its own.
//!
//! A port has one receive and one transmit queue per data worker, and, if it can keep traffic off
//! one, one more of each for the control worker: queue `W` for `W` data workers. RSS spreads over
//! the data queues only, so the control receive queue gets nothing but what the control-plane
//! classes' flow rules steer to it, and a data flood cannot crowd it out. The control queues draw
//! on a pool of their own for the same reason.
//!
//! A port whose device cannot be told to keep traffic off a queue gets no control queues at all,
//! because the device, not the flow rules, would decide what lands there. A virtio-net on a
//! multiqueue tap without the RSS feature is one: the host's tun driver spreads flows over every
//! queue pair the guest enables, and sends a flow's replies to the queue the guest last sent it
//! from. A control receive queue there gets a share of the data, which the control worker would
//! hand to the kernel, and a control transmit queue alone would still enable a pair whose receive
//! side nobody polls. On such a port the data workers take control traffic off the data path in
//! software, and data worker 0 transmits the kernel's frames.

use concurrency::thread;
use dpdk::dev::{
    Configured, Dev, DevConfig, DevConfigError, DevConfigFailure, DevIndex, DevInfo,
    FlowControlError, PortClaim, RssConf, RxOffload, Started, TxOffloadConfig,
};
use dpdk::eal::Eal;
use dpdk::mem::{Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use errno::ErrorCode;
use net::eth::mac::SourceMac;
use net::interface::{InterfaceIndex, InterfaceName};
use stats::PortCounters;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use concurrency::sync::Arc;

use super::classes::Fallback;
use super::inject::Injector;
use crate::drivers::DriverError;
use crate::drivers::cpbridge::{DatapathEnds, Frame, InjectReceiver};

use args::dpdk_memory::{
    MBUF_BURST, MBUF_DATA_SIZE, MBUF_FOOTPRINT, MBUF_PRIVATE_SIZE, POOL_CACHE, RX_DESCRIPTORS,
    TX_DESCRIPTORS, pool_mbufs, pool_mbufs_per_worker,
};

// Init sizes hugepages from `args::dpdk_memory`, so its burst has to be the one the queues use.
const _: () = assert!(MBUF_BURST as usize == dpdk::mem::MBUF_BURST);

/// Receive descriptors on the control queue: control traffic is a few thousand frames a second.
const CONTROL_RX_DESCRIPTORS: u16 = 512;

/// Transmit descriptors on the control queue.
const CONTROL_TX_DESCRIPTORS: u16 = 512;

/// Mbufs in a port's control pool: every descriptor of both control queues filled, with as many
/// again for frames on their way through and per-core caches (2<sup>11</sup> - 1, the size a
/// mempool uses best).
const CONTROL_POOL_MBUFS: u32 = (1 << 11) - 1;

/// Per-core cache of the control pool: only the control worker allocates from it, in small bursts.
const CONTROL_POOL_CACHE: u32 = 32;

/// Use the driver's RSS key and supported L3/L4 hash types; warn if no requested type is supported.
/// Symmetric hashing would not co-locate NAT's translated reverse tuples. Shared flow state
/// lets any worker process either direction.
fn rss_for(info: &DevInfo, name: &str, num_workers: u16) -> Option<RssConf> {
    let rss = RssConf::supported_on(info);
    if rss.is_none() && num_workers > 1 {
        warn!(
            "port {index} ({name}) advertises no RSS hash functions, so the device alone decides \
             which of the {num_workers} workers' receive queues a frame lands on: queue 0 on most \
             NICs, leaving one worker to do all the work",
            index = info.index()
        );
    }
    rss
}

/// Advertised queue limits and the supported worker count.
#[derive(Debug, thiserror::Error)]
#[error(
    "{port} has {max_rx} rx and {max_tx} tx queues, but {num_workers} worker(s) need {rx} and \
     {tx}: a queue pair per worker, and one for the control worker if the port has one. {}",
    if *fit == 0 {
        "It cannot carry even one worker.".to_string()
    } else {
        format!("This port carries at most {fit} worker(s) (--num-workers).")
    }
)]
struct QueueShortfall {
    port: String,
    num_workers: u16,
    rx: u16,
    tx: u16,
    max_rx: u16,
    max_tx: u16,
    /// Maximum supported worker count.
    fit: u16,
}

impl QueueShortfall {
    /// Requires one RX/TX queue pair per worker in `config`.
    fn new(port: String, num_workers: u16, config: &DevConfig, max_rx: u16, max_tx: u16) -> Self {
        let rx = config.num_rx_queues + config.num_hairpin_queues;
        let tx = config.num_tx_queues + config.num_hairpin_queues;
        // Control and hairpin queues do not scale with worker count.
        let (fixed_rx, fixed_tx) = (
            rx.saturating_sub(num_workers),
            tx.saturating_sub(num_workers),
        );
        Self {
            port,
            num_workers,
            rx,
            tx,
            max_rx,
            max_tx,
            fit: max_rx
                .saturating_sub(fixed_rx)
                .min(max_tx.saturating_sub(fixed_tx)),
        }
    }
}

/// Whether a port gets control queues: only if the device spreads with RSS through a redirection
/// table, which is what keeps everything but the flow rules' traffic off the control receive queue.
///
/// Without RSS the device decides where each frame goes (a multiqueue virtio-net tap spreads flows
/// over every enabled queue pair), and RSS without a table spreads over every queue: either way the
/// control queue would get data, which the control worker cannot forward. Whether the NIC accepts
/// the flow rules does not matter here: a table that keeps RSS off the control queue leaves it idle,
/// not misused, and the control transmit queue still keeps the kernel's frames off the data ones.
fn has_control_queues(spreads: bool, reta_size: u16) -> bool {
    spreads && reta_size > 0
}

/// RX/TX counts: a pair per worker, and one for the control worker if the port has control queues.
///
/// Never more of one than the other. A virtio-net enables as many queue pairs as the larger of the
/// two, and its host may deliver to any enabled pair.
fn queue_counts(num_workers: u16, control: bool) -> (u16, u16) {
    let queues = num_workers + u16::from(control);
    (queues, queues)
}

/// The device behind a port, `<bus address> (<driver>)`.
///
/// DPDK names a device by its bus address (with a suffix for representors); with the driver it says
/// which NIC this is to someone looking at it from the far end of the cable.
fn hardware(dev: &Dev<'_, Started>, name: &str) -> Option<String> {
    match dev.info().name() {
        Ok(device) => Some(format!("{device} ({})", dev.info().driver_name())),
        Err(e) => {
            warn!("port {name} would not report its device name: {e:?}");
            None
        }
    }
}

/// Create the pool a port's receive queues allocate from, sized from everything that can hold its
/// mbufs at once; see `pool_mbufs_per_worker`.
fn new_rx_pool<'eal>(
    eal: &'eal Eal,
    index: dpdk::dev::DevIndex,
    name: &str,
    rx_descriptors: u16,
    num_workers: u16,
    num_ports: u32,
) -> Result<Pool<'eal>, DriverError> {
    // Checked: an absurd `/rxd` and worker count can pass what one pool holds, and a wrapped count
    // would make a uselessly small pool rather than an error.
    let per_worker = pool_mbufs_per_worker(rx_descriptors, num_ports);
    let pool_mbufs =
        u32::try_from(pool_mbufs(rx_descriptors, num_ports, num_workers)).map_err(|_| {
            DriverError::PortSetup(format!(
                "port {index} ({name}): {rx_descriptors} rx descriptors for each of \
                 {num_workers} workers on {num_ports} ports needs more mbufs than one pool can hold"
            ))
        })?;
    let params = PoolParams {
        size: pool_mbufs,
        cache_size: POOL_CACHE,
        data_size: MBUF_DATA_SIZE,
        private_size: MBUF_PRIVATE_SIZE,
        ..Default::default()
    };
    let pool_mib = u64::from(pool_mbufs) * MBUF_FOOTPRINT / (1 << 20);
    eal.mem
        .new_pkt_pool(PoolConfig::new(format!("rx_{index}"), params).map_err(|e| {
            DriverError::PortSetup(format!("invalid rx pool config for port {index}: {e:?}"))
        })?)
        .map_err(|e| {
            DriverError::PortSetup(format!(
                "failed to create the rx pool for port {index} ({name}): {e:?}. It holds \
                 {pool_mbufs} mbufs (about {pool_mib} MiB of hugepages): {per_worker} for each \
                 of {num_workers} workers, covering {rx_descriptors} rx descriptors and a \
                 transmit ring on each of {num_ports} ports; lower /rxd or reserve more hugepages"
            ))
        })
}

/// How often [`report_links`] re-reads link state while waiting for carrier.
const LINK_POLL: Duration = Duration::from_millis(100);

/// How many polls [`report_links`] waits for autonegotiation before calling a link down.
const LINK_POLLS: u32 = 50;

/// Report carrier state separately from successful device startup, once every port has started.
///
/// A link read straight after `rte_eth_dev_start` is usually still down while autonegotiation
/// runs, so ports get [`LINK_POLLS`] × [`LINK_POLL`] between them to come up before one is
/// reported down. On bifurcated devices, a down kernel netdev can leave a started DPDK port
/// without carrier.
pub(crate) fn report_links(ports: &[Port<'_>], num_workers: u16) {
    let mut waiting: Vec<&Port<'_>> = ports.iter().collect();
    for poll in 0..=LINK_POLLS {
        waiting.retain(|port| match port.dev.link() {
            Ok(link) if link.up => {
                info!(
                    "DPDK port {index} ({name}) up: {netdev}, mac {mac}, mtu {mtu}, \
                     {num_workers} rx/tx queue pair(s), link {link}",
                    index = port.dev.info().index(),
                    name = port.name,
                    netdev = port.netdev(),
                    mac = port.mac,
                    mtu = port.mtu,
                );
                false
            }
            Ok(_) => true,
            Err(e) => {
                info!(
                    "DPDK port {index} ({name}) up: {netdev}, mac {mac}, mtu {mtu}, \
                     {num_workers} rx/tx queue pair(s); link state unavailable ({e:?})",
                    index = port.dev.info().index(),
                    name = port.name,
                    netdev = port.netdev(),
                    mac = port.mac,
                    mtu = port.mtu,
                );
                false
            }
        });
        if waiting.is_empty() || poll == LINK_POLLS {
            break;
        }
        thread::sleep(LINK_POLL);
    }
    for port in waiting {
        warn!(
            "DPDK port {index} ({name}) is configured and started but its link is still down \
             after {waited:?}: {netdev}, mac {mac}, mtu {mtu}, {num_workers} rx/tx \
             queue pair(s). No traffic will pass until it comes up. For a bifurcated device such \
             as mlx5 the port follows its kernel netdev, so check that the netdev is up inside \
             the datapath network namespace.",
            index = port.dev.info().index(),
            name = port.name,
            netdev = port.netdev(),
            mac = port.mac,
            mtu = port.mtu,
            waited = LINK_POLL * LINK_POLLS,
        );
    }
}

/// Honor `/rxd=N`, fitted to the device's advertised minimum, maximum and alignment.
fn rx_descriptor_count(
    info: &DevInfo<'_>,
    index: dpdk::dev::DevIndex,
    name: &str,
    asked: Option<u16>,
) -> u16 {
    let asked = asked.unwrap_or(RX_DESCRIPTORS);
    let limits = info.rx_desc_limits();
    let fitted = fit_descriptors(asked, limits.nb_min, limits.nb_max, limits.nb_align);
    if fitted != asked {
        warn!(
            "port {index} ({name}) needs between {min} and {max} rx descriptors per queue in \
             multiples of {align}; using {fitted} rather than the {asked} asked for",
            min = limits.nb_min,
            max = limits.nb_max,
            align = limits.nb_align,
        );
    }
    fitted
}

/// The descriptor count nearest `asked` that `rte_eth_rx_queue_setup` accepts.
///
/// Rounds up to a multiple of `align`, or down when rounding up would pass `max`. A zero `max` or
/// `align` is treated as unconstrained.
fn fit_descriptors(asked: u16, min: u16, max: u16, align: u16) -> u16 {
    let max = if max == 0 { u16::MAX } else { max };
    let align = u32::from(align.max(1));
    let clamped = u32::from(asked.clamp(min.min(max), max));
    let up = clamped.div_ceil(align) * align;
    let fitted = if up <= u32::from(max) {
        up
    } else {
        u32::from(max) / align * align
    };
    // `fitted <= max`, so the fallback is never taken.
    u16::try_from(fitted).unwrap_or(max)
}

/// A packet pool for port `index`, named `<what>_<index>`.
fn new_pool<'eal>(
    eal: &'eal Eal,
    index: DevIndex,
    what: &str,
    params: PoolParams,
) -> Result<Pool<'eal>, DriverError> {
    let config = PoolConfig::new(format!("{what}_{index}"), params).map_err(|e| {
        DriverError::PortSetup(format!(
            "invalid {what} pool config for port {index}: {e:?}"
        ))
    })?;
    eal.mem.new_pkt_pool(config).map_err(|e| {
        DriverError::PortSetup(format!(
            "failed to create {what} pool for port {index}: {e:?}"
        ))
    })
}

/// Set up receive queue `queue` with `descriptors` descriptors, filled from `pool`.
fn new_rx_queue<'eal>(
    dev: &mut Dev<'eal, Configured>,
    queue: u16,
    descriptors: u16,
    pool: &Pool<'eal>,
) -> Result<(), DriverError> {
    let index = dev.info().index();
    dev.new_rx_queue(RxQueueConfig {
        queue_index: RxQueueIndex(queue),
        num_descriptors: descriptors,
        socket_preference: socket::Preference::Dev(index),
        offloads: RxOffload::NONE,
        pool: pool.clone(),
    })
    .map_err(|e| {
        DriverError::PortSetup(format!(
            "failed to set up rx queue {queue} on port {index}: {e:?}"
        ))
    })
}

/// Set up transmit queue `queue` with `descriptors` descriptors.
fn new_tx_queue(
    dev: &mut Dev<'_, Configured>,
    queue: u16,
    descriptors: u16,
) -> Result<(), DriverError> {
    let index = dev.info().index();
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(queue),
        num_descriptors: descriptors,
        socket_preference: socket::Preference::Dev(index),
        config: (),
    })
    .map_err(|e| {
        DriverError::PortSetup(format!(
            "failed to set up tx queue {queue} on port {index}: {e:?}"
        ))
    })
}

/// The queues a port is brought up with: one receive and one transmit queue per worker, and one of
/// each for the control worker if the port has control queues.
struct Queues<'a, 'eal> {
    workers: u16,
    control: bool,
    rx_descriptors: u16,
    rx_pool: &'a Pool<'eal>,
    control_pool: &'a Pool<'eal>,
}

impl<'eal> Queues<'_, 'eal> {
    /// Set them all up on `dev`.
    fn set_up(&self, dev: &mut Dev<'eal, Configured>) -> Result<(), DriverError> {
        for queue in 0..self.workers {
            new_rx_queue(dev, queue, self.rx_descriptors, self.rx_pool)?;
            new_tx_queue(dev, queue, TX_DESCRIPTORS)?;
        }
        if self.control {
            new_rx_queue(dev, self.workers, CONTROL_RX_DESCRIPTORS, self.control_pool)?;
            new_tx_queue(dev, self.workers, CONTROL_TX_DESCRIPTORS)?;
        }
        Ok(())
    }
}

/// Spread RSS over the `data_queues` data queues only, keeping it off the control queue after them.
///
/// A port that cannot have that would deliver data to the control worker, which has no pipeline to
/// forward it with: it is refused rather than left to drop a share of the traffic.
fn keep_rss_off_control(
    dev: &mut Dev<'_, Started>,
    name: &str,
    data_queues: u16,
) -> Result<(), DriverError> {
    let index = dev.info().index();
    let data: Vec<RxQueueIndex> = (0..data_queues).map(RxQueueIndex).collect();
    let size = dev.spread_rss(&data).map_err(|e| {
        DriverError::PortSetup(format!(
            "port {index} ({name}) would not keep RSS off its control queue: {e}"
        ))
    })?;
    debug!("port {index} ({name}) spreads RSS over {data_queues} queue(s), {size} entries");
    Ok(())
}

/// A started port and its control pool. Workers borrow its queue handles.
pub(crate) struct Port<'eal> {
    /// The started device. Kept so the port can be stopped and closed explicitly at shutdown.
    pub(crate) dev: Dev<'eal, Started>,
    /// Kernel netdev index; pipeline fallback when no TAP exists.
    pub(crate) if_index: Option<InterfaceIndex>,
    /// Human-readable name for logs and status.
    ///
    /// This is the *configured* interface name, which is also the name of the tap that stands in
    /// for this port in the kernel. It is the key the control-plane bridge is addressed by.
    pub(crate) name: InterfaceName,
    /// The MAC the PMD reports for this port.
    ///
    /// The port's tap has to be given this, or the peer resolves the wrong address for it and the
    /// frames it sends back come in as `MacNotForUs`.
    pub(crate) mac: SourceMac,
    /// The MTU the port settled on, which is not necessarily the one that was requested: it is
    /// clamped into the device's advertised range at configuration time.
    pub(crate) mtu: u16,
    /// The device's bus address and driver, if DPDK would say.
    pub(crate) hardware: Option<String>,
    /// Where frames received on the data queues live.
    pub(crate) rx_pool: Pool<'eal>,
    /// Where frames received on the control queue live, and injected frames are allocated from.
    pub(crate) control_pool: Pool<'eal>,
    /// The number of data queues, which is also the index of the control queues.
    pub(crate) data_queues: u16,
    /// Whether the port has control queues; see [`has_control_queues`]. Without them its control
    /// traffic is taken off the data path in software and data worker 0 transmits for the kernel.
    pub(crate) control: bool,
    /// Whether the port's receive queues raise interrupts, for workers that sleep on them: asked
    /// for with `--idle interrupt`, and granted if the driver has them.
    pub(crate) rx_interrupts: bool,
}

impl<'eal> Port<'eal> {
    /// Configure a device with one receive and one transmit queue per worker, and one of each for
    /// the control worker if it can keep traffic off them, and start it.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] if the device cannot be configured, queued or started.
    #[allow(clippy::too_many_lines)] // one device's bring-up, step by step in the order it requires
    #[allow(clippy::too_many_arguments)] // the port's own settings, each passed straight through
    pub(crate) fn bring_up(
        eal: &'eal Eal,
        port: PortClaim<'eal>,
        name: InterfaceName,
        num_workers: u16,
        num_ports: u32,
        mtu: Option<u16>,
        rx_descriptors: Option<u16>,
        rx_interrupts: bool,
    ) -> Result<Self, DriverError> {
        let info = port.info();
        let index = info.index();

        // A driver that arms another queue's interrupt would leave workers asleep while packets
        // wait, and its queues cannot be watched anyway: do not ask it for interrupts at all.
        let rx_interrupts = rx_interrupts && {
            let arms_each_queue = dpdk::interrupt::arms_each_queue(info);
            if !arms_each_queue {
                warn!(
                    "port {index} ({name}): the {} driver arms other receive queues' interrupts \
                     than the ones asked for, so its workers will not sleep on interrupts",
                    info.driver_name()
                );
            }
            arms_each_queue
        };

        let rx_descriptors = rx_descriptor_count(info, index, name.as_ref(), rx_descriptors);

        let rss = rss_for(info, name.as_ref(), num_workers);

        let spreads = rss.is_some();
        let control = has_control_queues(spreads, info.reta_size());
        if !control {
            warn!(
                "port {index} ({name}) cannot keep traffic off a control queue (it has {}), so it \
                 gets none: its control traffic is taken off the data path in software, and data \
                 worker 0 transmits the kernel's frames",
                if spreads {
                    "RSS but no redirection table"
                } else {
                    "no RSS"
                }
            );
        }

        let (rx, tx) = queue_counts(num_workers, control);
        let mut config = DevConfig {
            rx_interrupts,
            num_rx_queues: rx,
            num_tx_queues: tx,
            num_hairpin_queues: 0,
            // The pipeline handles checksums in software and requires uncoalesced packets.
            // RSS spreads queues without `RSS_HASH`, which only copies the hash into mbufs, and
            // nothing reads it yet.
            rx_offloads: RxOffload::NONE,
            tx_offloads: TxOffloadConfig::none(),
            // An omitted MTU uses the device-clamped default; jumbo frames require an explicit MTU.
            mtu,
            rss,
        };

        let (max_rx, max_tx) = (info.max_rx_queues(), info.max_tx_queues());
        // Retry driver configuration errors with receive interrupts disabled.
        // If that also fails, preserve the original error; otherwise workers use monitor or poll.
        let applied = match config.apply(port) {
            Err(first)
                if config.rx_interrupts
                    && matches!(first.error, DevConfigError::DriverSpecificError { .. }) =>
            {
                let without = DevConfig {
                    rx_interrupts: false,
                    ..config.clone()
                };
                match without.apply(first.claim) {
                    Ok(dev) => {
                        warn!(
                            "port {index} ({name}) refused receive interrupts ({}); its workers \
                             will stay awake while it is idle",
                            first.error
                        );
                        config = without;
                        Ok(dev)
                    }
                    Err(second) => Err(DevConfigFailure {
                        error: first.error,
                        claim: second.claim,
                    }),
                }
            }
            applied => applied,
        };
        let mut dev = applied.map_err(|e| match e.error {
            DevConfigError::TooManyQueues { .. } => DriverError::PortSetup(
                QueueShortfall::new(
                    format!("port {index} ({name})"),
                    num_workers,
                    &config,
                    max_rx,
                    max_tx,
                )
                .to_string(),
            ),
            error => DriverError::PortSetup(error.to_string()),
        })?;

        // Ports without a kernel netdev report ifindex 0.
        let if_index = InterfaceIndex::try_new(dev.info().if_index()).ok();

        let rx_pool = new_rx_pool(
            eal,
            index,
            name.as_ref(),
            rx_descriptors,
            num_workers,
            num_ports,
        )?;
        let control_pool = new_pool(
            eal,
            index,
            "control",
            PoolParams {
                size: CONTROL_POOL_MBUFS,
                cache_size: CONTROL_POOL_CACHE,
                ..Default::default()
            },
        )?;

        let queues = Queues {
            workers: num_workers,
            control,
            rx_descriptors,
            rx_pool: &rx_pool,
            control_pool: &control_pool,
        };
        queues.set_up(&mut dev)?;

        let mut dev = match dev.start() {
            Ok(dev) => dev,
            // Interrupt setup can fail at start, for example when igb lacks MSI-X vectors, but so
            // can much else. Start once more as configured, so a passing failure does not cost the
            // port its interrupts. If that fails too, retry without them so the port can forward.
            Err(first) if config.rx_interrupts => match first.dev.start() {
                Ok(dev) => {
                    warn!(
                        "port {index} ({name}) started at the second attempt; the first failed: {}",
                        first.error
                    );
                    dev
                }
                Err(second) => {
                    let without = DevConfig {
                        rx_interrupts: false,
                        ..config.clone()
                    };
                    let mut dev = second.dev.reconfigure(&without).map_err(|e| {
                        DriverError::PortSetup(format!(
                            "port {index} ({name}) would not start with receive interrupts ({}, \
                             then {}), and could not be configured again without them: {}",
                            first.error, second.error, e.error
                        ))
                    })?;
                    queues.set_up(&mut dev)?;
                    let dev = dev.start().map_err(|e| {
                        DriverError::PortSetup(format!(
                            "failed to start port {index}, with receive interrupts ({}, then {}) \
                             or without them: {}",
                            first.error, second.error, e.error
                        ))
                    })?;
                    warn!(
                        "port {index} ({name}) would not start with receive interrupts ({}, then \
                         {}), but did without them; its workers will stay awake while it is idle",
                        first.error, second.error
                    );
                    config = without;
                    dev
                }
            },
            Err(e) => {
                return Err(DriverError::PortSetup(format!(
                    "failed to start port {index}: {e}"
                )));
            }
        };

        // LLDP is sent to a link-local group the device was never told about, and a device that
        // filters on its address list (virtio-net under QEMU, for one) drops it when not promiscuous.
        // A port that will not take all multicast can still forward, so this is not fatal.
        if let Err(e) = dev.set_allmulticast(true) {
            warn!(
                "port {index} ({name}) would not accept all multicast ({e:?}); LLDP and IPv6 neighbor \
                 discovery may not reach the control plane"
            );
        }
        match dev.disable_flow_control() {
            Ok(()) => {}
            Err(FlowControlError::NotSupported) => {
                debug!("port {index} ({name}) has no flow control to turn off");
            }
            Err(e) => warn!(
                "port {index} ({name}) would not turn flow control off ({e}); a congested queue \
                 may pause the whole link"
            ),
        }
        if control {
            keep_rss_off_control(&mut dev, name.as_ref(), num_workers)?;
        }

        // Both read after the port has started, because both are properties of the running device
        // rather than of the configuration: the MTU was clamped into the device's range and the MAC
        // came from the PMD. A port whose identity cannot be read is still usable for forwarding
        // but cannot have a working control plane, which is worth failing over rather than
        // discovering as an adjacency that never forms.
        let mac = dev.mac_address().map_err(|e| {
            DriverError::PortSetup(format!(
                "port {index} ({name}) is up but would not report its MAC address: {e:?}. Its tap \
                 could not then answer ARP for it."
            ))
        })?;
        // A port's own MAC is what its frames go out with, so a multicast one is a broken PMD.
        let mac = SourceMac::new(mac.into()).map_err(|e| {
            DriverError::PortSetup(format!(
                "port {index} ({name}) reports {e:?}, which cannot be a port's own address"
            ))
        })?;
        let mtu = dev.mtu().map_err(|e| {
            DriverError::PortSetup(format!(
                "port {index} ({name}) is up but would not report its MTU: {e:?}"
            ))
        })?;

        let hardware = hardware(&dev, name.as_ref());

        Ok(Port {
            dev,
            if_index,
            name,
            mac,
            mtu,
            hardware,
            rx_pool,
            control_pool,
            data_queues: num_workers,
            control,
            rx_interrupts: config.rx_interrupts,
        })
    }

    /// Return the kernel netdev index for a port without a TAP.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::PortSetup`] if the port has no kernel netdev.
    fn own_index(&self) -> Result<InterfaceIndex, DriverError> {
        self.if_index.ok_or_else(|| {
            DriverError::PortSetup(format!(
                "port {} has neither a tap nor a kernel netdev, so nothing above the driver can \
                 address it",
                self.name
            ))
        })
    }

    /// Format the kernel netdev index for logs.
    fn netdev(&self) -> String {
        self.if_index.map_or_else(
            || "no kernel netdev".to_string(),
            |i| format!("ifindex {i}"),
        )
    }

    /// Read cumulative device counters, including drops before packets reach a worker.
    ///
    /// # Errors
    /// Returns the driver's error code; unsupported statistics report `ENOTSUP`.
    pub(crate) fn counters(&self) -> Result<PortCounters, ErrorCode> {
        let stats = self.dev.stats()?;
        Ok(PortCounters {
            rx_packets: stats.ipackets,
            tx_packets: stats.opackets,
            rx_bytes: stats.ibytes,
            tx_bytes: stats.obytes,
            rx_missed: stats.imissed,
            rx_errors: stats.ierrors,
            tx_errors: stats.oerrors,
            rx_no_mbuf: stats.rx_nombuf,
        })
    }

    /// Stop and close the port, logging failures.
    pub(crate) fn shutdown(self) {
        let name = self.name.clone();
        match self.dev.stop() {
            Ok(stopped) => {
                if let Err(e) = stopped.close() {
                    error!("failed to close port {name}: {e}");
                }
            }
            Err(e) => error!("failed to stop port {name}: {e}"),
        }
    }
}

/// One port's queue pair, as handed to a single worker.
pub(crate) struct PortQueues<'p> {
    /// Which interface frames off this queue arrived on.
    pub(crate) if_index: InterfaceIndex,
    pub(crate) name: String,
    /// The MAC this port answers to, which decides whether control traffic taken off the data
    /// path was addressed to us.
    pub(crate) mac: SourceMac,
    pub(crate) rx: RxQueue<'p>,
    pub(crate) tx: TxQueue<'p>,
    /// Classes of control traffic to take off the data path before the pipeline, because the NIC
    /// does not steer them to the control queue.
    pub(crate) fallback: Fallback,
    /// Where to hand the kernel what is taken off the data path that way: the same channel the
    /// control worker punts on.
    pub(crate) control_punt: Option<mpsc::Sender<Frame>>,
    /// Where to hand a frame this port received which the kernel should see.
    ///
    /// `None` only without a control-plane bridge: in tests, or when building the bridge failed and
    /// the dataplane is already shutting down. There is then nowhere to punt to and local delivery is
    /// dropped.
    pub(crate) punt: Option<mpsc::Sender<Frame>>,
    /// The kernel's frames for this port, to transmit on `tx`: worker 0's, on a port without
    /// control queues, and `None` everywhere else.
    pub(crate) injector: Option<Injector<'p>>,
    /// Whether `rx` raises interrupts a sleeping worker can wait on.
    pub(crate) rx_interrupts: bool,
}

/// One port as the control worker sees it.
pub(crate) struct ControlQueues<'p, 'eal> {
    /// The device, for the flow rules that steer control traffic to the control queue.
    pub(crate) dev: &'p Dev<'eal, Started>,
    pub(crate) name: String,
    /// Where to tell the port's data workers which classes the NIC does not steer.
    pub(crate) fallback: Fallback,
    /// The port's control queues; `None` if it has none, when every class is taken in software.
    pub(crate) pair: Option<ControlPair<'p>>,
}

/// One port's control queue pair.
pub(crate) struct ControlPair<'p> {
    /// The index of the control queues.
    pub(crate) queue: u16,
    /// The MAC this port answers to.
    pub(crate) mac: SourceMac,
    /// Where the control-plane classes' flow rules steer to.
    pub(crate) rx: RxQueue<'p>,
    /// Where the control plane's frames leave, apart from forwarded traffic.
    pub(crate) tx: TxQueue<'p>,
    /// Where to hand the kernel what the control queue receives: the bridge's control channel,
    /// which its pump drains before the data workers' punts.
    pub(crate) punt: Option<mpsc::Sender<Frame>>,
    /// The kernel's frames for this port, to transmit on `tx`.
    pub(crate) injector: Option<Injector<'p>>,
    /// Whether `rx` raises interrupts a sleeping worker can wait on.
    pub(crate) rx_interrupts: bool,
}

/// A port's interface index as the control plane knows it, then its punt channel, its control
/// queue's priority punt channel, and its injection queue.
type CpChannels = (
    InterfaceIndex,
    Option<mpsc::Sender<Frame>>,
    Option<mpsc::Sender<Frame>>,
    Option<InjectReceiver>,
);

/// The interface index the rest of the dataplane knows `port` by, and the channels to and from its
/// tap, if the control-plane bridge has one: the ordinary punt channel, the control queue's
/// priority punt channel, and the injection queue.
fn map_port_to_cp(
    port: &Port<'_>,
    bridge: Option<&mut DatapathEnds>,
) -> Result<CpChannels, DriverError> {
    let Some(bridge) = bridge else {
        debug!(
            "no control-plane bridge, so port {} delivers nothing to the kernel",
            port.name
        );
        // No bridge, so nothing moved and the port's own index is the one the control plane saw
        // too.
        return Ok((port.own_index()?, None, None, None));
    };
    let Some(queues) = bridge.take(&port.name) else {
        warn!(
            "the control-plane bridge has no tap for port {}; frames the kernel should see will be \
             dropped and nothing can be injected",
            port.name
        );
        return Ok((port.own_index()?, None, None, None));
    };
    // The tap's index, not the port's. Interface indices are per-namespace and these two live in
    // different ones; everything above the driver was built from the control plane's view, so it
    // speaks in tap indices. See `cpbridge::PortCpQueues::index`.
    Ok((
        queues.index,
        Some(queues.punt),
        Some(queues.control),
        queues.inject,
    ))
}

/// Every port's queues, split between the data workers and the control worker.
pub(crate) struct Dealt<'p, 'eal> {
    /// Worker `i`'s queue pair `i` from every port.
    pub(crate) workers: Vec<Vec<PortQueues<'p>>>,
    /// Every port's control queues.
    pub(crate) control: Vec<ControlQueues<'p, 'eal>>,
}

/// Give worker `i` queue pair `i` from every port, and the control worker the control queues.
///
/// # Errors
///
/// Returns an error if queues were already taken or a configured queue is missing.
pub(crate) fn deal_queues<'p, 'eal>(
    ports: &'p [Port<'eal>],
    num_workers: u16,
    mut bridge: Option<&mut DatapathEnds>,
) -> Result<Dealt<'p, 'eal>, DriverError> {
    let mut per_worker: Vec<Vec<PortQueues<'p>>> = (0..num_workers)
        .map(|_| Vec::with_capacity(ports.len()))
        .collect();
    let mut control = Vec::with_capacity(ports.len());

    for port in ports {
        // The injection queue goes to the control worker alone; the punt sender is cloned to every
        // worker, because any worker can receive a frame the kernel should see but only one may
        // drain a queue without reordering the session it carries.
        let (if_index, punt, control_punt, inject) = map_port_to_cp(port, bridge.as_deref_mut())?;

        let fallback = Fallback::default();

        // The kernel's frames leave on the control queue if there is one, and on worker 0's
        // otherwise.
        let injector = inject.map(|frames| Injector {
            name: port.name.to_string(),
            pool: port.control_pool.clone(),
            frames,
        });
        let (control_injector, mut worker_injector) = if port.control {
            (injector, None)
        } else {
            (None, injector)
        };

        let mut queues = port.dev.take_queues().ok_or_else(|| {
            DriverError::PortSetup(format!(
                "queues for port {} were already taken; each device hands its set out once",
                port.name
            ))
        })?;

        for worker in 0..num_workers {
            let rx = queues.take_rx(RxQueueIndex(worker)).ok_or_else(|| {
                DriverError::PortSetup(format!(
                    "rx queue {worker} missing on port {} after start",
                    port.name
                ))
            })?;
            let tx = queues.take_tx(TxQueueIndex(worker)).ok_or_else(|| {
                DriverError::PortSetup(format!(
                    "tx queue {worker} missing on port {} after start",
                    port.name
                ))
            })?;
            per_worker[worker as usize].push(PortQueues {
                if_index,
                name: port.name.to_string(),
                mac: port.mac,
                rx,
                tx,
                fallback: Arc::clone(&fallback),
                control_punt: control_punt.clone(),
                punt: punt.clone(),
                injector: if worker == 0 {
                    worker_injector.take()
                } else {
                    None
                },
                rx_interrupts: port.rx_interrupts,
            });
        }

        let pair = if port.control {
            let queue = port.data_queues;
            let rx = queues.take_rx(RxQueueIndex(queue)).ok_or_else(|| {
                DriverError::PortSetup(format!(
                    "control rx queue {queue} missing on port {} after start",
                    port.name
                ))
            })?;
            let tx = queues.take_tx(TxQueueIndex(queue)).ok_or_else(|| {
                DriverError::PortSetup(format!(
                    "control tx queue {queue} missing on port {} after start",
                    port.name
                ))
            })?;
            Some(ControlPair {
                queue,
                mac: port.mac,
                rx,
                tx,
                punt: control_punt,
                injector: control_injector,
                rx_interrupts: port.rx_interrupts,
            })
        } else {
            None
        };
        control.push(ControlQueues {
            dev: &port.dev,
            name: port.name.to_string(),
            fallback,
            pair,
        });
    }

    Ok(Dealt {
        workers: per_worker,
        control,
    })
}

#[cfg(test)]
mod tests {
    use dpdk::dev::{DevConfig, RxOffload, TxOffloadConfig};

    use super::{QueueShortfall, fit_descriptors, has_control_queues, queue_counts};

    fn shortfall(
        num_workers: u16,
        control: bool,
        hairpins: u16,
        max_rx: u16,
        max_tx: u16,
    ) -> QueueShortfall {
        let (rx, tx) = queue_counts(num_workers, control);
        let config = DevConfig {
            rx_interrupts: false,
            num_rx_queues: rx,
            num_tx_queues: tx,
            num_hairpin_queues: hairpins,
            rx_offloads: RxOffload::NONE,
            tx_offloads: TxOffloadConfig::none(),
            mtu: None,
            rss: None,
        };
        QueueShortfall::new("port1".into(), num_workers, &config, max_rx, max_tx)
    }

    #[test]
    fn two_queue_pairs_fit_one_worker() {
        let short = shortfall(8, true, 0, 2, 2);
        assert_eq!((short.rx, short.tx, short.fit), (9, 9, 1));
    }

    #[test]
    fn without_control_queues_every_queue_pair_is_a_workers() {
        let short = shortfall(8, false, 0, 4, 4);
        assert_eq!((short.rx, short.tx, short.fit), (8, 8, 4));
    }

    /// A virtio-net enables as many queue pairs as the larger count, and its host delivers to any
    /// enabled pair, so a lone extra queue in either direction would be a receive queue nobody
    /// polls.
    #[test]
    fn receive_and_transmit_queues_always_pair_up() {
        bolero::check!()
            .with_type::<(u16, bool)>()
            .for_each(|&(num_workers, control)| {
                let num_workers = num_workers % 1024;
                let (rx, tx) = queue_counts(num_workers, control);
                assert_eq!(rx, tx);
                assert_eq!(rx, num_workers + u16::from(control));
            });
    }

    #[test]
    fn only_rss_through_a_redirection_table_earns_control_queues() {
        assert!(
            !has_control_queues(false, 0),
            "no RSS: virtio-net on a multiqueue tap"
        );
        assert!(!has_control_queues(true, 0), "RSS over every queue");
        assert!(
            has_control_queues(true, 128),
            "igb, i40e, ixgbe, mlx5, virtio-net with RSS"
        );
    }

    #[test]
    fn a_single_queue_device_fits_no_worker() {
        assert_eq!(shortfall(1, true, 0, 1, 1).fit, 0);
    }

    #[test]
    fn hairpin_queues_count_against_the_fit() {
        let short = shortfall(8, true, 2, 8, 8);
        assert_eq!((short.rx, short.tx, short.fit), (11, 11, 5));
    }

    #[test]
    fn a_fitting_count_is_kept() {
        assert_eq!(fit_descriptors(1024, 64, 4096, 32), 1024);
    }

    #[test]
    fn a_misaligned_count_rounds_up() {
        // i40e: 32-descriptor alignment.
        assert_eq!(fit_descriptors(1000, 64, 4096, 32), 1024);
    }

    #[test]
    fn rounding_up_past_the_maximum_rounds_down_instead() {
        assert_eq!(fit_descriptors(4090, 64, 4095, 32), 4064);
    }

    #[test]
    fn counts_are_clamped_into_range() {
        assert_eq!(fit_descriptors(8, 64, 4096, 32), 64);
        assert_eq!(fit_descriptors(8192, 64, 4096, 32), 4096);
    }

    #[test]
    fn zero_limits_are_unconstrained() {
        assert_eq!(fit_descriptors(1000, 0, 0, 0), 1000);
        assert_eq!(fit_descriptors(u16::MAX, 0, 0, 0), u16::MAX);
    }
}
