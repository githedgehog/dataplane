// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bringing DPDK ports up, and the queue split that gives each worker its own.
//!
//! A port has one receive and one transmit queue per data worker, and one more of each for the
//! control worker: queue `W` for `W` data workers. RSS spreads over the data queues only, so the
//! control receive queue gets nothing but what the control-plane classes' flow rules steer to it,
//! and a data flood cannot crowd it out. The control queues draw on a pool of their own for the
//! same reason.

use concurrency::thread;
use dpdk::dev::{
    Configured, Dev, DevConfig, DevIndex, DevInfo, PortClaim, RssConf, RxOffload, Started,
    TxOffloadConfig,
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

use crate::drivers::DriverError;
use crate::drivers::cpbridge::{DatapathEnds, Frame};

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
            "port {index} ({name}) advertises no RSS hash functions, so all {num_workers} workers \
             will share receive queue 0 and only one of them will do any work",
            index = info.index()
        );
    }
    rss
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
                    "DPDK port {index} ({name}) up: ifindex {if_index}, mac {mac}, mtu {mtu}, \
                     {num_workers} rx/tx queue pair(s), link {link}",
                    index = port.dev.info().index(),
                    name = port.name,
                    if_index = port.if_index,
                    mac = port.mac,
                    mtu = port.mtu,
                );
                false
            }
            Ok(_) => true,
            Err(e) => {
                info!(
                    "DPDK port {index} ({name}) up: ifindex {if_index}, mac {mac}, mtu {mtu}, \
                     {num_workers} rx/tx queue pair(s); link state unavailable ({e:?})",
                    index = port.dev.info().index(),
                    name = port.name,
                    if_index = port.if_index,
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
             after {waited:?}: ifindex {if_index}, mac {mac}, mtu {mtu}, {num_workers} rx/tx \
             queue pair(s). No traffic will pass until it comes up. For a bifurcated device such \
             as mlx5 the port follows its kernel netdev, so check that the netdev is up inside \
             the datapath network namespace.",
            index = port.dev.info().index(),
            name = port.name,
            if_index = port.if_index,
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
    /// The kernel `ifindex` of this port's netdev, which is what the pipeline knows it by.
    pub(crate) if_index: InterfaceIndex,
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
    /// Where frames received on the control queue live, and injected frames are allocated from.
    pub(crate) control_pool: Pool<'eal>,
    /// The number of data queues, which is also the index of the control queues.
    pub(crate) data_queues: u16,
    /// Whether the port has a control receive queue. It does unless the device spreads RSS over
    /// every queue with no table to keep it off one; then control traffic stays on the data path.
    pub(crate) control_rx: bool,
}

impl<'eal> Port<'eal> {
    /// Configure a device with one receive and one transmit queue per worker and one of each for
    /// the control worker, and start it.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] if the device cannot be configured, queued or started, or if the
    /// PMD reports an `if_index` the kernel does not recognise.
    #[allow(clippy::too_many_lines)] // one device's bring-up, step by step in the order it requires
    pub(crate) fn bring_up(
        eal: &'eal Eal,
        port: PortClaim<'eal>,
        name: InterfaceName,
        num_workers: u16,
        num_ports: u32,
        mtu: Option<u16>,
        rx_descriptors: Option<u16>,
    ) -> Result<Self, DriverError> {
        let info = port.info();
        let index = info.index();

        let rx_descriptors = rx_descriptor_count(info, index, name.as_ref(), rx_descriptors);

        let rss = rss_for(info, name.as_ref(), num_workers);

        // Without a redirection table, RSS would spread over the control queue too.
        let spreads = rss.is_some();
        let control_rx = !spreads || info.reta_size() > 0;
        if !control_rx {
            warn!(
                "port {index} ({name}) does RSS but has no redirection table to keep it off a \
                 control queue; its control traffic will share the data queues"
            );
        }

        // Each worker receives its own RX/TX queue pair on every port; the control worker gets the
        // next pair.
        let config = DevConfig {
            num_rx_queues: num_workers + u16::from(control_rx),
            num_tx_queues: num_workers + 1,
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

        let mut dev = config
            .apply(port)
            .map_err(|e| DriverError::PortSetup(e.to_string()))?;

        // The pipeline identifies interfaces by ifindex, and here that is the ifindex of the
        // port's own kernel netdev in this namespace. Only bifurcated PMDs (mlx5) keep a netdev
        // alongside DPDK; a device bound to vfio-pci has none, so it cannot be mapped yet.
        let raw_if_index = dev.info().if_index();
        let if_index = InterfaceIndex::try_new(raw_if_index).map_err(|e| {
            DriverError::PortSetup(format!(
                "port {index} ({name}) reports if_index {raw_if_index}, which is not a usable \
                 interface index: {e}. The DPDK driver currently requires a bifurcated PMD \
                 (mlx5) that keeps the port's kernel netdev; devices bound to vfio-pci have none."
            ))
        })?;

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

        for queue in 0..num_workers {
            new_rx_queue(&mut dev, queue, rx_descriptors, &rx_pool)?;
            new_tx_queue(&mut dev, queue, TX_DESCRIPTORS)?;
        }
        if control_rx {
            new_rx_queue(&mut dev, num_workers, CONTROL_RX_DESCRIPTORS, &control_pool)?;
        }
        new_tx_queue(&mut dev, num_workers, CONTROL_TX_DESCRIPTORS)?;

        let mut dev = dev
            .start()
            .map_err(|e| DriverError::PortSetup(format!("failed to start port {index}: {e}")))?;

        // LLDP is sent to a link-local group the device was never told about, and a device that
        // filters on its address list (virtio-net under QEMU, for one) drops it when not promiscuous.
        // A port that will not take all multicast can still forward, so this is not fatal.
        if let Err(e) = dev.set_allmulticast(true) {
            warn!(
                "port {index} ({name}) would not accept all multicast ({e:?}); LLDP and IPv6 neighbor \
                 discovery may not reach the control plane"
            );
        }
        if control_rx && spreads {
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
            control_pool,
            data_queues: num_workers,
            control_rx,
        })
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
    pub(crate) rx: RxQueue<'p>,
    pub(crate) tx: TxQueue<'p>,
    /// Where to hand a frame this port received which the kernel should see.
    ///
    /// `None` only without a control-plane bridge: in tests, or when building the bridge failed and
    /// the dataplane is already shutting down. There is then nowhere to punt to and local delivery is
    /// dropped.
    pub(crate) punt: Option<mpsc::Sender<Frame>>,
}

/// One port's control queues, as handed to the control worker.
pub(crate) struct ControlQueues<'p, 'eal> {
    /// The device, for the flow rules that steer control traffic to `rx`.
    pub(crate) dev: &'p Dev<'eal, Started>,
    /// The index of the control queues.
    pub(crate) queue: u16,
    pub(crate) name: String,
    /// The MAC this port answers to.
    pub(crate) mac: SourceMac,
    /// Where the control-plane classes' flow rules steer to; `None` if the port has no control
    /// receive queue.
    pub(crate) rx: Option<RxQueue<'p>>,
    /// Where the control plane's frames leave, apart from forwarded traffic.
    pub(crate) tx: TxQueue<'p>,
    /// The port's control pool, which injected frames are copied into.
    pub(crate) pool: Pool<'p>,
    /// Where to hand the kernel what the control queue receives.
    pub(crate) punt: Option<mpsc::Sender<Frame>>,
    /// Frames the kernel wants this port to transmit.
    pub(crate) inject: Option<mpsc::Receiver<Frame>>,
}

/// The interface index the rest of the dataplane knows `port` by, and the channels to and from its
/// tap, if the control-plane bridge has one.
fn map_port_to_cp(
    port: &Port<'_>,
    bridge: Option<&mut DatapathEnds>,
) -> (
    InterfaceIndex,
    Option<mpsc::Sender<Frame>>,
    Option<mpsc::Receiver<Frame>>,
) {
    let Some(bridge) = bridge else {
        debug!(
            "no control-plane bridge, so port {} delivers nothing to the kernel",
            port.name
        );
        // No bridge, so nothing moved and the port's own index is the one the control plane saw
        // too.
        return (port.if_index, None, None);
    };
    let Some(queues) = bridge.take(&port.name) else {
        warn!(
            "the control-plane bridge has no tap for port {}; frames the kernel should see will be \
             dropped and nothing can be injected",
            port.name
        );
        return (port.if_index, None, None);
    };
    // The tap's index, not the port's. Interface indices are per-namespace and these two live in
    // different ones; everything above the driver was built from the control plane's view, so it
    // speaks in tap indices. See `cpbridge::PortCpQueues::index`.
    (queues.index, Some(queues.punt), queues.inject)
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
        let (if_index, punt, inject) = map_port_to_cp(port, bridge.as_deref_mut());

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
                rx,
                tx,
                punt: punt.clone(),
            });
        }

        let queue = port.data_queues;
        let rx = if port.control_rx {
            Some(queues.take_rx(RxQueueIndex(queue)).ok_or_else(|| {
                DriverError::PortSetup(format!(
                    "control rx queue {queue} missing on port {} after start",
                    port.name
                ))
            })?)
        } else {
            None
        };
        let tx = queues.take_tx(TxQueueIndex(queue)).ok_or_else(|| {
            DriverError::PortSetup(format!(
                "control tx queue {queue} missing on port {} after start",
                port.name
            ))
        })?;
        control.push(ControlQueues {
            dev: &port.dev,
            queue,
            name: port.name.to_string(),
            mac: port.mac,
            rx,
            tx,
            pool: port.control_pool.clone(),
            punt,
            inject,
        });
    }

    Ok(Dealt {
        workers: per_worker,
        control,
    })
}

#[cfg(test)]
mod tests {
    use super::fit_descriptors;

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
