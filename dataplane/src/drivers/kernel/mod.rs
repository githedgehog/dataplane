// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Kernel dataplane driver

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::time::Duration;

use afpacket::sync::RawPacketStream;
use netdev::Interface;
use tokio::io::unix::{AsyncFd, TryIoError};
use tokio::sync::Mutex;
use tokio::sync::mpsc as chan;

use concurrency::sync::Arc;
use concurrency::thread;
use net::buffer::test_buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet};
use pipeline::{DynPipeline, NetworkFunction};
use pkt_meta::flow_table::flow_key::{Bidi, FlowKey};
use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::drivers::tokio_util::run_in_tokio_runtime;

trace_target!("kernel-driver", LevelFilter::ERROR, &["driver"]);

type WorkerTx = chan::Sender<Box<Packet<TestBuffer>>>;
type WorkerRx = chan::Receiver<Box<Packet<TestBuffer>>>;
type WorkerChans = (Arc<Vec<WorkerTx>>, WorkerRx);

/// Simple representation of a kernel interface.
pub struct Kif {
    /// Linux ifindex of the interface
    ifindex: InterfaceIndex,
    /// Name of the interface
    name: String,
    /// Packet socket for writing, use [`nix::unistd::dup`] to create a read fd
    write_sock: RawPacketStream,
}

impl Kif {
    /// Create a kernel interface entry.
    #[allow(unsafe_code)]
    fn new(ifindex: InterfaceIndex, name: &str) -> io::Result<Self> {
        let mut sock = RawPacketStream::new().map_err(|e| {
            error!("Failed to open raw sock for interface {name}: {e}");
            e
        })?;
        sock.set_non_blocking();
        sock.bind(name)
            .inspect_err(|e| error!("Failed to open raw sock for interface {name}: {e}"))?;
        let fd = sock.as_raw_fd();
        let buf_size = 4 * 1024 * 1024;
        let bfd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) };
        nix::sys::socket::setsockopt(&bfd, nix::sys::socket::sockopt::RcvBuf, &buf_size)
            .inspect_err(|e| {
                error!("Failed to set SO_RCVBUF for interface {name}: {e}");
            })?;
        nix::sys::socket::setsockopt(&bfd, nix::sys::socket::sockopt::SndBuf, &buf_size)
            .inspect_err(|e| {
                error!("Failed to set SO_SNDBUF for interface {name}: {e}");
            })?;

        let iface = Self {
            ifindex,
            name: name.to_owned(),
            write_sock: sock,
        };

        debug!("Successfully created interface '{name}'");
        Ok(iface)
    }
}

/// A hash table of kernel interfaces [`Kif`]s, keyed by ifindex..
pub struct KifTable {
    by_ifindex: HashMap<InterfaceIndex, Kif>,
}

impl KifTable {
    /// Create kernel interface table
    pub fn new() -> Self {
        Self {
            by_ifindex: HashMap::new(),
        }
    }
    /// Add a kernel interface 'representor' to this table.
    pub fn add(&mut self, ifindex: InterfaceIndex, name: &str) -> io::Result<()> {
        debug!("Adding interface '{name}'...");
        let interface = Kif::new(ifindex, name)?;
        self.by_ifindex.insert(ifindex, interface);
        debug!("Successfully registered interface '{name}' with index {ifindex:?}");
        Ok(())
    }

    /// Get a reference to the [`Kif`] with the indicated [`InterfaceIndex`].
    pub fn get(&self, idx: InterfaceIndex) -> Option<&Kif> {
        self.by_ifindex.get(&idx)
    }

    /// Get a mutable reference to the [`Kif`] with the indicated [`InterfaceIndex`].
    pub fn get_mut(&mut self, idx: InterfaceIndex) -> Option<&mut Kif> {
        self.by_ifindex.get_mut(&idx)
    }
}

/// Get the ifindex of the interface with the given name.
fn get_interface_ifindex(interfaces: &[Interface], name: &str) -> Option<InterfaceIndex> {
    interfaces
        .iter()
        .position(|interface| interface.name == name)
        .and_then(|pos| InterfaceIndex::try_new(interfaces[pos].index).ok())
}

/// Build a table of kernel interfaces to receive packets from (or send to).
/// Interfaces of interest are indicated by --interface INTERFACE in the command line.
/// Argument --interface ANY|any instructs the driver to capture on all interfaces.
fn build_kif_table(args: impl IntoIterator<Item = impl AsRef<str>>) -> io::Result<KifTable> {
    /* learn about existing kernel network interfaces. We need these to know their ifindex  */
    let interfaces = netdev::get_interfaces();

    /* build kiftable */
    let mut kiftable = KifTable::new();

    /* check what interfaces we're interested in from args */
    let ifnames: Vec<String> = args.into_iter().map(|x| x.as_ref().to_owned()).collect();
    if ifnames.is_empty() {
        warn!("No interfaces have been specified. No packet will be processed!");
        warn!("Consider specifying them with --interface. ANY captures over all interfaces.");
        return Ok(kiftable);
    }

    if ifnames.len() == 1 && ifnames[0].eq_ignore_ascii_case("ANY") {
        /* use all interfaces */
        for interface in &interfaces {
            let if_index = match InterfaceIndex::try_new(interface.index) {
                Ok(if_index) => if_index,
                Err(e) => match e {
                    net::interface::InterfaceIndexError::Zero => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                },
            };
            if let Err(e) = kiftable.add(if_index, &interface.name) {
                error!("Skipping interface '{}': {e}", interface.name);
            }
        }
    } else {
        /* use only the interfaces specified in args */
        for name in &ifnames {
            if let Some(ifindex) = get_interface_ifindex(&interfaces, name) {
                if let Err(e) = kiftable.add(ifindex, name) {
                    error!("Skipping interface '{name}': {e}");
                }
            } else {
                warn!("Could not find ifindex of interface '{name}'");
            }
        }
    }

    Ok(kiftable)
}

/// Main structure representing the kernel driver.
/// This driver:
///  * receives raw frames via `AF_PACKET`, parses to `Packet<TestBuffer>`
///  * selects a worker by symmetric flow hash
///  * workers run independent pipelines and send processed packets back
///  * dispatcher serializes & transmits on the chosen outgoing interface
pub struct DriverKernel;

fn single_worker(
    id: usize,
    thread_builder: thread::Builder,
    tx_to_control: WorkerTx,
    setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
) -> Result<WorkerTx, std::io::Error> {
    let (tx_to_worker, mut rx_from_control) = chan::channel::<Box<Packet<TestBuffer>>>(4096);
    let setup = setup_pipeline.clone();

    let handle_res = thread_builder.spawn(move || {
        let mut pipeline = setup();
        info!(worker = id, "Worker started");
        run_in_tokio_runtime(async || {
            loop {
                tracing::debug!(
                    worker = id,
                    "awaiting packets"
                );

                let mut packets_vec = Vec::with_capacity(1024);
                let pkt_count = rx_from_control.recv_many(&mut packets_vec, 1024).await;
                if (pkt_count == 0) {
                    trace!(worker = id, "sender closed, exiting");
                    return; // The sender closed so no more packets can ever be received
                }

                // Try to receive everything else that is in the buffer
                let packets = packets_vec.into_iter();

                let mut count = 0;
                for out_pkt in pipeline.process(packets.map(|pkt| *pkt)) {
                    trace!(worker = id, "Sending packet to tx after pipeline");
                    // backpressure via bounded channel
                    if let Err(e) = tx_to_control.send(Box::new(out_pkt)).await {
                        error!(worker = id,
                            "Failed to send packet to control channel, channel seems closed, exiting worker: {e}");
                        return;
                    }
                    trace!(worker = id, "Sent packet to tx after pipeline");
                    count += 1;
                }

                tracing::debug!(
                    worker = id,
                    "processed {count} packets"
                );
            }
        });
    })?;
    Ok(tx_to_worker)
}

#[allow(clippy::cast_possible_truncation)]
impl DriverKernel {
    /// Compute a **symmetric** worker index for a parsed `Packet` using a bidirectional flow key.
    #[must_use]
    pub fn compute_worker_idx(pkt: &Packet<TestBuffer>, workers: usize) -> usize {
        let n = workers.max(1);

        // Prefer symmetric flow-key hash (A<->B go to the same bucket)
        if let Ok(flow_key) = FlowKey::try_from(Bidi(pkt)) {
            let mut h = DefaultHasher::new();
            flow_key.hash(&mut h);
            let hv = h.finish() as usize;
            return hv % n;
        }
        //TODO: fallback to L2/VLAN to build
        0
    }

    /// Spawn `workers` processing threads, each with its own pipeline instance.
    ///
    /// Returns:
    ///   - `Arc<Vec<Sender<Packet<TestBuffer>>>>` one sender per worker (dispatcher -> worker)
    ///   - `Receiver<Packet<TestBuffer>>` a single queue for processed packets (worker -> dispatcher)
    fn spawn_workers(
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
    ) -> io::Result<WorkerChans> {
        let (tx_to_control, rx_from_workers) = chan::channel::<Box<Packet<TestBuffer>>>(4096);
        let mut to_workers = Vec::with_capacity(num_workers);
        info!("Spawning {num_workers} workers");
        for wid in 0..num_workers {
            let builder = thread::Builder::new().name(format!("dp-worker-{wid}"));
            let tx_to_worker =
                match single_worker(wid, builder, tx_to_control.clone(), setup_pipeline) {
                    Ok(tx_to_worker) => tx_to_worker,
                    Err(e) => {
                        error!("Failed to spawn worker {wid}: {e}");
                        return Err(io::Error::other("worker spawn failed"));
                    }
                };
            to_workers.push(tx_to_worker);
        }

        Ok((Arc::new(to_workers), rx_from_workers))
    }

    /// Starts the kernel driver, spawns worker threads, and runs the dispatcher loop.
    ///
    /// - `args`: kernel driver CLI parameters (e.g., `--interface` list)
    /// - `workers`: number of worker threads / pipelines
    /// - `setup_pipeline`: factory returning a **fresh** `DynPipeline<TestBuffer>` per worker
    #[allow(clippy::too_many_lines)]
    pub fn start(
        args: impl IntoIterator<Item = impl AsRef<str> + Clone>,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
    ) {
        // Prepare interfaces/poller
        let mut kiftable = match build_kif_table(args) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to initialize kernel interface table: {e}");
                return;
            }
        };

        // Spawn workers
        let (to_workers, mut from_workers) = match Self::spawn_workers(num_workers, setup_pipeline)
        {
            Ok(chans) => chans,
            Err(e) => {
                error!("Failed to start workers: {e}");
                return;
            }
        };

        run_in_tokio_runtime(async move || {
            let num_worker_chans = to_workers.len();
            assert!(num_worker_chans != 0, "No worker channels available!");
            if num_worker_chans != num_workers {
                warn!(
                    "Number of to_worker channels ({num_worker_chans}) does not match number of workers ({num_workers})"
                );
            }

            kiftable
                .by_ifindex
                .values()
                .map(|kif| {
                    #[allow(unsafe_code)]
                    let orig_fd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(kif.write_sock.as_raw_fd()) };
                    #[allow(clippy::expect_used)]
                    let read_fd = AsyncFd::with_interest(
                        nix::unistd::dup(orig_fd).expect("Failed to duplicate socket fd: {fd_raw}"),
                        tokio::io::Interest::READABLE
                    ).expect("Failed to create AsyncFd for {kif:?}");
                    (kif.name.clone(), read_fd, kif.ifindex)
                })
                .for_each(|(if_name, if_fd, if_index)| {
                    let to_workers = to_workers.clone();
                    tokio::spawn(async move {
                        let mut iters = 0u64;
                        loop {
                            let mut guard = match if_fd.readable().await {
                                Ok(guard) => guard,
                                Err(e) => {
                                    error!("Unable to wait for readability on interface {if_name}, index: {if_index}: {e}");
                                    continue;
                                }
                            };
                            if !guard.ready().is_readable() {
                                continue;
                            }
                            let mut pkts = Vec::with_capacity(128);
                            match guard.try_io(|fd| {
                                Self::packet_recv(if_name.as_str(), fd.as_raw_fd(), if_index, 128, &mut pkts).map_err(|e| {
                                    e.into()
                                })
                            }) {
                                Ok(result) => match result {
                                    Ok(()) => (),
                                    Err(e) => {
                                        error!("Unable to receive packet on interface {if_name}, index: {if_index}: {e}");
                                    }
                                },
                                Err(_wouldblock) => (),
                            }
                            if (iters.is_multiple_of(1_000)) {
                                debug!("Received {} packets from interface {if_name}, index: {if_index}", pkts.len());
                            }
                            trace!("Received {} packets from interface {if_name}, index: {if_index}", pkts.len());
                            for pkt in pkts {
                                let target = Self::compute_worker_idx(&pkt, num_worker_chans);
                                if let Err(mut e) = to_workers[target].try_send(pkt) {
                                    match e {
                                        chan::error::TrySendError::Full(mut pkt) => {
                                            // queue full => soft drop
                                            // FIXME(mvachhar): this is bad, we need to increment drop stats here, but how?
                                            pkt.done(DoneReason::InternalDrop);
                                            debug!("Worker {target} queue full: dropping packet");
                                        }
                                        chan::error::TrySendError::Closed(mut pkt) => {
                                            pkt.done(DoneReason::InternalFailure);
                                            error!(
                                                "Worker {target} channel closed: dropping packet, exiting loop"
                                            );
                                            break;
                                        }
                                    }
                                } else {
                                    trace!(worker = target, "dispatched packet to worker");
                                }
                            }
                            iters += 1;
                        }
                    });
                });

            loop {
                let mut iters = 0u64;
                let mut pkts = Vec::with_capacity(64);
                tokio::select! {
                    pkt_count = from_workers.recv_many(&mut pkts, 64) => {
                        if (iters.is_multiple_of(1_000)) {
                            debug!("Received {pkt_count} packets from workers");
                        }
                        trace!("Received {pkt_count} packets from workers");
                        for pkt in pkts {
                            trace!("Working to transmit packet from worker {pkt:?}");
                            let oif_id_opt = pkt.get_meta().oif;
                            if let Some(oif_id) = oif_id_opt {
                                if let Some(outgoing) = kiftable.get_mut(oif_id) {
                                    match pkt.serialize() {
                                        Ok(out) => {
                                            let len = out.as_ref().len();
                                            if let Err(e) = outgoing.write_sock.write(out.as_ref()) {
                                                match e.kind() {
                                                    std::io::ErrorKind::WouldBlock => {
                                                        debug!("TX drop: write would block ({len} octets) on '{}': {e}", &outgoing.name);
                                                    },
                                                    _ => {
                                                        error!("TX failed for pkt ({len} octets) on '{}': {e}", &outgoing.name);
                                                    }
                                                }
                                                warn!(
                                                    "TX failed for pkt ({len} octets) on '{}': {e}",
                                                    &outgoing.name
                                                );
                                            } else {
                                                trace!("TX {len} bytes on interface {}", &outgoing.name);
                                            }
                                        }
                                        Err(e) => error!("Serialize failed: {e:?}"),
                                    }
                                } else {
                                    warn!("TX drop: unknown oif {}", oif_id);
                                }
                            } else {
                            // No oif set -> inspect DoneReason via enforce()
                                match pkt.enforce() {
                                    Some(_keep) => {
                                        // Packet is not marked for drop by the pipeline (Delivered/None/keep=true),
                                        // but we still can't TX without an oif; drop here.
                                        error!(
                                            "No oif in packet meta; enforce() => keep/Delivered; dropping here"
                                        );
                                    }
                                    None => {
                                        // Pipeline explicitly marked it to be dropped
                                        debug!("Packet marked for drop by pipeline (enforce() => None)");
                                    }
                                }
                            }
                        }
                    }
                }
                iters += 1;
            }
            error!("Kernel driver exiting unexpectedly");
        });
    }

    /// Tries to receive frames from the indicated interface and builds `Packet`s
    /// out of them. Returns a vector of [`Packet`]s.
    #[allow(clippy::vec_box)] // We want to avoid Packet moves, so allow Vec<Box<_>> to be sure
    fn packet_recv(
        if_name: &str,
        if_fd: i32,
        if_index: InterfaceIndex,
        max_to_read: usize,
        pkts: &mut Vec<Box<Packet<TestBuffer>>>,
    ) -> Result<(), nix::Error> {
        let mut raw = [0u8; 9100];
        let mut ret = Ok(());
        pkts.clear();
        while (pkts.len() < max_to_read) {
            match nix::sys::socket::recv(
                if_fd,
                &mut raw,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT | nix::sys::socket::MsgFlags::MSG_TRUNC,
            ) {
                Ok(0) => break, // no more
                Ok(bytes) => {
                    trace!("Received packet with {} bytes on {}", bytes, if_name);
                    // build TestBuffer and parse
                    if (raw.len() < bytes) {
                        error!(
                            "Received packet with {bytes} bytes on {if_name} but raw buffer is only {} bytes, trunctating",
                            raw.len()
                        );
                    }
                    let buf = TestBuffer::from_raw_data(&raw[..std::cmp::min(raw.len(), bytes)]);
                    match Packet::new(buf) {
                        Ok(mut incoming) => {
                            incoming.get_meta_mut().iif = Some(if_index);
                            pkts.push(Box::new(incoming));
                        }
                        Err(e) => {
                            // Parsing errors happen; avoid logspam for loopback
                            if if_name != "lo" {
                                error!("Failed to parse packet on '{}': {e}", if_name);
                            }
                        }
                    }
                }
                Err(e) if e == nix::errno::Errno::EWOULDBLOCK => {
                    ret = Err(e);
                    break;
                }
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            }
        }
        ret
    }
}
