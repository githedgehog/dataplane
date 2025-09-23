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

use afpacket::sync::RawPacketStream;

use concurrency::sync::Arc;
use concurrency::thread;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use crossbeam_channel as chan;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use net::buffer::test_buffer::TestBuffer;
use net::packet::{InterfaceId, Packet};
use netdev::Interface;
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, info, warn};

// Flow-key based symmetric hashing
use pkt_meta::flow_table::flow_key::{Bidi, FlowKey};

type WorkerTx = chan::Sender<Packet<TestBuffer>>;
type WorkerRx = chan::Receiver<Packet<TestBuffer>>;
type WorkerChans = (Vec<WorkerTx>, WorkerRx);

/// Simple representation of a kernel interface.
pub struct Kif {
    ifindex: u32,          /* ifindex of interface */
    token: Token,          /* token for polling */
    name: String,          /* name of interface */
    sock: RawPacketStream, /* packet socket */
    raw_fd: RawFd,         /* raw desc of packet socket */
}

impl Kif {
    /// Create a kernel interface entry. Each interface gets a [`Token`] assigned
    /// and a packet socket opened, which gets registered in a poller to detect
    /// activity.
    fn new(ifindex: u32, name: &str, token: Token) -> io::Result<Self> {
        let mut sock = RawPacketStream::new().map_err(|e| {
            error!("Failed to open raw sock for interface {name}: {e}");
            e
        })?;
        sock.set_non_blocking();
        sock.bind(name)
            .inspect_err(|e| error!("Failed to open raw sock for interface {name}: {e}"))?;
        let raw_fd = sock.as_raw_fd();
        let iface = Self {
            ifindex,
            token,
            name: name.to_owned(),
            sock,
            raw_fd,
        };
        debug!("Successfully created interface '{name}'");
        Ok(iface)
    }
}

/// A hash table of kernel interfaces [`Kif`]s, keyed by some arbitrary but unique token.
pub struct KifTable {
    poll: Poll,
    by_token: HashMap<Token, Kif>,
    next_token: usize,
}

impl KifTable {
    /// Create kernel interface table
    pub fn new() -> io::Result<Self> {
        let poll = Poll::new()?;
        Ok(Self {
            poll,
            next_token: 1,
            by_token: HashMap::new(),
        })
    }
    /// Add a kernel interface 'representor' to this table. For each interface, a packet socket
    /// is created and a poller [`Token`] assigned.
    pub fn add(&mut self, ifindex: u32, name: &str) -> io::Result<()> {
        debug!("Adding interface '{name}'...");
        let token = Token(self.next_token);
        let interface = Kif::new(ifindex, name, token)?;
        let mut source = SourceFd(&interface.raw_fd);
        self.poll
            .registry()
            .register(&mut source, token, Interest::READABLE)
            .inspect_err(|e| {
                error!("Failed to register interface '{name}': {e}");
            })?;
        self.by_token.insert(token, interface);
        self.next_token += 1;
        debug!("Successfully registered interface '{name}' with token {token:?}");
        Ok(())
    }
    /// Get a mutable reference to the [`Kif`] with the indicated [`Token`].
    pub fn get_mut(&mut self, token: Token) -> Option<&mut Kif> {
        self.by_token.get_mut(&token)
    }

    /// Get a mutable reference to the [`Kif`] with the indicated ifindex.
    /// TODO: replace this linear search with a hash lookup if needed.
    pub fn get_mut_by_index(&mut self, ifindex: u32) -> Option<&mut Kif> {
        self.by_token
            .values_mut()
            .find(|kif| kif.ifindex == ifindex)
    }
}

/// Get the ifindex of the interface with the given name.
fn get_interface_ifindex(interfaces: &[Interface], name: &str) -> Option<u32> {
    interfaces
        .iter()
        .position(|interface| interface.name == name)
        .map(|pos| interfaces[pos].index)
}

/// Build a table of kernel interfaces to receive packets from (or send to).
/// Interfaces of interest are indicated by --interface INTERFACE in the command line.
/// Argument --interface ANY|any instructs the driver to capture on all interfaces.
fn build_kif_table(
    args: impl IntoIterator<Item = impl AsRef<str> + Clone>,
) -> io::Result<KifTable> {
    /* learn about existing kernel network interfaces. We need these to know their ifindex  */
    let interfaces = netdev::get_interfaces();

    /* build kiftable */
    let mut kiftable = KifTable::new()?;

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
            if let Err(e) = kiftable.add(interface.index, &interface.name) {
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
    tx_to_control: chan::Sender<Packet<TestBuffer>>,
    setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
) -> Result<chan::Sender<Packet<TestBuffer>>, std::io::Error> {
    let (tx_to_worker, rx_from_control) = chan::bounded::<Packet<TestBuffer>>(4096);
    let setup = setup_pipeline.clone();

    let handle_res = thread_builder.spawn(move || {
        let mut pipeline = setup();
        // Prefer while-let over loop+match (clippy::while_let_loop)
        while let Ok(pkt) = rx_from_control.recv() {
            tracing::debug!(
                worker = id,
                thread = %thread::current().name().unwrap_or("unnamed"),
                pkt_len = pkt.total_len(),
                "processing packet"
            );
            // feed single packet iterator through the worker's pipeline
            // TODO: Add packet batching support
            for out_pkt in pipeline.process(std::iter::once(pkt)) {
                // backpressure via bounded channel
                if tx_to_control.send(out_pkt).is_err() {
                    // dispatcher gone; exit the thread
                    return;
                }
            }
        }
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
    ///   - `Vec<Sender<Packet<TestBuffer>>>` one sender per worker (dispatcher -> worker)
    ///   - `Receiver<Packet<TestBuffer>>` a single queue for processed packets (worker -> dispatcher)
    fn spawn_workers(
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
    ) -> io::Result<WorkerChans> {
        let (tx_to_control, rx_from_workers) = chan::bounded::<Packet<TestBuffer>>(4096);
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

        Ok((to_workers, rx_from_workers))
    }

    /// Starts the kernel driver, spawns worker threads, and runs the dispatcher loop.
    ///
    /// - `args`: kernel driver CLI parameters (e.g., `--interface` list)
    /// - `workers`: number of worker threads / pipelines
    /// - `setup_pipeline`: factory returning a **fresh** `DynPipeline<TestBuffer>` per worker
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
        let (to_workers, from_workers) = match Self::spawn_workers(num_workers, setup_pipeline) {
            Ok(chans) => chans,
            Err(e) => {
                error!("Failed to start workers: {e}");
                return;
            }
        };

        let num_worker_chans = to_workers.len();
        assert!(num_worker_chans != 0, "No worker channels available!");
        if num_worker_chans != num_workers {
            warn!(
                "Number of to_worker channels ({num_worker_chans}) does not match number of workers ({num_workers})"
            );
        }

        let poll_timeout = Some(Duration::from_millis(2));

        // Dispatcher loop: drain processed packets, poll RX, parse+shard, TX results.
        let mut events = Events::with_capacity(256);
        loop {
            // 1) Drain processed packets coming back from workers, serialize + TX
            while let Ok(mut pkt) = from_workers.try_recv() {
                // choose outgoing interface from meta
                let oif_id_opt = pkt.get_meta().oif.as_ref().map(InterfaceId::get_id);
                if let Some(oif_id) = oif_id_opt {
                    if let Some(outgoing) = kiftable.get_mut_by_index(oif_id) {
                        match pkt.serialize() {
                            Ok(out) => {
                                if let Err(e) = outgoing.sock.write_all(out.as_ref()) {
                                    error!("TX failed on '{}': {e}", &outgoing.name);
                                } else {
                                    debug!(
                                        "TX {} bytes on interface {}",
                                        out.as_ref().len(),
                                        &outgoing.name
                                    );
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

            // 2) Poll for new RX events
            if let Err(e) = kiftable.poll.poll(&mut events, poll_timeout) {
                warn!("Poll error: {e}");
                continue;
            }

            // 3) For readable interfaces, pull frames, parse to Packet<TestBuffer>, shard to workers
            for event in &events {
                if !event.is_readable() {
                    continue;
                }
                if let Some(interface) = kiftable.get_mut(event.token()) {
                    let pkts = Self::packet_recv(interface);
                    for pkt in pkts {
                        let idx = Self::compute_worker_idx(&pkt, num_worker_chans);
                        let target = idx;
                        // best-effort delivery; if full, drop (bounded channel is the backpressure)
                        if to_workers[target].try_send(pkt).is_err() {
                            // queue full => soft drop
                            warn!("Worker {} queue full: dropping packet", target);
                        } else {
                            debug!(worker = target, "dispatched packet to worker");
                        }
                    }
                }
            }
        }
    }

    /// Tries to receive frames from the indicated interface and builds `Packet`s
    /// out of them. Returns a vector of [`Packet`]s.
    pub fn packet_recv(interface: &mut Kif) -> Vec<Packet<TestBuffer>> {
        let mut raw = [0u8; 2048];
        let mut pkts = Vec::with_capacity(32);
        loop {
            match interface.sock.read(&mut raw) {
                Ok(0) => break, // no more
                Ok(bytes) => {
                    // build TestBuffer and parse
                    let buf = TestBuffer::from_raw_data(&raw[..bytes]);
                    match Packet::new(buf) {
                        Ok(mut incoming) => {
                            incoming.get_meta_mut().iif = InterfaceId::new(interface.ifindex);
                            pkts.push(incoming);
                        }
                        Err(e) => {
                            // Parsing errors happen; avoid logspam for loopback
                            if interface.name != "lo" {
                                error!("Failed to parse packet on '{}': {e}", interface.name);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("Read error on '{}': {e}", interface.name);
                    break;
                }
            }
        }
        pkts
    }
}
