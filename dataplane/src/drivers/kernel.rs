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
use args::{InterfaceArg, PortArg};
use concurrency::sync::Arc;
use concurrency::thread;

use tokio::sync::mpsc as chan;
use tokio::time::timeout;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use std::collections::hash_map::DefaultHasher;
use std::fmt::Display;
use std::hash::{Hash, Hasher};

use net::buffer::test_buffer::TestBuffer;
use net::interface::{InterfaceIndex, InterfaceName};
use net::packet::{DoneReason, Packet, PortIndex};
use netdev::Interface;
use pipeline::{DynPipeline, NetworkFunction};
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use pkt_io::{PortMapWriter, PortSpec, build_portmap};

// Flow-key based symmetric hashing
use pkt_meta::flow_table::flow_key::{Bidi, FlowKey};

use crate::drivers::tokio_util::run_in_tokio_runtime;

use tracectl::trace_target;
trace_target!("kernel-driver", LevelFilter::INFO, &["driver"]);

type WorkerTx = chan::Sender<Box<Packet<TestBuffer>>>;
type WorkerRx = chan::Receiver<Box<Packet<TestBuffer>>>;
type WorkerChans = (Vec<WorkerTx>, WorkerRx);

/// Simple representation of a kernel interface.
pub struct Kif {
    name: InterfaceName,     // name of PORT interface
    ifindex: InterfaceIndex, // ifindex of PORT interface
    token: Token,            // token for polling
    sock: RawPacketStream,   // packet socket
    raw_fd: RawFd,           // raw desc of packet socket
    pindex: PortIndex, // port index. This is how the kernel interface is externally identified

    tapname: InterfaceName,             // name of tap interface
    tapifindex: Option<InterfaceIndex>, // tap ifindex
}

impl Kif {
    /// Create a kernel interface entry. Each interface gets a [`Token`] assigned
    /// and a packet socket opened, which gets registered in a poller to detect
    /// activity.
    fn new(
        ifindex: InterfaceIndex,
        name: &InterfaceName,
        token: Token,
        tapname: &InterfaceName,
    ) -> Result<Self, String> {
        let mut sock = RawPacketStream::new()
            .map_err(|e| format!("Failed to open raw sock for interface {name}: {e}"))?;
        sock.set_non_blocking();
        sock.bind(name.as_ref())
            .map_err(|e| format!("Failed to open raw sock for interface {name}: {e}"))?;

        let raw_fd = sock.as_raw_fd();
        #[allow(clippy::cast_possible_truncation)]
        let pindex = PortIndex::new(ifindex.to_u32() as u16);
        let iface = Self {
            ifindex,
            token,
            name: name.clone(),
            sock,
            raw_fd,
            pindex,
            tapname: tapname.clone(),
            tapifindex: None,
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
    pub fn new() -> Result<Self, String> {
        let poll = Poll::new().map_err(|e| format!("Failed to create kif poller: {e}"))?;
        Ok(Self {
            poll,
            next_token: 1,
            by_token: HashMap::new(),
        })
    }
    /// Add a kernel interface 'representor' to this table. For each interface, a packet socket
    /// is created and a poller [`Token`] assigned.
    pub fn add(
        &mut self,
        ifindex: InterfaceIndex,
        name: &InterfaceName,
        tapname: &InterfaceName,
    ) -> Result<(), String> {
        debug!("Adding interface '{name}'...");
        let token = Token(self.next_token);
        let interface = Kif::new(ifindex, name, token, tapname)?;
        let mut source = SourceFd(&interface.raw_fd);
        self.poll
            .registry()
            .register(&mut source, token, Interest::READABLE)
            .map_err(|e| format!("Failed to register interface '{name}': {e}"))?;
        self.by_token.insert(token, interface);
        self.next_token += 1;
        debug!("Successfully registered interface '{name}' with token {token:?}");
        Ok(())
    }
    /// Get a mutable reference to the [`Kif`] with the indicated [`Token`].
    pub fn get_mut(&mut self, token: Token) -> Option<&mut Kif> {
        self.by_token.get_mut(&token)
    }

    /// Get a mutable reference to the [`Kif`] with the given tapifindex
    pub fn get_mut_by_tap_index(&mut self, tapifindex: InterfaceIndex) -> Option<&mut Kif> {
        self.by_token
            .values_mut()
            .find(|kif| kif.tapifindex == Some(tapifindex))
    }
}

macro_rules! KIF_FMT {
    () => {
        "   {:<16} {:<11} {:<6} {:<16} {:<8}"
    };
}
fn fmt_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        KIF_FMT!(),
        "Port", "Portifindex", "pindex", "interface", "ifindex"
    )
}

impl Display for Kif {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tapifindex = if let Some(i) = self.tapifindex {
            i.to_string()
        } else {
            "--".to_string()
        };
        writeln!(
            f,
            KIF_FMT!(),
            self.name.to_string(),
            self.ifindex.to_string(),
            self.pindex.to_string(),
            self.tapname.to_string(),
            tapifindex
        )
    }
}
impl Display for KifTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━ kernel driver  ━━━━━━━━━━━━━━━━━━━━━━━━━"
        )?;
        fmt_heading(f)?;
        for kif in self.by_token.values() {
            kif.fmt(f)?;
        }
        writeln!(
            f,
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )
    }
}

/// Get the ifindex of the kernel interface with the given name.
fn get_interface_ifindex(interfaces: &[Interface], name: &str) -> Option<InterfaceIndex> {
    interfaces
        .iter()
        .position(|interface| interface.name == name)
        .and_then(|pos| InterfaceIndex::try_new(interfaces[pos].index).ok())
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
        run_in_tokio_runtime(async || {
            loop {
                // receive packets from IO thread. If we don't, check pipeline anyway since there may be pkts to send.
                // This is done every 20ms at the moment.
                let mut packets_vec = Vec::new();
                if let Ok(0) = timeout(Duration::from_millis(20), rx_from_control.recv_many(&mut packets_vec, 1024)).await {
                    trace!(worker = id, thread = %thread::current().name().unwrap_or("unnamed"), "sender closed, exiting");
                    return;
                }
                let packets = packets_vec.into_iter();
                let mut count = 0;
                for out_pkt in pipeline.process(packets.map(|pkt| *pkt)) {
                    // backpressure via bounded channel
                    if tx_to_control.send(Box::new(out_pkt)).await.is_err() {
                        warn!("Kernel IO channel closed. IO thread may be gone. Stopping...");
                        return;
                    }
                    count += 1;
                }

                tracing::debug!(
                    worker = id,
                    thread = %thread::current().name().unwrap_or("unnamed"),
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
    fn compute_worker_idx(pkt: &Packet<TestBuffer>, workers: usize) -> usize {
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
    ) -> WorkerChans {
        let (tx_to_control, rx_from_workers) = chan::channel::<Box<Packet<TestBuffer>>>(4096);
        let mut to_workers = Vec::with_capacity(num_workers);
        info!("Spawning {num_workers} workers");
        for wid in 0..num_workers {
            let builder = thread::Builder::new().name(format!("dp-worker-{wid}"));
            if let Ok(tx_to_worker) =
                single_worker(wid, builder, tx_to_control.clone(), setup_pipeline)
            {
                to_workers.push(tx_to_worker);
            } else {
                error!("Failed to spawn pipeline worker {wid}");
            }
        }
        (to_workers, rx_from_workers)
    }

    /// Init devices depending on command line. This creates a `KifTable` for local representation of kernel interfaces.
    fn init_devices(args: impl Iterator<Item = InterfaceArg>) -> Result<KifTable, String> {
        // get all kernel interfaces
        let inventory_kern_ifs = netdev::get_interfaces();

        // create empty kernel interface table
        let mut kiftable = KifTable::new()?;

        // populate the kernel interface table with the desired interfaces
        for ifarg in args {
            match ifarg.port {
                Some(PortArg::PCI(_)) => {
                    error!("kernel driver does not support PCI ports");
                    return Err("kernel driver does not support PCI ports".to_string());
                }
                Some(PortArg::KERNEL(name)) => {
                    let Some(ifindex) = get_interface_ifindex(&inventory_kern_ifs, name.as_ref())
                    else {
                        return Err(format!("Could not find kernel interface {name}"));
                    };
                    if let Err(e) = kiftable.add(ifindex, &name, &ifarg.interface) {
                        error!("Could not add kernel interface '{name}': {e}");
                        return Err(e);
                    }
                }
                _ => {
                    // TODO: remove Option<> from PortArg as it will need to be mandatory
                    // after the integration
                    return Err("Port specification is mandatory".to_string());
                }
            }
        }
        // we allow starting the dataplane without any kernel interface.
        // this is mostly for testing features that don't require packet handling.
        if kiftable.by_token.is_empty() {
            warn!(">>>>> Did not register any kernel interface: no packets will be received <<<<<");
        }
        Ok(kiftable)
    }

    /// Register devices in the port map and return back the writer and factory
    fn register_devices(kiftable: &mut KifTable) -> PortMapWriter {
        // build port specs from the kifs to populate portmap
        let pspecs: Vec<_> = kiftable
            .by_token
            .values()
            .map(|kif| PortSpec::new(kif.name.to_string(), kif.pindex, kif.tapname.clone()))
            .collect();

        // populate port-map
        let mapw = build_portmap(pspecs.into_iter());

        // burn the tap ifindex in the kif so that we need not look it up
        let rh = mapw.factory().handle();
        kiftable.by_token.values_mut().for_each(|kif| {
            kif.tapifindex = Some(
                rh.get_by_pdesc(&kif.name.to_string())
                    .unwrap_or_else(|| unreachable!())
                    .ifindex,
            );
        });

        // give ownership of portmap writer
        mapw
    }

    /// Start the kernel IO thread for rx/tx
    fn start_kernel_io_thread(
        to_workers: Vec<WorkerTx>,
        mut from_workers: WorkerRx,
        mut kiftable: KifTable,
    ) {
        // IO thread takes ownership of kiftable
        let io = move || {
            let num_worker_chans = to_workers.len();
            let poll_timeout = Some(Duration::from_millis(2));

            info!("Kernel interface configuration is:\n{kiftable}");

            // Dispatcher loop: drain processed packets, poll RX, parse+shard, TX results.
            let mut events = Events::with_capacity(256);
            loop {
                // 1) Drain processed packets coming back from workers, serialize + TX
                while let Ok(mut pkt) = from_workers.try_recv() {
                    // choose outgoing port interface from pkt metadata
                    if let Some(oif_id) = pkt.get_meta().oif {
                        if let Some(okif) = kiftable.get_mut_by_tap_index(oif_id) {
                            match pkt.serialize() {
                                Ok(out) => {
                                    let len = out.as_ref().len();
                                    if let Err(e) = okif.sock.write_all(out.as_ref()) {
                                        error!(
                                            "TX failed for pkt ({len} octets) on '{}': {e}",
                                            &okif.name
                                        );
                                    } else {
                                        trace!("TX {len} bytes on port {}", &okif.name);
                                    }
                                }
                                Err(e) => error!("Serialize failed: {e:?}"),
                            }
                        } else {
                            warn!("TX drop: unknown outgoing port {}", oif_id);
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
                Self::recv_packets(&mut kiftable, &events).for_each(|pkt| {
                    let target = Self::compute_worker_idx(&pkt, num_worker_chans);
                    if let Err(e) = to_workers[target].try_send(pkt) {
                        match e {
                            chan::error::TrySendError::Full(_) => {
                                // queue full => soft drop
                                // FIXME(mvachhar): this is bad, we need to increment drop stats here, but how?
                                // FIXME(mvachhar): We need to backpressure the NIC without starving other workers, how do we do that?
                                warn!("Worker {target} queue full: dropping packet");
                            }
                            chan::error::TrySendError::Closed(_) => {
                                error!("Worker {target} channel closed: dropping packet");
                            }
                        }
                    } else {
                        trace!(worker = target, "dispatched packet to worker");
                    }
                });
            }
        };

        // spawn
        #[allow(clippy::expect_used)]
        thread::Builder::new()
            .name("kernel-driver-io".to_string())
            .spawn(io)
            .expect("Fatal: failed to spawn kernel driver IO thread");

        info!("Kernel driver IO thread spawned");
    }

    /// Starts the kernel driver, spawns worker threads, IO thread and runs the dispatcher loop.
    ///
    /// - `args`: kernel driver CLI parameters (e.g., `--interface` list)
    /// - `workers`: number of worker threads / pipelines
    /// - `setup_pipeline`: factory returning a **fresh** `DynPipeline<TestBuffer>` per worker
    #[allow(clippy::panic, clippy::missing_panics_doc)]
    pub fn start(
        interfaces: impl Iterator<Item = InterfaceArg>,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
    ) -> PortMapWriter {
        // init port devices
        let mut kiftable = match Self::init_devices(interfaces) {
            Ok(kiftable) => kiftable,
            Err(e) => {
                error!("{e}");
                panic!("{e}");
            }
        };

        // register port devices
        let mapt_w = Self::register_devices(&mut kiftable);

        // Spawn pipeline workers
        let (to_workers, from_workers) = Self::spawn_workers(num_workers, setup_pipeline);
        if to_workers.len() != num_workers {
            warn!(
                "Could spawn only {} of {} workers",
                to_workers.len(),
                num_workers
            );
        }
        assert!(
            !to_workers.is_empty(),
            "Could not start any pipeline worker!"
        );

        // Spawn io thread
        Self::start_kernel_io_thread(to_workers, from_workers, kiftable);

        // return maptable writer
        mapt_w
    }

    fn recv_packets(
        kiftable: &mut KifTable,
        events: &mio::Events,
    ) -> impl Iterator<Item = Box<Packet<TestBuffer>>> {
        events
            .iter()
            .filter(|e| e.is_readable())
            .map(mio::event::Event::token)
            .filter_map(|token| kiftable.get_mut(token).map(Self::packet_recv))
            .flatten()
    }

    /// Tries to receive frames from the indicated interface and builds `Packet`s
    /// out of them. Returns a vector of [`Packet`]s.
    #[allow(clippy::vec_box)] // We want to avoid Packet moves, so allow Vec<Box<_>> to be sure
    fn packet_recv(kif: &mut Kif) -> Vec<Box<Packet<TestBuffer>>> {
        let mut raw = [0u8; 2048];
        let mut pkts = Vec::with_capacity(32);
        loop {
            match kif.sock.read(&mut raw) {
                Ok(0) => break, // no more
                Ok(bytes) => {
                    // build TestBuffer and parse
                    let buf = TestBuffer::from_raw_data(&raw[..bytes]);
                    match Packet::new(buf) {
                        Ok(mut incoming) => {
                            // we'll probably ditch iport, but for the time being....
                            incoming.get_meta_mut().iport = Some(kif.pindex);
                            incoming.get_meta_mut().iif = kif.tapifindex;
                            pkts.push(Box::new(incoming));
                        }
                        Err(e) => {
                            // Parsing errors happen; avoid logspam for loopback
                            if kif.name.as_ref() != "lo" {
                                error!("Failed to parse packet on '{}': {e}", kif.name);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("Read error on '{}': {e}", kif.name);
                    break;
                }
            }
        }
        pkts
    }
}
