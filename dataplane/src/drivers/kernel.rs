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
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

use crate::CmdArgs;
use net::buffer::test_buffer::TestBuffer;
use net::packet::Packet;
use net::packet::InterfaceId;
use netdev::Interface;
use pipeline::DynPipeline;
use tracing::{debug, error, warn};

// -------- Worker sharding & hashing --------
use ahash::AHasher;
use crossbeam_channel as chan; // Cargo.toml: crossbeam-channel = "0.5"
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::flow_table::{FlowKey, IpProtoKey, TcpProtoKey, UdpProtoKey};
use crate::headers::{Net, Transport, TryHeaders, TryIp, TryTransport};

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
        sock.set_non_blocking().map_err(|e| {
            error!("Failed to set non-blocking on '{name}': {e}");
            e
        })?;
        sock.bind(name).map_err(|e| {
            error!("Failed to bind to interface '{name}': {e}");
            e
        })?;
        let raw_fd = sock.as_raw_fd();
        let iface = Self {
            ifindex,
            token,
            name: name.to_owned(),
            sock,
            raw_fd,
        };
        debug!("Successfully created interface '{name}' (ifindex={ifindex})");
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
    /// is created and a poller [`Token`] assigned. Failures are simply logged.
    pub fn add(&mut self, ifindex: u32, name: &str) -> io::Result<()> {
        debug!("Adding interface '{name}'...");
        let token = Token(self.next_token);
        let interface = Kif::new(ifindex, name, token)?;
        let mut source = SourceFd(&interface.raw_fd);
        self.poll
            .registry()
            .register(&mut source, token, Interest::READABLE)
            .map_err(|e| {
                error!("Failed to register interface '{name}': {e}");
                e
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

    /// Get a mutable refernce to the [`Kif`] with the indicated ifindex
    /// Todo: replace this linear search with a hash lookup
    pub fn get_mut_by_index(&mut self, ifindex: u32) -> Option<&mut Kif> {
        self.by_token
            .values_mut()
            .find(|kif| kif.ifindex == ifindex)
    }
}

/// Get the ifindex of the interface with the given name
fn get_interface_ifindex(interfaces: &[Interface], name: &str) -> Option<u32> {
    interfaces
        .iter()
        .position(|interface| interface.name == name)
        .map(|pos| interfaces[pos].index)
}

/// Build a table of kernel interfaces to receive packets from (or send to).
/// Interfaces of interest are indicated by --interface INTERFACE in the command line.
/// Argument --interface ANY|any instructs the driver to capture on all interfaces.
fn build_kif_table(args: impl IntoIterator<Item = impl AsRef<str> + Clone>) -> io::Result<KifTable> {
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
/// This version of the kernel driver does not create any interface,
/// but expects to be indicated the interfaces to receive packets from.
pub struct DriverKernel;

impl DriverKernel {
    /// Compute a **symmetric** worker index for a parsed `Packet`.
    ///
    /// - Uses a bidirectional 5-tuple via `FlowKey::bidi()` so A→B and B→A map to the same worker.
    /// - If the packet isn’t IP (no L3), falls back to an L2-based hash (not guaranteed symmetric).
    /// - Works with any positive `workers`; prefers power-of-two bucket sizes (uses `& (n-1)`).
    ///
    /// This function is pure and has no side effects.
    #[must_use]
    pub fn compute_worker_idx(pkt: &Packet<TestBuffer>, workers: usize) -> usize {
        let n = workers.max(1);

        // Try to build a symmetric FlowKey from IP + (optional) transport
        if let Some(ip) = pkt.headers().try_ip() {
            let (src_ip, dst_ip, ip_proto_key) = match ip {
                Net::Ipv4(ipv4) => {
                    let src: IpAddr = (*ipv4.source()).into();
                    let dst: IpAddr = (*ipv4.destination()).into();
                    let ipk = match pkt.headers().try_transport() {
                        Some(Transport::Tcp(tcp)) => {
                            IpProtoKey::Tcp(TcpProtoKey {
                                src_port: *tcp.source(),
                                dst_port: *tcp.destination(),
                            })
                        }
                        Some(Transport::Udp(udp)) => {
                            IpProtoKey::Udp(UdpProtoKey {
                                src_port: *udp.source(),
                                dst_port: *udp.destination(),
                            })
                        }
                        _ => IpProtoKey::Icmp,
                    };
                    (src, dst, ipk)
                }
                Net::Ipv6(ipv6) => {
                    let src: IpAddr = (*ipv6.source()).into();
                    let dst: IpAddr = (*ipv6.destination()).into();
                    let ipk = match pkt.headers().try_transport() {
                        Some(Transport::Tcp(tcp)) => {
                            IpProtoKey::Tcp(TcpProtoKey {
                                src_port: *tcp.source(),
                                dst_port: *tcp.destination(),
                            })
                        }
                        Some(Transport::Udp(udp)) => {
                            IpProtoKey::Udp(UdpProtoKey {
                                src_port: *udp.source(),
                                dst_port: *udp.destination(),
                            })
                        }
                        _ => IpProtoKey::Icmp,
                    };
                    (src, dst, ipk)
                }
            };

            let key = FlowKey::bidi(None, src_ip, None, dst_ip, ip_proto_key);
            let mut h = AHasher::default();
            key.hash(&mut h);
            let hv = h.finish() as usize;
            return if n.is_power_of_two() {
                hv & (n - 1)
            } else {
                hv % n
            };
        }

        // Fallback: hash L2 frame (Ether + VLANs + some L3 invariants if any)
        let mut h = AHasher::default();
        pkt.hash_l2_frame(&mut h);
        let hv = h.finish() as usize;
        if n.is_power_of_two() {
            hv & (n - 1)
        } else {
            hv % n
        }
    }

    /// Spawn worker threads, each with its own pipeline. Workers receive parsed Packets,
    /// run the pipeline, and send the resulting Packets back to the dispatcher.
    ///
    /// Serialization and TX remain **centralized** in the dispatcher thread.
    fn spawn_workers(
        workers: usize,
        setup_pipeline: Arc<dyn Fn() -> DynPipeline<TestBuffer> + Send + Sync + 'static>,
    ) -> io::Result<(Vec<chan::Sender<Packet<TestBuffer>>>, chan::Receiver<Packet<TestBuffer>>)> {
        let w = workers.max(1);
        let (tx_from_workers, rx_from_workers) = chan::bounded::<Packet<TestBuffer>>(2048);
        let mut to_workers = Vec::with_capacity(w);

        for wid in 0..w {
            let (tx_to_worker, rx_to_worker) = chan::bounded::<Packet<TestBuffer>>(4096);
            to_workers.push(tx_to_worker);

            let tx_out = tx_from_workers.clone();
            let setup = setup_pipeline.clone();

            let builder = std::thread::Builder::new().name(format!("dp-worker-{wid}"));
            let spawn_res = builder.spawn(move || {
                let mut pipeline = (setup)();
                loop {
                    match rx_to_worker.recv() {
                        Ok(pkt) => {
                            let out_iter = pipeline.process(std::iter::once(pkt));
                            for out_pkt in out_iter {
                                let _ = tx_out.try_send(out_pkt);
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            if let Err(e) = spawn_res {
                error!("Failed to spawn worker {wid}: {e}");
                return Err(io::Error::new(io::ErrorKind::Other, "spawn failed"));
            }
        }

        Ok((to_workers, rx_from_workers))
    }

    /// Starts the kernel driver.
    ///
    /// `workers` is the number of parallel pipelines to run. Use a power of two for
    /// slightly faster sharding (bitmask). Minimum is 1.
    ///
    /// `setup_pipeline` is a factory used to build a **dedicated pipeline per worker**.
    pub fn start<F>(
        args: impl IntoIterator<Item = impl AsRef<str> + Clone>,
        workers: usize,
        setup_pipeline: F,
    ) where
        F: Fn() -> DynPipeline<TestBuffer> + Send + Sync + 'static,
    {
        // Build kernel interface table from interfaces available and cmd line args
        let mut kiftable = match build_kif_table(args) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to initialize kernel interface table: {e}");
                return;
            }
        };

        // Wrap user closure into Arc so we can clone into worker threads
        let setup_pipeline: Arc<dyn Fn() -> DynPipeline<TestBuffer> + Send + Sync + 'static> =
            Arc::new(setup_pipeline);

        // Build worker threads and channels
        let (to_workers, from_workers) = match Self::spawn_workers(workers, setup_pipeline) {
            Ok(chans) => chans,
            Err(e) => {
                error!("Failed to start workers: {e}");
                return;
            }
        };
        let buckets = to_workers.len();
        let poll_timeout = Some(Duration::from_millis(2));

        // Poll registered interfaces
        let mut events = Events::with_capacity(64);
        loop {
            // Drain processed packets from workers first (centralized serialize+TX)
            while let Ok(mut pkt) = from_workers.try_recv() {
                let oif_id_opt = {
                    let meta = pkt.get_meta();
                    meta.oif.as_ref().map(|id| id.get_id())
                };
                if let Some(oif_id) = oif_id_opt {
                    if let Some(outgoing) = kiftable.get_mut_by_index(oif_id) {
                        match pkt.serialize() {
                            Ok(out) => {
                                debug!(
                                    "TX {} bytes on interface {}",
                                    out.as_ref().len(),
                                    &outgoing.name
                                );
                                if let Err(e) = outgoing.sock.write_all(out.as_ref()) {
                                    error!("Transmit failed on '{}': {e}", &outgoing.name);
                                }
                            }
                            Err(e) => error!("Serialize failed: {e:?}"),
                        }
                    } else {
                        warn!("TX drop: unknown oif {}", oif_id);
                    }
                }
            }

            if let Err(e) = kiftable.poll.poll(&mut events, poll_timeout) {
                warn!("Poll error: {e}");
                continue;
            }

            for event in &events {
                if !event.is_readable() {
                    continue;
                }
                if let Some(interface) = kiftable.get_mut(event.token()) {
                    // Receive and parse frames into Packets
                    let pkts = DriverKernel::packet_recv(interface);

                    // Dispatch each packet to a worker based on symmetric flow hash
                    for pkt in pkts {
                        let idx = Self::compute_worker_idx(&pkt, buckets);
                        let target = idx % buckets; // defensive
                        let _ = to_workers[target].try_send(pkt);
                    }
                }
            }
        }
    }

    /// Tries to receive frames from the indicated interface and builds `Packet`s
    /// out of them. Returns a vector of [`Packet`]s
    pub fn packet_recv(interface: &mut Kif) -> Vec<Packet<TestBuffer>> {
        let mut raw = [0u8; 2048];
        let mut pkts = Vec::with_capacity(10);
        while let Ok(bytes) = interface.sock.read(&mut raw) {
            if bytes == 0 {
                break;
            }
            /* build test buffer from raw data */
            let buf = TestBuffer::from_raw_data(&raw[0..bytes]);
            /* build Packet (parse) */
            match Packet::new(buf) {
                Ok(mut incoming) => {
                    /* set the iif id */
                    let mut meta = incoming.get_meta_mut();
                    meta.iif = InterfaceId::new(interface.ifindex);
                    pkts.push(incoming);
                }
                Err(e) => {
                    if interface.name != "lo" {
                        error!("Failed to parse packet on '{}': {e}", interface.name);
                    }
                }
            }
        }
        pkts
    }
}
