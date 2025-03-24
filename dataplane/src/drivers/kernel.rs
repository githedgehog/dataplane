// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Kernel dataplane driver

use afpacket::sync::RawPacketStream;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

use std::{thread, time};

use crate::CmdArgs;
use default_net::Interface;
use net::buffer::test_buffer::TestBuffer;
use net::packet::DoneReason;
use net::packet::Packet;
use pipeline::{self, DynPipeline, NetworkFunction};
use tracing::{debug, error, warn};

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
    fn new(ifindex: u32, name: &str, token: Token) -> Option<Self> {
        let mut sock = RawPacketStream::new().expect("Failed to create raw sock");
        sock.set_non_blocking();
        if let Err(e) = sock.bind(name) {
            error!("Failed to bind to interface '{name}'");
            return None;
        }
        let raw_fd = sock.as_raw_fd();
        let iface = Self {
            ifindex,
            token,
            name: name.to_owned(),
            sock,
            raw_fd,
        };
        debug!("Successfully created interface '{name}'");
        Some(iface)
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
    pub fn new() -> Self {
        Self {
            poll: Poll::new().expect("Failed to create poller"),
            next_token: 1,
            by_token: HashMap::new(),
        }
    }
    /// Add a kernel interface 'representor' to this table. For each interface, a packet socket
    /// is created and a poller [`Token`] assigned. Failures are simply logged.
    pub fn add(&mut self, ifindex: u32, name: &str) {
        debug!("Adding interface '{name}'...");
        let token = Token(self.next_token);
        let interface = Kif::new(ifindex, name, token);
        if let Some(interface) = interface {
            let mut source = SourceFd(&interface.raw_fd);
            if let Err(e) = self
                .poll
                .registry()
                .register(&mut source, token, Interest::READABLE)
            {
                error!("Failed to register interface '{name}'");
                return;
            }
            self.by_token.insert(token, interface);
            self.next_token += 1;
            debug!("Successfully registered interface '{name}' with token {token:?}");
        }
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
fn build_kif_table(args: impl IntoIterator<Item = impl AsRef<str> + Clone>) -> KifTable {
    /* learn about existing kernel network interfaces. We need these to know their ifindex  */
    let interfaces = default_net::get_interfaces();

    /* build kiftable */
    let mut kiftable = KifTable::new();

    /* check what interfaces we're interested in from args */
    let ifnames: Vec<String> = args.into_iter().map(|x| x.as_ref().to_owned()).collect();
    if ifnames.is_empty() {
        error!("Please specify at least one interface to capture packets from.");
        error!("--interface ANY captures over all interfaces.");
        std::process::exit(-1);
    }

    if ifnames.len() == 1 && ifnames[0].to_uppercase() == "ANY" {
        /* use all interfaces */
        for interface in &interfaces {
            kiftable.add(interface.index, &interface.name);
        }
    } else {
        /* use only the interfaces specified in args */
        for name in &ifnames {
            if let Some(ifindex) = get_interface_ifindex(&interfaces, name) {
                kiftable.add(ifindex, name);
            } else {
                warn!("Could not find ifindex of interface '{name}'");
            }
        }
    }

    kiftable
}

/// Main structure representing the kernel driver.
/// This version of the kernel driver does not create any interface,
/// but expects to be indicated the interfaces to receive packets from.
pub struct DriverKernel;
impl DriverKernel {
    /// Starts the kernel driver
    pub fn start(
        args: impl IntoIterator<Item = impl AsRef<str> + Clone>,
        mut pipeline: DynPipeline<TestBuffer>,
    ) {
        /* build kernel interface table from interfaces available and cmd line args */
        let mut kiftable = build_kif_table(args);

        /* poll the registered interfaces */
        let mut events = Events::with_capacity(64);
        loop {
            kiftable.poll.poll(&mut events, None).expect("Poll error");
            for event in &events {
                if let Some(interface) = kiftable.get_mut(event.token()) {
                    /* get vector of packets (only one) */
                    let pkts = DriverKernel::packet_recv(interface);
                    let pkts_out = pipeline.process(pkts.into_iter());

                    /* deal with processed packets */
                    for mut pkt in pkts_out {
                        let mut meta = pkt.get_meta_mut();
                        if let Some(oif) = &meta.oif {
                            /* lookup outgoing interface and xmit packet */
                            if let Some(outgoing) = kiftable.get_mut_by_index(oif.get_id()) {
                                let mut out = pkt.reserialize();
                                /* fixme: this may fail with EAGAIN since we set all socks as
                                non-blocking. */
                                outgoing.sock.write_all(out.as_mut());
                            }
                        } else {
                            warn!("Outgoing interface not set for packet");
                        }
                    }
                }
            }
        }
    }

    /// Tries to receive a frame from the indicated interface and builds a `Packet`
    /// out of it. Returns a vector of [`Packet`]s. In this version, the kernel driver
    /// returns at most one packet per vector, unlike DPDK.
    pub fn packet_recv(interface: &mut Kif) -> Vec<Packet<TestBuffer>> {
        let mut raw = [0u8; 2048];
        match interface.sock.read(&mut raw) {
            Ok(bytes) => {
                /* build test buffer from raw data */
                let mut buf = TestBuffer::from_raw_data(&raw[0..bytes]);
                /* build Packet (parse) */
                match Packet::new(buf) {
                    Ok(incoming) => vec![incoming],
                    Err(e) => {
                        error!("Fail to parse packet: e");
                        vec![]
                    }
                }
            }
            Err(e) => {
                error!("Failed to receive from sock: e");
                vec![]
            }
        }
    }
}
