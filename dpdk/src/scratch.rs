use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::marker::PhantomData;
use std::sync::{Arc, Weak};

/// A universally unique id
#[repr(transparent)]
struct Uuid(u128);

enum Tcp {}
enum Udp {}

trait L4Proto {
    type Port;
}

impl L4Proto for Tcp {
    type Port = TcpPort;
}
impl L4Proto for Udp {
    type Port = UdpPort;
}

/// Marker trait for layer 4 ports
trait L4Port {}

#[repr(transparent)]
struct Port<Proto: L4Proto> {
    pub val: u16,
    phantom: PhantomData<Proto>,
}

impl<Proto: L4Proto> Port<Proto> {
    fn new(val: u16) -> Self {
        Self {
            val,
            phantom: PhantomData,
        }
    }
}

impl<Proto: L4Proto> From<u16> for Port<Proto> {
    fn from(val: u16) -> Self {
        Self::new(val)
    }
}


/// A tcp port
#[repr(transparent)]
struct TcpPort(u16);

/// A udp port
#[repr(transparent)]
struct UdpPort(u16);

impl L4Port for TcpPort {}
impl L4Port for UdpPort {}

#[repr(transparent)]
struct SctpPort(u16);

#[repr(transparent)]
struct ThreadId(u32);

struct Peering {
    pub client: Arc<Interface>,
    pub server: Arc<Interface>,
}

struct Vpc {
    pub id: Uuid,
    pub name: String,
    pub interfaces: Vec<Interface>,
}

struct Cidr {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

#[repr(transparent)]
pub struct Chunk<P>(VecDeque<P>);

impl<P> Chunk<P> {
    fn pop(&mut self) -> Option<P> {
        self.0.pop_front()
    }
}

trait Merge {
    fn merge(&mut self, other: Self);
}

impl<P> Merge for Chunk<P> {
    fn merge(&mut self, other: Self) {
        self.0.extend(other.0);
    }
}

struct InterfaceWorker {
    interface: Weak<Interface>,
    used_tcp: HashMap<Ipv4Addr, Chunk<Tcp>>,
    used_udp: HashMap<Ipv4Addr, Chunk<Udp>>,
    available_tcp: BTreeMap<Ipv4Addr, Chunk<Tcp>>,
    available_udp: BTreeMap<Ipv4Addr, Chunk<Udp>>,
    nat: HashMap<(Ipv4Addr, u16), (Ipv4Addr, u16)>,
    incoming_tcp: std::sync::mpsc::Receiver<(Ipv4Addr, Chunk<Tcp>)>,
    incoming_udp: std::sync::mpsc::Receiver<(Ipv4Addr, Chunk<Udp>)>,
    outgoing_tcp: std::sync::mpsc::Sender<(Ipv4Addr, Chunk<Tcp>)>,
    outgoing_udp: std::sync::mpsc::Sender<(Ipv4Addr, Chunk<Udp>)>,
}

struct InterfaceWorkerAllocation {
    interface_worker: InterfaceWorker,
    outgoing_tcp: std::sync::mpsc::Sender<(Ipv4Addr, Chunk<Tcp>)>,
    outgoing_udp: std::sync::mpsc::Sender<(Ipv4Addr, Chunk<Udp>)>,
}

struct Interface {
    vpc: Weak<Vpc>,
    cidrs: Vec<Cidr>,
    workers: BTreeMap<ThreadId, InterfaceWorkerAllocation>,
    available_tcp: BTreeMap<Ipv4Addr, Chunk<Tcp>>,
    available_udp: BTreeMap<Ipv4Addr, Chunk<Udp>>,
    incoming_tcp: std::sync::mpsc::Receiver<Chunk<Tcp>>,
    incoming_udp: std::sync::mpsc::Receiver<Chunk<Udp>>,
    // ...
}
