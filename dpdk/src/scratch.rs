use crate::flow::MacAddr;
use alloc::rc::Weak;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use crossbeam::utils::CachePadded;
use left_right::{Absorb, ReadHandle, WriteHandle};
use core::hash::Hash;
use core::marker::PhantomData;
use core::net::Ipv6Addr;
use core::num::NonZero;
use tracing::error;

use std::collections::{BinaryHeap, HashMap, VecDeque};


#[derive(Debug, Copy, Clone)]
enum CounterOp {
    Add(i32),
    Subtract(i32),
    Multiply(i32),
    Divide(i32),
}

impl Absorb<CounterOp> for i32 {
    fn absorb_first(&mut self, operation: &mut CounterOp, _other: &Self) {
        match *operation {
            CounterOp::Add(i) => {
                *self += i;
            }
            CounterOp::Subtract(i) => {
                *self -= i;
            }
            CounterOp::Multiply(i) => {
                *self *= i;
            }
            CounterOp::Divide(i) => {
                *self /= i;
            }
        }
    }

    fn sync_with(&mut self, first: &Self) {
        *self = *first;
    }
}

trait Transactional
where
    Self: Absorb<Self::Operation>,
{
    type Operation;
}

struct Wal<T: Transactional> {
    log: VecDeque<<T as Transactional>::Operation>,
    base: WriteHandle<T, <T as Transactional>::Operation>,
}

impl<T: Transactional> Wal<T> {
    fn apply(self) -> Self {
        let mut next = self;
        next.log.into_iter().for_each(|item| {
            next.base.append(item);
        });
        next.base.publish();
        Wal {
            base: next.base,
            log: VecDeque::new(),
        }
    }
}

#[repr(transparent)]
struct Reader<T: Transactional>(ReadHandle<T>);

#[repr(transparent)]
struct Writer<T: Transactional>(WriteHandle<T, <T as Transactional>::Operation>);

struct CounterMut(WriteHandle<i32, CounterOp>);

impl CounterMut {
    pub fn add(&mut self, i: i32) {
        self.0.append(CounterOp::Add(i));
    }

    pub fn sub(&mut self, i: i32) {
        self.0.append(CounterOp::Subtract(i));
    }

    pub fn mul(&mut self, i: i32) {
        self.0.append(CounterOp::Multiply(i));
    }

    pub fn div(&mut self, i: i32) {
        self.0.append(CounterOp::Divide(i));
    }

    pub fn publish(&mut self) {
        self.0.publish();
    }
}

impl core::ops::AddAssign<i32> for CounterMut {
    fn add_assign(&mut self, rhs: i32) {
        self.add(rhs)
    }
}

impl core::ops::SubAssign<i32> for CounterMut {
    fn sub_assign(&mut self, rhs: i32) {
        self.sub(rhs)
    }
}

impl core::ops::MulAssign<i32> for CounterMut {
    fn mul_assign(&mut self, rhs: i32) {
        self.mul(rhs)
    }
}

impl core::ops::DivAssign<i32> for CounterMut {
    fn div_assign(&mut self, rhs: i32) {
        self.div(rhs)
    }
}

#[derive(Clone)]
struct CounterRo(ReadHandle<i32>);

impl CounterRo {
    pub fn get(&self) -> i32 {
        self.0.enter().map(|guard| *guard).unwrap_or(0)
    }
}

#[test]
fn biscuit() {
    let (write, read) = left_right::new::<i32, CounterOp>();

    let (mut w, r) = (CounterMut(write), CounterRo(read));

    assert_eq!(r.get(), 0);

    w += 3;
    w *= 2;
    w -= 3;

    assert_eq!(r.get(), 0);
    w.publish();

    assert_eq!(r.get(), 3);
}

trait TransportProtocol: 'static + Copy + Ord + Hash {}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Tcp;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Udp;

impl TransportProtocol for Tcp {}
impl TransportProtocol for Udp {}

/// A universally unique id
#[repr(transparent)]
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Clone, Copy)]
struct Uuid(pub u128);

#[repr(transparent)]
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ThreadId(u32);

#[derive(Debug, Clone)]
struct Peering {
    pub client: Weak<Interface>,
    pub server: Weak<Interface>,
}

#[derive(Debug, Clone)]
struct Vpc {
    id: Uuid,
    version: u64,
    vrf: u32, // TODO: write a proper type for VRF
    vni: net::vxlan::Vni,
    interfaces: Vec<Interface>,
}

#[repr(transparent)]
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Clone, Copy)]
pub struct Prefix<Ip>(u8, PhantomData<Ip>)
where
    Ip: IpMarker;

impl<Ip> From<Prefix<Ip>> for u8
where
    Ip: IpMarker,
{
    fn from(p: Prefix<Ip>) -> u8 {
        p.0
    }
}

impl TryFrom<u8> for Prefix<Ipv4Addr> {
    type Error = PrefixError;

    fn try_from(value: u8) -> Result<Prefix<Ipv4Addr>, Self::Error> {
        Prefix::<Ipv4Addr>::new(value)
    }
}

impl TryFrom<u8> for Prefix<Ipv6Addr> {
    type Error = PrefixError;

    fn try_from(value: u8) -> Result<Prefix<Ipv6Addr>, Self::Error> {
        Prefix::<Ipv6Addr>::new(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PrefixError {
    #[error("prefix {0} is too long for ip address type")]
    TooLong(u8),
}

impl Prefix<Ipv4Addr> {
    fn new(prefix: u8) -> Result<Prefix<Ipv4Addr>, PrefixError> {
        if prefix > 32 {
            return Err(PrefixError::TooLong(prefix));
        }
        Ok(Prefix(prefix, PhantomData))
    }
}

impl Prefix<Ipv6Addr> {
    fn new(prefix: u8) -> Result<Prefix<Ipv6Addr>, PrefixError> {
        if prefix > 128 {
            return Err(PrefixError::TooLong(prefix));
        }
        Ok(Prefix(prefix, PhantomData))
    }
}

#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Clone, Copy)]
struct Cidr<Ip>
where
    Ip: IpMarker,
{
    pub ip: Ip,
    pub prefix: Prefix<Ip>,
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Port {
    raw: NonZero<u16>,
}

impl Port {
    fn from_raw(raw: NonZero<u16>) -> Self {
        Self { raw }
    }
}

/// Sealed marker trait for ip address types
trait IpMarker: Copy {}
impl IpMarker for Ipv4Addr {}
impl IpMarker for Ipv6Addr {}

#[derive(Debug)]
struct ConnectionTracker<Ip: IpMarker> {
    mappings_tcp: HashMap<(Ip, Port), (Ip, Port)>,
    mappings_udp: HashMap<(Ip, Port), (Ip, Port)>,
}

#[derive(Debug, Clone)]
struct Interface {
    vpc: Weak<Vpc>,

    ipv4_cidrs: Vec<Cidr<Ipv4Addr>>,
    ipv6_cidrs: Vec<Cidr<Ipv6Addr>>,
}

#[derive(Debug, Copy, Clone)]
struct TransportSliceManager<Protocol: TransportProtocol> {
    bitmap: CachePadded<[u128; 2]>, // 256 bits for the map
    dispatch: [u8; 256],
    proto: PhantomData<Protocol>,
}

#[repr(transparent)]
#[derive(Debug)]
struct TransportSlice {
    prefix: u8,
}

#[derive(Debug)]
struct SourceNat<Protocol: TransportProtocol> {
    prefix: TransportSlice,
    outside_ip: Ipv4Addr,
    bitmap: CachePadded<[u128; 2]>,

    egress_map: HashMap<
        /* (orig src ip, orig src port, orig dst port) */
        (Ipv4Addr, Port, Port),
        /* transformed src ip, transformed src port */
        (Ipv4Addr, Port),
    >,

    return_map: HashMap<
        /* returning src IP, returning dst port (transformed src port), returning src port (orig dst port) */
        (Ipv4Addr, Port, Port),
        /* orig src ip, returning dst port (orig src port) */
        (Ipv4Addr, Port),
    >,
    // egress_map: HashMap</* orig src port[1] */ u16, /* orig src ip */ Ipv4Addr>,
    // return_map: [(/* orig src ip */ Ipv4Addr, /* orig src port */ u16); 256],
    proto: PhantomData<Protocol>,
}

struct CTrackBlock {
    bitmap: [u128; 2], // bitmap of allocated source ports
    forward_map:
        BinaryHeap</* orig src ip, orig src port, mapped src port */ (Ipv4Addr, Port, Port)>,
    reverse_map: [Option<(
        /* orig src ip */
        Ipv4Addr,
        /* orig src port */
        Port,
    )>; 256], // transformed orig src port (returning dst port) is implicit as array index,
}

impl Default for CTrackBlock {
    fn default() -> Self {
        Self {
            bitmap: [0; 2],
            forward_map: BinaryHeap::with_capacity(256),
            reverse_map: [None; 256],
        }
    }
}

struct SourceNat2 {
    // inner_prefix: TransportSlice<Protocol>, // <- very unclear if I need this
    prefix: TransportSlice, // This is the slice of source ports we are allowed
    // to allocate from
    outside_ip: Ipv4Addr,
    // orig_dest_ip: Ipv4Addr, // <- ideally this wouldn't be here
    // bitmap: CachePadded<[u128; 2]>, // <- but you need orig_dest_ip to make this plan work
    //
    // bitmaps: HashMap<Ipv4Addr, CachePadded<[u128; 2]>>, // <- That might fix it but seems unfortunate
    contrack: HashMap<
        /* orig dest ip (returning src ip), orig dst port (returning src port) */
        (Ipv4Addr, Port),
        CTrackBlock,
    >,
    // // transformed orig src port (returning dst port) is implicit as array index
    // connections: [Vec<(
    //     /* orig dst ip (returning src ip) */
    //     Ipv4Addr,
    //     /* orig dst port ( returning src port) */
    //     Port<Protocol>,
    //     /* orig src ip */
    //     Ipv4Addr,
    //     /* orig src port */
    //     Port<Protocol>,
    // )>; 256],
    //
    // egress_map: HashMap<
    //     /* (orig src ip, orig src port, orig dst port) */
    //     (Ipv4Addr, Port<Protocol>, Port<Protocol>),
    //     /* transformed src ip, transformed src port */
    //     (Ipv4Addr, Port<Protocol>),
    // >,
    //
    // // return_map: HashMap<
    // //     /* returning src IP, returning dst port (transformed orig src port), returning src port (orig dst port) */
    // //     (Ipv4Addr, Port<Protocol>, Port<Protocol>),
    // //     /* orig src ip, returning dst port (orig src port) */
    // //     (Ipv4Addr, Port<Protocol>),
    // // >,
    //
    // // returning dst port (transformed orig src port) is implicit as array index
    // returning_map: [(hashbrown::HashMap<
    //     (
    //         /* returning src ip (orig dst ip) */
    //         Ipv4Addr,
    //         /* returning src port (orig dst port) */
    //         Port<Protocol>,
    //     ),
    //     (
    //         /* new dst ip (orig src ip) */
    //         Ipv4Addr,
    //         /* new dst port (orig src port) */
    //         Port<Protocol>,
    //     ),
    // >); 256],
    //
    // return_map: [(
    //     /* orig src port */ u8,
    //     /* orig src ip */ Vec<Ipv4Addr>,
    // ); 256],
    // egress_map: HashMap</* orig src port[1] */ u16, /* orig src ip */ Ipv4Addr>,
    // return_map: [(/* orig src ip */ Ipv4Addr, /* orig src port */ u16); 256],
    // proto: PhantomData<Protocol>,
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct TypedId<T> {
    raw: u64,
    marker: PhantomData<T>,
}

pub type Id<T> = TypedId<*const T>;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
struct Metadata {
    pub ingress: Id<Interface>,
    pub egress: Id<Interface>,
    pub verdict: Verdict,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
struct EthernetHeader {
    pub src: MacAddr,
    pub dst: MacAddr,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
struct TransportHeader {
    pub src: Port,
    pub dst: Port,
}

#[repr(u8)]
#[derive(Default, Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum PipelinePhase {
    #[default]
    Ingress = 0,
    Egress = 1,
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
struct Packet {
    pub metadata: Metadata,
    pub ethernet: EthernetHeader,
    pub network: Ipv4Header,
    pub transport: TransportHeader,
    payload: Vec<u8>,
    phase: PipelinePhase,
}

impl Packet {
    fn schedule(&mut self, verdict: Verdict) {
        self.metadata.verdict = verdict;
    }
}

// #[allow(clippy::expect_used)]
// fn nat_to_egress(
//     input: Packet,
//     nats: &mut HashMap<(Ipv4Addr, u8), SourceNat<Tcp>>,
// ) -> Result<Packet, ()> {
//     let src_port = input.transport.src.raw.get();
//     let [input_prefix, input_sub] = src_port.to_ne_bytes();
//     let block = nats
//         .get_mut(&(input.network.src, input_prefix))
//         .expect("Assumed to be in expected range for now");
//
//     let mut egress = input.clone();
//     let mapping =
//         block
//             .egress_map
//             .get(&(input.network.src, input.transport.src, input.transport.dst));
//     match mapping {
//         None => {
//             // create new mapping
//         }
//         Some(&(ip, src_port)) => {
//             egress.network.src = ip;
//             egress.transport.src = src_port;
//         }
//     }
// }

impl SourceNat2 {
    #[allow(clippy::expect_used)]
    fn inside_to_outside(&mut self, packet: Packet) -> Result<Packet, ()> {
        let block: &mut CTrackBlock = match self
            .contrack
            .get_mut(&(packet.network.dst, packet.transport.dst))
        {
            None => {
                let block: CTrackBlock = Default::default();
                self.contrack
                    .insert((packet.network.dst, packet.transport.dst), block)
                    .expect("incoherent HashMap access");
                self.contrack
                    .get_mut(&(packet.network.dst, packet.transport.dst))
                    .expect("incoherent HashMap access")
            }
            Some(block) => block,
        };

        let (new_src_port, _) = block
            .reverse_map
            .iter()
            .enumerate()
            .find_map(|(i, x)| match x {
                None => None,
                Some((orig_src_ip, orig_src_port)) => {
                    if (packet.network.src == *orig_src_ip)
                        && (packet.transport.src == *orig_src_port)
                    {
                        let new_src_port = ((self.prefix.prefix as u16) << 8) & i as u16;
                        Some((
                            Port::from_raw(NonZero::new(new_src_port).expect("todo")),
                            (*orig_src_ip, *orig_src_port),
                        ))
                    } else {
                        None
                    }
                }
            })
            .unwrap_or_else(|| {
                let first_unoccupied_index = block.bitmap[0].trailing_ones();
                if first_unoccupied_index == 128 {
                    // try second idx
                    let first_unoccupied_index = block.bitmap[1].trailing_ones();
                    if first_unoccupied_index == 128 {
                        todo!("TODO: no mappings available");
                    }
                    let idx = 128_u8 & first_unoccupied_index as u8;
                    let new_src_port = u16::from_be_bytes([self.prefix.prefix, idx]);
                    let new_mapping = (packet.network.src, packet.transport.src);
                    block.bitmap[1] &= 1 << first_unoccupied_index;
                    block.reverse_map[idx as usize] = Some(new_mapping);
                    let new_src_port = Port::from_raw(NonZero::new(new_src_port).expect("TODO"));
                    return (new_src_port, new_mapping);
                }
                let idx = first_unoccupied_index as u8;
                let new_src_port = Port::from_raw(
                    NonZero::new(u16::from_be_bytes([self.prefix.prefix, idx])).expect("TODO"),
                );
                let new_mapping = (packet.network.src, packet.transport.src);
                block.bitmap[0] &= 1 << first_unoccupied_index;
                block.reverse_map[idx as usize] = Some(new_mapping);

                block
                    .forward_map
                    .push((packet.network.src, packet.transport.src, new_src_port));
                (new_src_port, new_mapping)
            });

        let mut ret = packet.clone();
        ret.network.src = self.outside_ip;
        ret.transport.src = new_src_port;
        Ok(ret)
    }
}

#[repr(u8)]
#[derive(Default, Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum Verdict {
    #[default]
    Ingress,
    Transmit,
    Trap,
    Drop,
}

#[repr(transparent)]
#[derive(Debug)]
struct Batch {
    packets: Vec<Packet>,
}

trait PacketProcessor {
    fn process(&mut self, packet: Packet) -> Result<Packet, ()>;
}
