use alloc::rc::{Rc, Weak};
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::Hash;
use std::marker::PhantomData;
use std::net::Ipv6Addr;
use std::num::NonZero;
use std::sync::mpsc::Receiver;

use left_right::{Absorb, ReadHandle, WriteHandle};

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

trait CounterType {}

struct CounterMut(WriteHandle<i32, CounterOp>);

impl CounterType for CounterMut {}
impl CounterType for CounterRo {}

struct Counter<Type: CounterType> {
    inner: Type,
}

impl Counter<CounterMut> {
    pub fn add(&mut self, i: i32) {
        self.inner.0.append(CounterOp::Add(i));
    }

    pub fn sub(&mut self, i: i32) {
        self.inner.0.append(CounterOp::Subtract(i));
    }

    pub fn mul(&mut self, i: i32) {
        self.inner.0.append(CounterOp::Multiply(i));
    }

    pub fn div(&mut self, i: i32) {
        self.inner.0.append(CounterOp::Divide(i));
    }

    pub fn publish(&mut self) {
        self.inner.0.publish();
    }
}

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

trait Layer4Protocol: Copy + 'static {}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Tcp {}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Udp {}

impl Layer4Protocol for Tcp {}
impl Layer4Protocol for Udp {}

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
    interfaces: Vec<Rc<Interface>>,
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
#[derive(Debug, Clone, Copy)]
pub struct Port<L4Protocol>
where
    L4Protocol: Layer4Protocol + Copy,
{
    raw: NonZero<u16>,
    proto: PhantomData<&'static L4Protocol>,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Pool<Protocol>
where
    Protocol: Layer4Protocol,
{
    prefix: u8,
    free: VecDeque<u8>,
    proto: PhantomData<Protocol>,
}

impl<L4Protocol> Pool<L4Protocol>
where
    L4Protocol: Layer4Protocol,
{
    fn new(prefix: u8) -> Self {
        let start: u8 = if prefix == 0 { 1 } else { 0 };
        const END: u8 = 255;
        let free: VecDeque<_> = (start..=END).collect();
        Self {
            prefix,
            free,
            proto: PhantomData,
        }
    }

    pub(crate) fn take(&mut self) -> Option<Port<L4Protocol>> {
        match self.free.pop_front() {
            None => None,
            Some(next) => {
                let out = u16::from_ne_bytes([self.prefix, next]);
                match NonZero::new(out) {
                    None => {
                        unreachable!("prefix = 0 is special cased in ctor")
                    }
                    Some(raw) => Some(Port::<L4Protocol> {
                        raw,
                        proto: PhantomData,
                    }),
                }
            }
        }
    }

    fn free_sub(&mut self, entry: u8) -> Result<(), ()> {
        if self.free.contains(&entry) {
            return Err(());
        };
        self.free.push_back(entry);
        Ok(())
    }

    pub(crate) fn free(&mut self, entry: NonZero<u16>) -> Result<(), ()> {
        let bytes = entry.get().to_ne_bytes();
        if bytes[0] != self.prefix {
            return Err(());
        };
        self.free_sub(bytes[1])
    }
}

/// Sealed marker trait for ip address types
trait IpMarker: Copy {}
impl IpMarker for Ipv4Addr {}
impl IpMarker for Ipv6Addr {}

#[derive(Debug)]
struct ConnectionTracker<Ip: IpMarker> {
    mappings_tcp: HashMap<(Ip, Port<Tcp>), (Ip, Port<Tcp>)>,
    mappings_udp: HashMap<(Ip, Port<Udp>), (Ip, Port<Udp>)>,
}

#[derive(Debug, Clone)]
struct Interface {
    vpc: Weak<Vpc>,

    ipv4_cidrs: Vec<Cidr<Ipv4Addr>>,
    ipv6_cidrs: Vec<Cidr<Ipv6Addr>>,

    available_tcp4: BTreeMap<Ipv4Addr, Pool<Tcp>>,
    available_tcp6: BTreeMap<Ipv6Addr, Pool<Tcp>>,
    available_udp4: BTreeMap<Ipv4Addr, Pool<Udp>>,
    available_udp6: BTreeMap<Ipv6Addr, Pool<Udp>>,

    incoming_tcp4: Rc<Receiver<Pool<Tcp>>>,
    incoming_tcp6: Rc<Receiver<Pool<Tcp>>>,
    incoming_udp4: Rc<Receiver<Pool<Udp>>>,
    incoming_udp6: Rc<Receiver<Pool<Udp>>>,
}
