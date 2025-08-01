// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::buffer::PacketBufferMut;
use net::packet::Packet;

pub trait Initialize {
    type Error;

    type Args<I: Iterator<Item: AsRef<str>>>: TryFrom<I, Error: Into<Self::Error>>;

    fn initialize<I>(args: Self::Args<I>) -> Result<Self, Self::Error>
    where
        I: Iterator<Item: AsRef<str>>,
        Self: Sized;
}

pub trait Receive {
    type Error<Buf: PacketBufferMut>;

    fn receive<Buf: PacketBufferMut>(
        &mut self,
    ) -> Result<impl Iterator<Item = Packet<Buf>>, Self::Error<Buf>>;
}

pub trait Transmit {
    type Error<Buf: PacketBufferMut>;

    fn transmit<Buf: PacketBufferMut>(
        &mut self,
        buf: impl IntoIterator<Item = Packet<Buf>>,
    ) -> Result<(), Self::Error<Buf>>;
}

pub trait Run: Receive + Transmit {
    fn run(&mut self)

}
