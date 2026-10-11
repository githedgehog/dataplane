// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a capture copies out of a packet.

use crate::names::CaptureNames;
use arrayvec::ArrayString;
use clock::{Duration, SystemTime};
use net::FlowKey;
use net::buffer::PacketBufferMut;
use net::headers::{Headers, TryHeaders};
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use std::fmt::{Display, Formatter};

/// Which way a packet was going when a [`CaptureRecord`] was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// After parsing, before any network function has touched the packet.
    Ingress,
    /// After the last network function, before the driver transmits, punts, or drops it.
    Egress,
}

impl Display for Direction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        })
    }
}

/// The name of the thread which took a [`CaptureRecord`].
///
/// Fixed capacity so that taking a record never allocates for it.
pub type ThreadLabel = ArrayString<32>;

/// A copy of everything a capture keeps from one packet.
///
/// This holds parsed headers rather than the packet buffer: buffers stay on the core that owns them,
/// and the headers are enough to rebuild the frame (minus its payload) on the capture writer's thread.
/// It deliberately omits [`PacketMeta::flow_info`], since a queued record must not keep a flow alive.
///
/// [`PacketMeta::flow_info`]: net::packet::PacketMeta::flow_info
#[derive(Debug, Clone)]
pub struct CaptureRecord {
    direction: Direction,
    timestamp: Duration,
    thread: Option<ThreadLabel>,
    headers: Headers,
    original_len: u32,
    iif: Option<InterfaceIndex>,
    oif: Option<InterfaceIndex>,
    src_vpcd: Option<VpcDiscriminant>,
    dst_vpcd: Option<VpcDiscriminant>,
    done: Option<DoneReason>,
    flow_key: Option<FlowKey>,
}

impl CaptureRecord {
    /// Copy what a capture needs out of `packet`.
    ///
    /// A `timestamp` before the Unix epoch is recorded as the epoch itself: pcapng cannot express it,
    /// and a wall clock that far off is a host problem the capture should not refuse packets over.
    #[must_use]
    pub fn new<Buf: PacketBufferMut>(
        direction: Direction,
        packet: &Packet<Buf>,
        timestamp: SystemTime,
        thread: Option<ThreadLabel>,
    ) -> Self {
        let meta = packet.meta();
        CaptureRecord {
            direction,
            timestamp: timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default(),
            thread,
            headers: packet.headers().clone(),
            original_len: u32::from(packet.total_len()),
            iif: meta.iif,
            oif: meta.oif,
            src_vpcd: meta.src_vpcd,
            dst_vpcd: meta.dst_vpcd,
            done: meta.done,
            flow_key: meta.flow_key.as_deref().copied(),
        }
    }

    /// Which way the packet was going.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// When the record was taken, as time since the Unix epoch.
    #[must_use]
    pub fn timestamp(&self) -> Duration {
        self.timestamp
    }

    /// The packet's headers as they were when captured.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The length of the whole frame (headers and payload) when captured.
    #[must_use]
    pub fn original_len(&self) -> u32 {
        self.original_len
    }

    /// The interface the record belongs to: the outgoing one at egress if known, else the incoming one.
    #[must_use]
    pub fn interface(&self) -> Option<InterfaceIndex> {
        match self.direction {
            Direction::Ingress => self.iif,
            Direction::Egress => self.oif.or(self.iif),
        }
    }

    /// The packet's metadata as `key=value` text, for a pcapng comment.
    ///
    /// Text rather than a binary option so that stock Wireshark can display and filter on it
    /// (`frame.comment contains "done=AclDropped"`).
    /// Every key is always present, with `-` for an absent value, so filters can rely on the key set.
    /// The flow key comes last and quoted because its own rendering contains spaces.
    #[must_use]
    pub fn annotation<'a>(&'a self, names: &'a CaptureNames) -> impl Display + 'a {
        Annotation {
            record: self,
            names,
        }
    }
}

struct Annotation<'a> {
    record: &'a CaptureRecord,
    names: &'a CaptureNames,
}

/// Renders an absent value as `-`.
struct OrDash<T>(Option<T>);

impl<T: Display> Display for OrDash<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(value) => value.fmt(f),
            None => f.write_str("-"),
        }
    }
}

impl Display for Annotation<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let Annotation { record, names } = self;
        let interface = |index: Option<InterfaceIndex>| OrDash(index.map(|i| names.interface(i)));
        write!(
            f,
            "direction={direction} thread={thread} done={done} iif={iif} oif={oif}",
            direction = record.direction,
            thread = OrDash(record.thread.as_ref()),
            done = OrDash(record.done.map(|done| format!("{done:?}"))),
            iif = interface(record.iif),
            oif = interface(record.oif),
        )?;
        for (side, vpcd) in [("src", record.src_vpcd), ("dst", record.dst_vpcd)] {
            let vni = vpcd.map(|vpcd| match vpcd {
                VpcDiscriminant::VNI(vni) => vni,
            });
            let vpc = vpcd.and_then(|vpcd| names.vpc(vpcd));
            write!(f, " {side}_vni={} {side}_vpc={}", OrDash(vni), OrDash(vpc))?;
        }
        match &record.flow_key {
            Some(key) => write!(f, " flow=\"{key}\""),
            None => f.write_str(" flow=-"),
        }
    }
}
