// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A catalog of frames a gateway should refuse, or should take despite their looking odd, and what
//! it should do with each.
//!
//! Every [`Entry`] is a [`Mutation`] of an otherwise ordinary tunnelled frame, from a VTEP to the
//! gateway, carrying a packet from one VPC to another; and the [`Fate`] the frame should meet.
//! Where an RFC says what that is, the entry cites it.
//!
//! Not every fate is settled; an entry's [`Standing`] says. Some are undecided: the RFCs leave
//! the choice to the implementation, or the gateway's behaviour has not been decided on. Others are
//! known divergences: the gateway is known not to meet them yet. A run still sends both and records
//! what happened, without judging it -- except that a known divergence the gateway now meets is a
//! failure, so that the entry is settled rather than left to rot.
//!
//! The catalog speaks of the gateway's counters by the names its telemetry gives them, less the
//! prefix a run reads them under: a drop by the pipeline is `pipeline_packets.reason=<reason>`, a
//! frame the worker could not parse `worker_parse_errors`.

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::mutate::{Change, Layer, Mutation};

/// What becomes of a frame the gateway receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fate {
    /// Forwarded, as any other frame of its flow would be.
    Forwarded,
    /// Dropped, and counted as dropped: by `counted`, if it says.
    Dropped {
        /// The counter that counts it, if the entry says which.
        counted: Option<Counted>,
        /// Whether the gateway answers each frame it drops with an ICMP error to its source; if not,
        /// it drops it silently.
        answered: bool,
    },
}

/// Which of the gateway's counters counts a dropped frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Counted {
    /// The pipeline, finishing with the frame for this reason: `pipeline_packets.reason=<reason>`.
    Reason(&'static str),
    /// The worker, unable to parse the frame: `worker_parse_errors`.
    Unparsed,
}

/// What an entry expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Expect {
    /// What should become of the frame.
    pub fate: Fate,
    /// Whether that is settled.
    pub standing: Standing,
}

/// Whether an entry's fate is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// It is: a frame that meets another fails.
    Settled,
    /// It is not decided, for this reason.
    Undecided(&'static str),
    /// It is what should happen, and the gateway is known not to do it yet: this is what it does
    /// instead.
    Diverges(&'static str),
}

/// What an entry's frame carries before it is mutated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Base {
    /// A UDP datagram.
    Udp,
    /// A TCP segment opening a connection: SYN.
    TcpSyn,
}

/// A frame and what the gateway should do with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// A short name, unique in the catalog.
    pub id: &'static str,
    /// What is wrong, or odd, about the frame.
    pub summary: &'static str,
    /// What the frame carries before it is mutated.
    pub base: Base,
    /// How it is mutated.
    pub mutation: Mutation,
    /// What should become of it.
    pub expect: Expect,
}

const fn inner(change: Change) -> Mutation {
    Mutation {
        layer: Layer::Inner,
        change,
    }
}

const fn outer(change: Change) -> Mutation {
    Mutation {
        layer: Layer::Outer,
        change,
    }
}

const fn settled(fate: Fate) -> Expect {
    Expect {
        fate,
        standing: Standing::Settled,
    }
}

const FORWARDED: Expect = settled(Fate::Forwarded);

const DROPPED: Fate = Fate::Dropped {
    counted: None,
    answered: false,
};

const fn dropped_as(reason: &'static str) -> Fate {
    Fate::Dropped {
        counted: Some(Counted::Reason(reason)),
        answered: false,
    }
}

const UNPARSED: Fate = Fate::Dropped {
    counted: Some(Counted::Unparsed),
    answered: false,
};

const fn undecided(fate: Fate, why: &'static str) -> Expect {
    Expect {
        fate,
        standing: Standing::Undecided(why),
    }
}

const fn diverges(fate: Fate, instead: &'static str) -> Expect {
    Expect {
        fate,
        standing: Standing::Diverges(instead),
    }
}

const fn entry(
    id: &'static str,
    summary: &'static str,
    mutation: Mutation,
    expect: Expect,
) -> Entry {
    Entry {
        id,
        summary,
        base: Base::Udp,
        mutation,
        expect,
    }
}

const fn tcp_entry(
    id: &'static str,
    summary: &'static str,
    mutation: Mutation,
    expect: Expect,
) -> Entry {
    Entry {
        id,
        summary,
        base: Base::TcpSyn,
        mutation,
        expect,
    }
}

const MULTICAST_MAC: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05];
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
const STRANGER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x99, 0x99];

/// Every entry.
pub const CATALOG: &[Entry] = &[
    // The inner frame's Ethernet header.
    entry(
        "inner-source-mac-multicast",
        "the inner frame is from a group MAC address, which no station has",
        inner(Change::SourceMac { mac: MULTICAST_MAC }),
        settled(dropped_as("VxlanDecapFailure")),
    ),
    entry(
        "inner-source-mac-broadcast",
        "the inner frame is from the broadcast MAC address",
        inner(Change::SourceMac { mac: BROADCAST_MAC }),
        settled(dropped_as("VxlanDecapFailure")),
    ),
    entry(
        "inner-source-mac-zero",
        "the inner frame is from the all-zero MAC address",
        inner(Change::SourceMac { mac: [0; 6] }),
        undecided(
            DROPPED,
            "all-zero is a unicast address, if one no NIC is given; whether to take it is policy",
        ),
    ),
    entry(
        "inner-destination-mac-stranger",
        "the inner frame is for another station's MAC address",
        inner(Change::DestinationMac { mac: STRANGER_MAC }),
        settled(dropped_as("VxlanNotForUs")),
    ),
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.3.4
    //= type=test
    //# A router MUST NOT forward any packet that the router received as a
    //# Link Layer broadcast, unless it is directed to an IP Multicast
    //# address.
    entry(
        "inner-destination-mac-broadcast",
        "a unicast packet in a broadcast inner frame",
        inner(Change::DestinationMac { mac: BROADCAST_MAC }),
        settled(dropped_as("VxlanNotForUs")),
    ),
    entry(
        "inner-ethertype-unknown",
        "the inner frame carries an EtherType the gateway does not route",
        inner(Change::EtherType { ethertype: 0x88b5 }),
        settled(dropped_as("NotIp")),
    ),
    //= https://www.rfc-editor.org/rfc/rfc7348#section-6.1
    //= type=test
    //# Decapsulated VXLAN frames with the inner VLAN tag SHOULD be discarded unless configured
    //# otherwise.
    entry(
        "inner-vlan-tag",
        "the inner frame is 802.1Q tagged",
        inner(Change::VlanTag { vid: 7 }),
        settled(dropped_as("Unhandled")),
    ),
    entry(
        "inner-truncated",
        "the inner frame ends partway through its IPv4 header",
        inner(Change::Truncate { len: 24 }),
        settled(DROPPED),
    ),
    entry(
        "inner-padding",
        "the inner frame carries bytes after its packet, as Ethernet padding would be",
        inner(Change::Padding { bytes: 10 }),
        FORWARDED,
    ),
    // The inner packet's IPv4 header.
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.2.2
    //= type=test
    //# (3) The IP version number must be 4.
    entry(
        "inner-ip-version-6",
        "an IPv4 EtherType, and a version of 6",
        inner(Change::IpVersion { version: 6 }),
        settled(dropped_as("NotIp")),
    ),
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.2.2
    //= type=test
    //# (4) The IP header length field must be large enough to hold the
    //# minimum length legal IP datagram (20 bytes = 5 words).
    entry(
        "inner-header-length-short",
        "a header length of four words, less than the header",
        inner(Change::HeaderLength { words: 4 }),
        settled(dropped_as("NotIp")),
    ),
    entry(
        "inner-header-length-long",
        "a header length of fifteen words, the transport header and payload taken for options",
        inner(Change::HeaderLength { words: 15 }),
        undecided(
            DROPPED,
            "the header is long enough to be legal; its options are the transport header, and \
             none of them is well formed",
        ),
    ),
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.2.2
    //= type=test
    //# (5) The IP total length field must be large enough to hold the IP
    //# datagram header, whose length is specified in the IP header length
    //# field.
    entry(
        "inner-total-length-below-header",
        "a total length of ten bytes, less than the header",
        inner(Change::TotalLength { delta: -82 }),
        diverges(
            DROPPED,
            "forwarded, masqueraded, with the total length still ten",
        ),
    ),
    entry(
        "inner-total-length-past-frame",
        "a total length a hundred bytes longer than the frame holds",
        inner(Change::TotalLength { delta: 100 }),
        diverges(
            DROPPED,
            "forwarded, masqueraded, still claiming the hundred bytes it does not have",
        ),
    ),
    entry(
        "inner-total-length-short",
        "a total length ten bytes short, cutting into the UDP datagram",
        inner(Change::TotalLength { delta: -10 }),
        undecided(
            DROPPED,
            "the packet is legal and the rest of the frame padding; the UDP datagram in it is not",
        ),
    ),
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.2.2
    //= type=test
    //# (2) The IP checksum must be correct.
    entry(
        "inner-header-checksum",
        "a wrong IPv4 header checksum",
        inner(Change::IpChecksum),
        diverges(
            DROPPED,
            "the checksum is not checked: the packet is forwarded, and translating it makes the \
             checksum right",
        ),
    ),
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.3.1
    //= type=test
    //# If the TTL is reduced to zero (or less), the packet MUST be
    //# discarded, and if the destination is not a multicast address the
    //# router MUST send an ICMP Time Exceeded message, Code 0 (TTL Exceeded
    //# in Transit) message to the source.
    entry(
        "inner-ttl-zero",
        "a TTL of zero",
        inner(Change::Ttl { ttl: 0 }),
        settled(dropped_as("HopLimitExceeded")),
    ),
    entry(
        "inner-ttl-one",
        "a TTL of one, which forwarding would take to zero",
        inner(Change::Ttl { ttl: 1 }),
        settled(dropped_as("HopLimitExceeded")),
    ),
    entry(
        "inner-ttl-one-answered",
        "a TTL of one, answered with ICMP Time Exceeded",
        inner(Change::Ttl { ttl: 1 }),
        diverges(
            Fate::Dropped {
                counted: Some(Counted::Reason("HopLimitExceeded")),
                answered: true,
            },
            "dropped without an answer: no ICMP Time Exceeded is sent",
        ),
    ),
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.3.7
    //= type=test
    //# A router SHOULD NOT forward any packet that has an invalid IP source
    //# address or a source address on network 0.
    entry(
        "inner-source-multicast",
        "a multicast source address",
        inner(Change::SourceIp {
            addr: Ipv4Addr::new(224, 0, 0, 5),
        }),
        settled(dropped_as("NotIp")),
    ),
    entry(
        "inner-source-broadcast",
        "the limited broadcast address as the source",
        inner(Change::SourceIp {
            addr: Ipv4Addr::BROADCAST,
        }),
        settled(dropped_as("NotIp")),
    ),
    entry(
        "inner-source-this-network",
        "a source address on network 0",
        inner(Change::SourceIp {
            addr: Ipv4Addr::UNSPECIFIED,
        }),
        settled(dropped_as("Filtered")),
    ),
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.3.7
    //= type=test
    //# A router SHOULD NOT forward, except over a loopback interface, any
    //# packet that has a source address on network 127.
    entry(
        "inner-source-loopback",
        "a loopback source address",
        inner(Change::SourceIp {
            addr: Ipv4Addr::LOCALHOST,
        }),
        settled(dropped_as("Filtered")),
    ),
    entry(
        "inner-source-reserved",
        "a source address in the reserved class E range",
        inner(Change::SourceIp {
            addr: Ipv4Addr::new(240, 0, 0, 1),
        }),
        settled(dropped_as("Filtered")),
    ),
    //= https://www.rfc-editor.org/rfc/rfc1812#section-5.3.7
    //= type=test
    //# A router SHOULD NOT forward any packet that has an invalid IP
    //# destination address or a destination address on network 0.
    entry(
        "inner-destination-loopback",
        "a loopback destination address",
        inner(Change::DestinationIp {
            addr: Ipv4Addr::LOCALHOST,
        }),
        settled(dropped_as("Filtered")),
    ),
    entry(
        "inner-first-fragment",
        "the first fragment of a packet whose other fragments never come",
        inner(Change::Fragment {
            more: true,
            offset: 0,
        }),
        undecided(
            DROPPED,
            "how the gateway treats fragments through NAT is not decided",
        ),
    ),
    entry(
        "inner-last-fragment",
        "the last fragment of a packet, without the transport header the first would carry",
        inner(Change::Fragment {
            more: false,
            offset: 100,
        }),
        undecided(
            DROPPED,
            "how the gateway treats fragments through NAT is not decided",
        ),
    ),
    entry(
        "inner-options",
        "three words of No Operation options",
        inner(Change::IpOptions { words: 3 }),
        FORWARDED,
    ),
    entry(
        "inner-protocol-unknown",
        "an experimental protocol number, 253",
        inner(Change::Protocol { protocol: 253 }),
        undecided(
            DROPPED,
            "a router forwards any protocol; a NAT translates only those it knows",
        ),
    ),
    // The inner packet's transport header.
    entry(
        "inner-udp-checksum",
        "a wrong UDP checksum",
        inner(Change::L4Checksum),
        undecided(
            Fate::Forwarded,
            "a router does not check transport checksums; a NAT rewriting the datagram may",
        ),
    ),
    // RFC 768, which has no sections for duvet to cite: "An all zero transmitted checksum value
    // means that the transmitter generated no checksum".
    entry(
        "inner-udp-checksum-absent",
        "no UDP checksum, which IPv4 allows",
        inner(Change::UdpChecksumZero),
        FORWARDED,
    ),
    entry(
        "inner-udp-length-long",
        "a UDP length ten bytes longer than the packet holds",
        inner(Change::UdpLength { delta: 10 }),
        undecided(
            DROPPED,
            "the datagram is malformed, but no RFC tells a router to look; a NAT rewriting it may",
        ),
    ),
    entry(
        "inner-udp-length-short",
        "a UDP length fifty bytes short of the packet",
        inner(Change::UdpLength { delta: -50 }),
        undecided(
            DROPPED,
            "the datagram is legal and the rest of the packet surplus; whether to take it is policy",
        ),
    ),
    entry(
        "inner-udp-length-below-header",
        "a UDP length of zero, less than the UDP header",
        inner(Change::UdpLength { delta: -72 }),
        undecided(
            DROPPED,
            "the datagram is malformed, but no RFC tells a router to look; a NAT rewriting it may",
        ),
    ),
    entry(
        "inner-source-port-zero",
        "UDP source port zero: no port to reply to, which UDP allows",
        inner(Change::SourcePort { port: 0 }),
        undecided(
            Fate::Forwarded,
            "UDP allows it; a NAT mapping from port zero is policy",
        ),
    ),
    entry(
        "inner-destination-port-zero",
        "UDP destination port zero, which is reserved",
        inner(Change::DestinationPort { port: 0 }),
        undecided(DROPPED, "port zero is reserved; dropping it is policy"),
    ),
    tcp_entry(
        "inner-tcp-syn-fin",
        "a TCP segment both opening and closing a connection",
        inner(Change::TcpFlags { flags: 0x03 }),
        settled(dropped_as("Filtered")),
    ),
    tcp_entry(
        "inner-tcp-no-flags",
        "a TCP segment with no flags at all",
        inner(Change::TcpFlags { flags: 0 }),
        settled(dropped_as("Filtered")),
    ),
    tcp_entry(
        "inner-tcp-christmas",
        "a TCP segment with FIN, PSH and URG",
        inner(Change::TcpFlags { flags: 0x29 }),
        settled(dropped_as("Filtered")),
    ),
    tcp_entry(
        "inner-tcp-data-offset-short",
        "a TCP data offset of four words, less than the header",
        inner(Change::TcpDataOffset { words: 4 }),
        settled(dropped_as("Malformed")),
    ),
    tcp_entry(
        "inner-tcp-checksum",
        "a wrong TCP checksum",
        inner(Change::L4Checksum),
        undecided(
            Fate::Forwarded,
            "a router does not check transport checksums; a NAT rewriting the segment may",
        ),
    ),
    // The tunnel's Ethernet header.
    entry(
        "outer-source-mac-multicast",
        "the tunnel's frame is from a group MAC address",
        outer(Change::SourceMac { mac: MULTICAST_MAC }),
        settled(UNPARSED),
    ),
    entry(
        "outer-destination-mac-stranger",
        "the tunnel's frame is for another station's MAC address",
        outer(Change::DestinationMac { mac: STRANGER_MAC }),
        settled(dropped_as("MacNotForUs")),
    ),
    entry(
        "outer-vlan-tag",
        "the tunnel's frame is 802.1Q tagged, on a port with no VLANs",
        outer(Change::VlanTag { vid: 7 }),
        undecided(
            DROPPED,
            "decapsulated and forwarded as if untagged; the port has no VLAN configuration to say \
             otherwise",
        ),
    ),
    // The tunnel's IPv4 header: the gateway is the packet's destination.
    // RFC 1122 section 3.2.1.2.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-3
    //= type=test
    //# A host MUST verify the IP header checksum on every received
    //# datagram and silently discard every datagram that has a bad
    //# checksum.
    entry(
        "outer-header-checksum",
        "a wrong IPv4 header checksum on the tunnel",
        outer(Change::IpChecksum),
        diverges(
            DROPPED,
            "the checksum is not checked: the frame is decapsulated and what it carries forwarded",
        ),
    ),
    // RFC 1122 section 3.2.1.7.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-3
    //= type=test
    //# A host MUST NOT discard a datagram just because it was received with
    //# TTL less than 2.
    entry(
        "outer-ttl-zero",
        "a TTL of zero on a tunnel that ends at the gateway",
        outer(Change::Ttl { ttl: 0 }),
        FORWARDED,
    ),
    entry(
        "outer-header-length-short",
        "a header length of four words on the tunnel",
        outer(Change::HeaderLength { words: 4 }),
        diverges(
            DROPPED,
            "handed to the kernel, as if it were addressed to the gateway itself",
        ),
    ),
    // RFC 1122 section 3.2.1.3.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-3
    //= type=test
    //# A host MUST silently discard an incoming datagram containing an IP
    //# source address that is invalid by the rules of this section.
    entry(
        "outer-source-multicast",
        "a tunnel from a multicast source address",
        outer(Change::SourceIp {
            addr: Ipv4Addr::new(224, 0, 0, 5),
        }),
        diverges(
            DROPPED,
            "handed to the kernel, as if it were addressed to the gateway itself",
        ),
    ),
    entry(
        "outer-first-fragment",
        "the first fragment of a tunnelled packet whose other fragments never come",
        outer(Change::Fragment {
            more: true,
            offset: 0,
        }),
        undecided(
            DROPPED,
            "the gateway does not reassemble; a VTEP should not fragment",
        ),
    ),
    entry(
        "outer-options",
        "three words of No Operation options on the tunnel",
        outer(Change::IpOptions { words: 3 }),
        FORWARDED,
    ),
    // The tunnel's UDP and VXLAN headers.
    entry(
        "outer-udp-checksum",
        "a wrong, rather than absent, UDP checksum on the tunnel",
        outer(Change::L4Checksum),
        undecided(
            Fate::Forwarded,
            "RFC 7348 lets a VTEP verify a checksum it is sent, and drop the frame if it is \
             wrong, or not verify it",
        ),
    ),
    //= https://www.rfc-editor.org/rfc/rfc7348#section-5
    //= type=test
    //# I flag MUST be set to 1 for a valid
    //# VXLAN Network ID (VNI).
    entry(
        "vxlan-vni-not-valid",
        "the VXLAN I flag clear: no valid VNI",
        outer(Change::VxlanFlags { flags: 0 }),
        undecided(
            DROPPED,
            "handed to the kernel, which has no VXLAN socket; whether the gateway should drop it \
             itself is not decided",
        ),
    ),
    //= https://www.rfc-editor.org/rfc/rfc7348#section-5
    //= type=test
    //# The other 7 bits
    //# (designated "R") are reserved fields and MUST be set to zero on
    //# transmission and ignored on receipt.
    entry(
        "vxlan-reserved-set",
        "every reserved bit of the VXLAN header set",
        outer(Change::VxlanReserved),
        diverges(
            Fate::Forwarded,
            "handed to the kernel rather than decapsulated: the reserved bits are not ignored",
        ),
    ),
    entry(
        "vxlan-vni-unknown",
        "a VNI the gateway has no VPC for",
        outer(Change::Vni { vni: 999 }),
        settled(dropped_as("Unroutable")),
    ),
    entry(
        "vxlan-truncated",
        "the tunnel's frame ends partway through the VXLAN header",
        outer(Change::Truncate { len: 46 }),
        settled(DROPPED),
    ),
];

/// The entry named `id`.
#[must_use]
pub fn entry_named(id: &str) -> Option<&'static Entry> {
    CATALOG.iter().find(|entry| entry.id == id)
}
