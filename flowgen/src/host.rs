// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A stand-in for the network stack of the host the generator runs on.
//!
//! On a real port, the generator owns the port and the host's kernel sees nothing, so nothing
//! answers the switch's ARP requests for the addresses the streams use, and nothing would come
//! back. A [`Host`] answers them, for each address on its VLAN, and announces the addresses when it
//! starts and now and then after, so the switch learns them before the first stream needs them.
//!
//! It also takes whatever else a switch sends a host -- LLDP, IPv6 neighbour discovery, spanning
//! tree -- and counts it by `EtherType`, so that a run does not mistake it for stray traffic; and
//! IPv4 not addressed to the port, such as the host's own DHCP broadcasts, which a NIC reflects back
//! to the port's queues. IPv4 for the port it leaves to the streams.

use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::Duration;

use flowgen_report::Sample;
use serde::{Deserialize, Serialize};

use crate::drive::Agent;
use crate::frame::{Mac, mac_text, tagged, untag};

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ARP_LEN: usize = 28;
const REQUEST: u16 = 1;
const REPLY: u16 = 2;
const BROADCAST: Mac = [0xff; 6];

/// One address the host answers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    /// The address.
    pub ip: Ipv4Addr,
    /// The 802.1Q VLAN it is on, if the port is tagged.
    #[serde(default)]
    pub vlan: Option<u16>,
}

/// What a [`Host`] answers for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The port's MAC: what the host answers with, and what streams should send from.
    #[serde(with = "mac_text")]
    pub mac: Mac,
    /// The addresses it answers for.
    pub addresses: Vec<Address>,
    /// How often to announce the addresses, by gratuitous ARP, after the first time; never again
    /// if `None`.
    #[serde(default)]
    pub announce_every: Option<Duration>,
}

/// What a [`Host`] has done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Counts {
    requests: u64,
    replies: u64,
    announcements: u64,
    /// ARP that was neither a request for one of the host's addresses nor anything it sent.
    other_arp: u64,
    /// Frames neither ARP nor IPv4, by `EtherType`.
    ignored: BTreeMap<u16, u64>,
    /// IPv4 frames for some other MAC, broadcast and multicast included.
    not_for_us: u64,
}

/// The host's own network stack, as far as the switch needs one.
#[derive(Debug)]
pub struct Host {
    name: String,
    wire: usize,
    config: Config,
    outbox: VecDeque<Vec<u8>>,
    /// When to announce next: at once, at first.
    announce_at: Option<u64>,
    counts: Counts,
}

impl Host {
    /// A host called `name` on wire `wire`, answering as `config` says.
    #[must_use]
    pub fn new(name: impl Into<String>, wire: usize, config: Config) -> Self {
        Self {
            name: name.into(),
            wire,
            config,
            outbox: VecDeque::new(),
            announce_at: Some(0),
            counts: Counts::default(),
        }
    }

    /// An ARP packet from this host, tagged for `address`'s VLAN.
    fn arp(&self, op: u16, address: Address, to_mac: Mac, to_ip: Ipv4Addr, dst: Mac) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + ARP_LEN);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&self.config.mac);
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&[6, 4]);
        frame.extend_from_slice(&op.to_be_bytes());
        frame.extend_from_slice(&self.config.mac);
        frame.extend_from_slice(&address.ip.octets());
        frame.extend_from_slice(&to_mac);
        frame.extend_from_slice(&to_ip.octets());
        tagged(frame, address.vlan)
    }

    /// Announce every address: a gratuitous ARP request for each, from and for itself.
    fn announce(&mut self) {
        for address in self.config.addresses.clone() {
            let frame = self.arp(REQUEST, address, [0; 6], address.ip, BROADCAST);
            self.outbox.push_back(frame);
            self.counts.announcements += 1;
        }
    }

    /// Answer an ARP packet `arp`, received on `vlan`, if it asks for one of the host's addresses.
    fn answer(&mut self, vlan: Option<u16>, arp: &[u8]) {
        let Some(arp) = arp.get(..ARP_LEN) else {
            self.counts.other_arp += 1;
            return;
        };
        let op = u16::from_be_bytes([arp[6], arp[7]]);
        let ip = |at: usize| Ipv4Addr::new(arp[at], arp[at + 1], arp[at + 2], arp[at + 3]);
        let (sender_ip, target_ip) = (ip(14), ip(24));
        let mut sender_mac = [0; 6];
        sender_mac.copy_from_slice(&arp[8..14]);
        let ours = self
            .config
            .addresses
            .iter()
            .copied()
            .find(|a| a.ip == target_ip && a.vlan == vlan);
        match (op, ours) {
            // A gratuitous request has the asker's own address as its target: not a question.
            (REQUEST, Some(address)) if sender_ip != target_ip => {
                self.counts.requests += 1;
                let reply = self.arp(REPLY, address, sender_mac, sender_ip, sender_mac);
                self.outbox.push_back(reply);
                self.counts.replies += 1;
            }
            _ => self.counts.other_arp += 1,
        }
    }
}

impl Agent for Host {
    fn wire(&self) -> usize {
        self.wire
    }

    fn transmit(&mut self, now_ns: u64) -> Option<Vec<u8>> {
        if let Some(at) = self.announce_at
            && now_ns >= at
        {
            self.announce();
            self.announce_at = self.config.announce_every.map(|every| {
                now_ns.saturating_add(u64::try_from(every.as_nanos()).unwrap_or(u64::MAX))
            });
        }
        self.outbox.pop_front()
    }

    fn receive(&mut self, frame: &[u8], _now_ns: u64) -> bool {
        let Some((vlan, ethertype, rest)) = untag(frame) else {
            return false;
        };
        match ethertype {
            ETHERTYPE_IPV4 if frame[..6] == self.config.mac => false,
            ETHERTYPE_IPV4 => {
                self.counts.not_for_us += 1;
                true
            }
            ETHERTYPE_ARP => {
                self.answer(vlan, rest);
                true
            }
            other => {
                *self.counts.ignored.entry(other).or_default() += 1;
                true
            }
        }
    }

    fn sample(&self, _now_ns: u64, sample: Sample) -> Sample {
        let path = |what: &str| format!("host.{}.{what}", self.name);
        let sample = [
            ("arp_requests", self.counts.requests),
            ("arp_replies", self.counts.replies),
            ("announcements", self.counts.announcements),
            ("other_arp", self.counts.other_arp),
            ("not_for_us", self.counts.not_for_us),
        ]
        .into_iter()
        .fold(sample, |sample, (what, n)| sample.counter(path(what), n));
        self.counts
            .ignored
            .iter()
            .fold(sample, |sample, (ethertype, n)| {
                sample.counter(path(&format!("ignored.{ethertype:#06x}")), *n)
            })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const MAC: Mac = [2, 0, 0, 0, 0, 5];
    const SWITCH: Mac = [2, 0, 0, 0, 0, 0xee];

    fn host() -> Host {
        Host::new(
            "server",
            0,
            Config {
                mac: MAC,
                addresses: vec![
                    Address {
                        ip: Ipv4Addr::new(10, 1, 0, 2),
                        vlan: Some(1001),
                    },
                    Address {
                        ip: Ipv4Addr::new(10, 2, 0, 2),
                        vlan: Some(1002),
                    },
                ],
                announce_every: None,
            },
        )
    }

    /// The switch asking, on `vlan`, who has `ip`.
    fn request(vlan: Option<u16>, ip: Ipv4Addr) -> Vec<u8> {
        let asking = Host::new(
            "switch",
            0,
            Config {
                mac: SWITCH,
                addresses: vec![],
                announce_every: None,
            },
        );
        asking.arp(
            REQUEST,
            Address {
                ip: Ipv4Addr::new(10, 1, 0, 1),
                vlan,
            },
            [0; 6],
            ip,
            BROADCAST,
        )
    }

    fn drain(host: &mut Host, now_ns: u64) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| host.transmit(now_ns)).collect()
    }

    #[test]
    fn it_announces_every_address_on_its_vlan_once() {
        let mut host = host();
        let sent = drain(&mut host, 0);
        assert_eq!(sent.len(), 2);
        for (frame, (vid, ip)) in sent
            .iter()
            .zip([(1001, [10, 1, 0, 2]), (1002, [10, 2, 0, 2])])
        {
            let (vlan, ethertype, arp) = untag(frame).unwrap();
            assert_eq!((vlan, ethertype), (Some(vid), ETHERTYPE_ARP));
            assert_eq!(&frame[..6], &BROADCAST);
            // From and for itself.
            assert_eq!(&arp[14..18], &ip);
            assert_eq!(&arp[24..28], &ip);
        }
        assert_eq!(drain(&mut host, 1_000_000_000_000), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn it_answers_for_its_addresses_on_their_own_vlans_only() {
        let mut host = host();
        drain(&mut host, 0);
        assert!(host.receive(&request(Some(1001), Ipv4Addr::new(10, 1, 0, 2)), 0));
        let replies = drain(&mut host, 0);
        assert_eq!(replies.len(), 1);
        let (vlan, ethertype, arp) = untag(&replies[0]).unwrap();
        assert_eq!((vlan, ethertype), (Some(1001), ETHERTYPE_ARP));
        assert_eq!(&replies[0][..6], &SWITCH);
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), REPLY);
        assert_eq!(&arp[8..14], &MAC);
        assert_eq!(&arp[14..18], &[10, 1, 0, 2]);

        // Right address, wrong VLAN; and someone else's address.
        assert!(host.receive(&request(Some(1002), Ipv4Addr::new(10, 1, 0, 2)), 0));
        assert!(host.receive(&request(Some(1001), Ipv4Addr::new(10, 1, 0, 9)), 0));
        assert_eq!(drain(&mut host, 0), Vec::<Vec<u8>>::new());
        let sample = host.sample(0, Sample::new());
        assert_eq!(sample.counters["host.server.arp_replies"], 1);
        assert_eq!(sample.counters["host.server.other_arp"], 2);
    }

    #[test]
    fn it_takes_link_noise_and_leaves_ipv4_to_the_streams() {
        let mut host = host();
        let mut lldp = vec![0u8; 60];
        lldp[12..14].copy_from_slice(&0x88ccu16.to_be_bytes());
        assert!(host.receive(&lldp, 0));
        let mut ipv4 = vec![0u8; 60];
        ipv4[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // Broadcast IPv4, such as the host's own DHCP discover reflected back: not the streams'.
        ipv4[..6].copy_from_slice(&BROADCAST);
        assert!(host.receive(&ipv4, 0));
        ipv4[..6].copy_from_slice(&MAC);
        assert!(!host.receive(&tagged(ipv4, Some(1001)), 0));
        let sample = host.sample(0, Sample::new());
        assert_eq!(sample.counters["host.server.ignored.0x88cc"], 1);
        assert_eq!(sample.counters["host.server.not_for_us"], 1);
    }

    #[test]
    fn it_announces_again_when_told_to() {
        let mut host = host();
        host.config.announce_every = Some(Duration::from_secs(1));
        assert_eq!(drain(&mut host, 0).len(), 2);
        assert_eq!(drain(&mut host, 500_000_000), Vec::<Vec<u8>>::new());
        assert_eq!(drain(&mut host, 1_000_000_000).len(), 2);
    }
}
