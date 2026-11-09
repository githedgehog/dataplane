// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! SYN cookies: the initial sequence numbers the proxy picks when it answers a SYN.
//!
//! A cookie lets the proxy recognize, without keeping state, the client's ACK that completes the
//! handshake: the ACK acknowledges the cookie, and the proxy can compute the cookie again from the
//! ACK. A cookie holds:
//!
//! - in its 2 low bits, the index of the client's MSS in a table of common values;
//! - in the next bit, the parity of the time slot in which the proxy made it;
//! - in the 29 high bits, a keyed hash of the flow key of the client's packets, the client's
//!   initial sequence number, the time slot and the MSS index.
//!
//! A cookie is valid during the slot in which the proxy made it and the next one, so between
//! [`SLOT`] and twice [`SLOT`]. The hash covers the VPC of the client, as VPCs can use overlapping
//! addresses: a cookie made for one VPC never validates for another.

use clock::Instant;
use net::FlowKey;
use net::tcp::TcpMss;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::time::Duration;

/// The duration of a time slot for cookies.
pub const SLOT: Duration = Duration::from_secs(64);

const MSS_BITS: u32 = 2;
const MSS_MASK: u32 = (1 << MSS_BITS) - 1;
const SLOT_BIT: u32 = 1 << MSS_BITS;
const HASH_MASK: u32 = !(MSS_MASK | SLOT_BIT);

// Common MSS values, from Linux: Ethernet with and without TCP timestamps or tunnels, and some
// smaller links. A cookie records the largest one that does not exceed the client's MSS.
const MSS_TABLE_V4: [u16; 4] = [536, 1300, 1440, 1460];
const MSS_TABLE_V6: [u16; 4] = [1220, 1420, 1440, 8940];

// The values of the tables are valid MSS values
fn mss_from_table(table: [u16; 4], index: usize) -> TcpMss {
    TcpMss::new(table[index]).unwrap_or_else(|e| unreachable!("{e:?}"))
}

// The MSS table for the IP version of a flow.
fn mss_table(conn: &FlowKey) -> [u16; 4] {
    match conn.src_ip() {
        IpAddr::V4(_) => MSS_TABLE_V4,
        IpAddr::V6(_) => MSS_TABLE_V6,
    }
}

/// The secret from which the proxy makes its cookies.
#[derive(Debug)]
pub struct CookieKey {
    // SipHash keys, random for each key
    hasher: RandomState,
    epoch: Instant,
}

impl CookieKey {
    /// Make a new key, with a random secret.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: RandomState::new(),
            epoch: clock::now(),
        }
    }

    fn slot(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs() / SLOT.as_secs()
    }

    fn hash(&self, conn: &FlowKey, client_isn: u32, slot: u64, mss_index: u32) -> u32 {
        let hash = self.hasher.hash_one((conn, client_isn, slot, mss_index));
        #[allow(clippy::cast_possible_truncation)] // fold the 64 bits into 32
        let folded = (hash ^ (hash >> 32)) as u32;
        folded
    }

    fn cookie(&self, conn: &FlowKey, client_isn: u32, slot: u64, mss_index: u32) -> u32 {
        let slot_bit = if slot.is_multiple_of(2) { 0 } else { SLOT_BIT };
        self.hash(conn, client_isn, slot, mss_index) & HASH_MASK | slot_bit | mss_index
    }

    /// Make the cookie for a SYN of `conn` with initial sequence number `client_isn`, and with
    /// MSS `mss`, if the SYN has one. Return the cookie and the MSS it records.
    #[must_use]
    pub fn make(
        &self,
        conn: &FlowKey,
        client_isn: u32,
        mss: Option<TcpMss>,
        now: Instant,
    ) -> (u32, TcpMss) {
        let mss = mss.map_or(0, TcpMss::get);
        let table = mss_table(conn);
        let index = table.iter().rposition(|&value| value <= mss).unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)] // index into a table of 4 entries
        let cookie = self.cookie(conn, client_isn, self.slot(now), index as u32);
        (cookie, mss_from_table(table, index))
    }

    /// Check that `cookie` is a valid cookie for a SYN of `conn` with initial sequence number
    /// `client_isn`, and return the MSS it recorded if so.
    #[must_use]
    pub fn check(
        &self,
        conn: &FlowKey,
        client_isn: u32,
        cookie: u32,
        now: Instant,
    ) -> Option<TcpMss> {
        let mss_index = cookie & MSS_MASK;
        let now = self.slot(now);
        // The slot bit tells whether the cookie comes from this slot or from the previous one
        let slot = if (now % 2 == 1) == (cookie & SLOT_BIT != 0) {
            now
        } else {
            now.checked_sub(1)?
        };
        if self.cookie(conn, client_isn, slot, mss_index) != cookie {
            return None;
        }
        Some(mss_from_table(mss_table(conn), mss_index as usize))
    }
}

impl Default for CookieKey {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::{CookieKey, SLOT};
    use net::flow_key::FlowAddrs;
    use net::ip::UnicastIpAddr;
    use net::packet::VpcDiscriminant;
    use net::tcp::{TcpMss, TcpPort};
    use net::vxlan::Vni;
    use net::{FlowKey, IpProtoKey, TcpProtoKey};

    fn conn(client: &str, vni: u32) -> FlowKey {
        let client: UnicastIpAddr = client.parse().unwrap();
        let server: UnicastIpAddr = match client {
            UnicastIpAddr::V4(_) => "10.0.0.2".parse().unwrap(),
            UnicastIpAddr::V6(_) => "2001:db8::2".parse().unwrap(),
        };
        FlowKey::new(
            Some(VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap())),
            FlowAddrs::new(client, server).unwrap(),
            IpProtoKey::Tcp(TcpProtoKey {
                src_port: TcpPort::new_checked(1234).unwrap(),
                dst_port: TcpPort::new_checked(80).unwrap(),
            }),
        )
    }

    // A cookie validates for the connection it was made for, during its lifetime, and gives back
    // an MSS no larger than the client's (or the smallest of the table).
    #[test]
    fn cookie_round_trip() {
        let key = CookieKey::new();
        let conn = conn("10.0.0.1", 100);
        bolero::check!()
            .with_type()
            .for_each(|(isn, mss, age): &(u32, Option<TcpMss>, u8)| {
                let made = key.epoch + SLOT * 3 + SLOT / 2;
                let (cookie, recorded) = key.make(&conn, *isn, *mss, made);
                let checked = made + SLOT / 2 * u32::from(*age % 3);
                let recovered = key.check(&conn, *isn, cookie, checked).unwrap();
                assert_eq!(recovered, recorded);
                if let Some(mss) = mss
                    && mss.get() >= 536
                {
                    assert!(recovered <= *mss);
                } else {
                    assert_eq!(recovered.get(), 536);
                }
            });
    }

    #[test]
    fn cookie_mss_table() {
        let key = CookieKey::new();
        let now = key.epoch;
        for (client, mss, expected) in [
            ("10.0.0.1", Some(1460), 1460),
            ("10.0.0.1", Some(1459), 1440),
            ("10.0.0.1", Some(9000), 1460),
            ("10.0.0.1", None, 536),
            ("2001:db8::1", Some(1440), 1440),
            ("2001:db8::1", Some(8960), 8940),
            ("2001:db8::1", None, 1220),
        ] {
            let conn = conn(client, 100);
            let mss = mss.map(|mss| TcpMss::new(mss).unwrap());
            let (cookie, _) = key.make(&conn, 7, mss, now);
            assert_eq!(key.check(&conn, 7, cookie, now).unwrap().get(), expected);
        }
    }

    #[test]
    fn cookie_expires() {
        let key = CookieKey::new();
        let conn = conn("10.0.0.1", 100);
        let made = key.epoch + SLOT * 5 + SLOT / 2;
        let (cookie, _) = key.make(&conn, 7, None, made);
        assert!(key.check(&conn, 7, cookie, made + SLOT).is_some());
        assert!(key.check(&conn, 7, cookie, made + SLOT * 2).is_none());
        assert!(key.check(&conn, 7, cookie, made + SLOT * 3).is_none());
    }

    // A cookie does not validate for another connection, another VPC, another initial sequence
    // number, or another key.
    #[test]
    fn cookie_is_specific() {
        let key = CookieKey::new();
        let now = key.epoch;
        let conn = conn("10.0.0.1", 100);
        let (cookie, _) = key.make(&conn, 7, None, now);
        assert!(key.check(&conn, 7, cookie, now).is_some());
        assert!(key.check(&conn, 8, cookie, now).is_none());
        assert!(
            key.check(&self::conn("10.0.0.3", 100), 7, cookie, now)
                .is_none()
        );
        assert!(
            key.check(&self::conn("10.0.0.1", 200), 7, cookie, now)
                .is_none()
        );
        assert!(key.check(&conn, 7, cookie ^ 0x100, now).is_none());
        assert!(CookieKey::new().check(&conn, 7, cookie, now).is_none());
    }
}
