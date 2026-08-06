// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ports that port forwarding has claimed on public addresses, and that masquerade must not hand
//! out.
//!
//! A public `(address, port)` may only be live once towards a given peer, and port forwarding maps
//! its own statically, so masquerade allocating a pair port forwarding has taken would send return
//! traffic to whichever of the two the flow table happened to keep.
//!
//! One address can carry several claims. Port forwarding names a public range and a port range per
//! expose, and nothing stops two exposes naming the same address with different ports, so the
//! claims on an address are kept as a list and every one of them applies. Holding a single range
//! per address instead would silently honour whichever was recorded last.

use super::region::AddrInterval;
use crate::masquerade::natip::NatIp;
use crate::ranges::IpRange;
use lpm::prefix::PortRange;
use std::collections::BTreeSet;
use std::net::IpAddr;

/// Ports 0..=1023 cover the IANA system/well-known range and should not be
/// allocated by masquerade NAT for TCP or UDP.
pub(crate) const IANA_WELLKNOWN_PORT_LIMIT: u16 = 1024;

/// How many 256-port blocks an address is divided into.
const BLOCKS_PER_ADDRESS: u32 = 256;

/// Ports claimed on public addresses, as a flat list of claims.
///
/// Kept flat rather than keyed by address, because claims may be made on overlapping address
/// ranges and every claim covering an address has to be honoured, not just the innermost or the
/// last recorded.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReservedPorts {
    claims: Vec<(IpRange, PortRange)>,
}

impl ReservedPorts {
    pub(crate) fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    pub(crate) fn claim(&mut self, addresses: IpRange, ports: PortRange) {
        self.claims.push((addresses, ports));
    }

    /// Every port range claimed on `address`.
    pub(crate) fn for_address(&self, address: IpAddr) -> PortClaims {
        PortClaims(
            self.claims
                .iter()
                .filter(|(addresses, _)| addresses.contains(&address))
                .map(|(_, ports)| *ports)
                .collect(),
        )
    }

    /// The claims, for display.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (IpRange, PortRange)> + '_ {
        self.claims.iter().copied()
    }

    /// The stretches of `range` on which masquerade could never hand anything out, because port
    /// forwarding has claimed every port it is allowed to draw from.
    ///
    /// Walks the claims rather than the addresses: a region may hold billions of addresses, while
    /// there are only as many claims as there are port-forwarding exposes towards one peer.
    /// Coverage can only change where a claim begins or just past where one ends, so cutting at
    /// those points gives stretches over which the answer cannot change and a single address
    /// decides each of them. Adjacent stretches that agree are merged.
    ///
    /// `range` must be one every address of which converts to an offset, so callers pass the
    /// indexable part of a region rather than the whole of it.
    pub(crate) fn unusable_within<I: NatIp>(
        &self,
        range: AddrInterval,
        exclude_wellknown_ports: bool,
    ) -> Vec<AddrInterval> {
        // With nothing claimed there is nothing to find: the well-known range on its own never
        // uses an address up, since every block above it is still there to draw from.
        if self.claims.is_empty() {
            return Vec::new();
        }

        let mut cuts = BTreeSet::from([range.start]);
        for (addresses, _) in &self.claims {
            let Some((start, end)) = claim_bounds::<I>(addresses) else {
                // A claim of the other address family, which says nothing about this region.
                continue;
            };
            for cut in [Some(start), end.checked_add(1)].into_iter().flatten() {
                if cut > range.start && cut <= range.end {
                    cuts.insert(cut);
                }
            }
        }

        let cuts: Vec<u128> = cuts.into_iter().collect();
        let mut unusable: Vec<AddrInterval> = Vec::new();
        for (index, &start) in cuts.iter().enumerate() {
            let end = cuts.get(index + 1).map_or(range.end, |&next| next - 1);
            let Ok(address) = I::try_from_bits(start) else {
                continue;
            };
            if !self
                .for_address(address.to_ip_addr())
                .every_block_is_unusable(exclude_wellknown_ports)
            {
                continue;
            }
            match unusable.last_mut() {
                Some(previous) if previous.end.checked_add(1) == Some(start) => previous.end = end,
                _ => unusable.push(AddrInterval::new(start, end)),
            }
        }
        unusable
    }
}

// The bounds of a claim as raw bits, or None if the claim is of another address family.
fn claim_bounds<I: NatIp>(addresses: &IpRange) -> Option<(u128, u128)> {
    let start = I::try_from_addr(addresses.start()).ok()?;
    let end = I::try_from_addr(addresses.end()).ok()?;
    Some((start.to_addr_bits(), end.to_addr_bits()))
}

/// The port ranges claimed on one public address.
///
/// The ranges are independent and may overlap; nothing here merges them, because reserving a port
/// in a bitmap is idempotent and reserving the same port twice is harmless.
#[derive(Debug, Clone, Default)]
pub(crate) struct PortClaims(Vec<PortRange>);

impl PortClaims {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The claims, for display.
    pub(crate) fn iter(&self) -> impl Iterator<Item = PortRange> + '_ {
        self.0.iter().copied()
    }

    /// The claims that fall in the 256-port block starting at `base`, each clipped to it.
    ///
    /// Clipping here is what lets a claim span block boundaries: the bitmap of a block indexes
    /// ports modulo 256 and cannot represent a range reaching past its end.
    pub(crate) fn within_block(&self, base: u16) -> impl Iterator<Item = PortRange> + '_ {
        let block = block_range(base);
        self.0
            .iter()
            .filter_map(move |claim| claim.intersection(block))
    }

    /// Whether the block at `base` is one masquerade may never draw from, whether because policy
    /// keeps it off or because port forwarding has taken the whole of it.
    ///
    /// This is the decision the port allocator makes when it marks a block permanently non-free,
    /// and the one [`every_block_is_unusable`](Self::every_block_is_unusable) asks 256 times over.
    /// Both go through here so that the address-level answer cannot drift from the block-level one:
    /// an address dropped from a pool while a block of it was still allocatable would be capacity
    /// silently thrown away.
    pub(crate) fn block_is_unusable(&self, base: u16, exclude_wellknown_ports: bool) -> bool {
        (exclude_wellknown_ports && base < IANA_WELLKNOWN_PORT_LIMIT)
            || (!self.is_empty() && self.covers_block(base))
    }

    /// Whether no block of the address carrying these claims can be drawn from, so the address can
    /// serve masquerade nothing at all.
    pub(crate) fn every_block_is_unusable(&self, exclude_wellknown_ports: bool) -> bool {
        (0..BLOCKS_PER_ADDRESS)
            .map(|index| {
                u16::try_from(index * 256).unwrap_or_else(|_| unreachable!("256 blocks of 256"))
            })
            .all(|base| self.block_is_unusable(base, exclude_wellknown_ports))
    }

    /// Whether every port the block at `base` could hand out is claimed, so the block is of no use
    /// to masquerade at all.
    ///
    /// Port 0 is never handed out for TCP or UDP, so a claim over the whole of a block bar port 0
    /// still leaves nothing allocatable. Several claims may cover a block between them while no
    /// single one of them does, which is why this walks the union rather than testing each claim.
    pub(crate) fn covers_block(&self, base: u16) -> bool {
        let block = block_range(base);
        // Port 0 is never handed out for TCP or UDP, so the first block only has to be covered
        // from port 1 to be useless.
        let must_cover_from = if base == 0 { 1 } else { base };

        let mut claims: Vec<PortRange> = self.within_block(base).collect();
        claims.sort_by_key(PortRange::start);

        let mut covered_through: Option<u16> = None;
        for claim in claims {
            match covered_through {
                // The block has to be covered from its first allocatable port.
                None if claim.start() > must_cover_from => return false,
                None => covered_through = Some(claim.end()),
                // A claim starting more than one port past what is covered leaves a gap, and a
                // port left in a gap is one masquerade may still hand out.
                Some(end) if claim.start() > end.saturating_add(1) => return false,
                Some(end) => covered_through = Some(end.max(claim.end())),
            }
        }
        covered_through.is_some_and(|end| end >= block.end())
    }
}

impl FromIterator<PortRange> for PortClaims {
    fn from_iter<T: IntoIterator<Item = PortRange>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

fn block_range(base: u16) -> PortRange {
    // A block is 256 ports wide and based at a multiple of 256, so this cannot overflow.
    PortRange::new(base, base.saturating_add(255)).unwrap_or_else(|_| unreachable!())
}

#[cfg(test)]
mod bolero_tests {
    use super::*;
    use bolero::{Driver, TypeGenerator};
    use std::net::Ipv4Addr;

    // A narrow window, so that claims overlap one another as a matter of course and every address
    // in it can be checked rather than a sampled few.
    const BASE: u32 = 0x0A01_0000;
    const WINDOW: u32 = 12;
    const MAX_CLAIMS: u8 = 4;

    /// A generated set of claims: each an offset and a length into the window, and a port range
    /// that is either the whole of what masquerade could draw on or some slice of it.
    #[derive(Debug, Clone)]
    struct Scenario {
        claims: Vec<(u8, u8, u8, u16, u16)>,
    }

    impl TypeGenerator for Scenario {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let count = usize::from(driver.produce::<u8>()? % (MAX_CLAIMS + 1));
            let mut claims = Vec::with_capacity(count);
            for _ in 0..count {
                claims.push((
                    driver.produce::<u8>()?,
                    driver.produce::<u8>()?,
                    // Which shape of port range to draw. Left to chance, a range that happens to
                    // reach from 1024 to 65535, or to stop exactly on a block boundary, is
                    // vanishingly rare, and those are the shapes the answer turns on.
                    driver.produce::<u8>()?,
                    driver.produce::<u16>()?,
                    driver.produce::<u16>()?,
                ));
            }
            Some(Self { claims })
        }
    }

    impl Scenario {
        fn reserved(&self) -> ReservedPorts {
            let mut reserved = ReservedPorts::default();
            for &(offset, length, shape, port_lo, port_span) in &self.claims {
                // Claims may begin below the window and end past it, since a port-forwarded
                // prefix is under no obligation to sit inside the region being asked about. The
                // sweep cuts only within the range it is given, so both overhangs have to clip
                // correctly: an oracle mismatch at the window's first or last address is what a
                // mistake here would look like.
                let start = (BASE - WINDOW / 2) + u32::from(offset) % (WINDOW + WINDOW / 2);
                let end = start + u32::from(length) % WINDOW;
                let ports = match shape % 3 {
                    // The whole of what masquerade could draw on, which uses the address up by
                    // itself.
                    0 => PortRange::new(IANA_WELLKNOWN_PORT_LIMIT, u16::MAX),
                    // Up to the end of some block: the shape that decides whether the block a
                    // claim stops on is judged the same way by the address-level answer and the
                    // block-level one.
                    1 => {
                        let blocks = 1 + u32::from(port_lo) % 255;
                        let end = (u32::from(IANA_WELLKNOWN_PORT_LIMIT) + blocks * 256 - 1)
                            .min(u32::from(u16::MAX));
                        PortRange::new(
                            IANA_WELLKNOWN_PORT_LIMIT,
                            u16::try_from(end).unwrap_or_else(|_| unreachable!()),
                        )
                    }
                    // Anywhere at all.
                    _ => {
                        let low = port_lo.max(1);
                        PortRange::new(low, low.saturating_add(port_span))
                    }
                }
                .unwrap_or_else(|_| unreachable!());
                reserved.claim(
                    IpRange::new(
                        IpAddr::V4(Ipv4Addr::from(start)),
                        IpAddr::V4(Ipv4Addr::from(end)),
                    ),
                    ports,
                );
            }
            reserved
        }
    }

    #[test]
    fn unusable_within_matches_a_per_address_oracle() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|scenario: Scenario| {
                let reserved = scenario.reserved();
                let range = AddrInterval::new(u128::from(BASE), u128::from(BASE + WINDOW - 1));
                let unusable = reserved.unusable_within::<Ipv4Addr>(range, true);

                for interval in &unusable {
                    assert!(
                        interval.start <= interval.end,
                        "interval {interval:?} ends before it starts"
                    );
                    assert!(
                        interval.start >= range.start && interval.end <= range.end,
                        "interval {interval:?} reaches outside the range it was asked about"
                    );
                }

                // Ordered, and never touching: two that met should have been reported as one.
                for pair in unusable.windows(2) {
                    assert!(
                        pair[0].end.saturating_add(1) < pair[1].start,
                        "intervals {:?} and {:?} touch, overlap, or are out of order",
                        pair[0],
                        pair[1]
                    );
                }

                // The load-bearing property, at every address in the window. An address is kept out
                // of the pool exactly when no block of it could ever be drawn from: keeping out one
                // that still had a block is capacity silently thrown away, and leaving in one that
                // had none is the walk this exists to avoid.
                for bits in range.start..=range.end {
                    let address =
                        Ipv4Addr::from(u32::try_from(bits).unwrap_or_else(|_| unreachable!()));
                    let has_nothing_to_give =
                        covers_every_usable_port(&reserved.for_address(IpAddr::V4(address)));
                    let kept_out = unusable.iter().any(|interval| interval.contains(bits));
                    assert_eq!(
                        kept_out, has_nothing_to_give,
                        "address {address}: kept out of the pool = {kept_out}, but every block \
                         unusable = {has_nothing_to_give}"
                    );
                }
            });
    }

    /// The oracle: an address can serve nothing when the claims on it cover every port masquerade
    /// could hand out, end to end.
    ///
    /// Worked out over the port space directly, rather than by asking whether each of the 256
    /// blocks is covered. That is the whole value of it: the implementation deliberately routes the
    /// address-level answer and the block-level one through a single predicate so they cannot
    /// drift, and a test that reused that predicate would be comparing it with itself.
    fn covers_every_usable_port(claims: &PortClaims) -> bool {
        let mut ranges: Vec<PortRange> = claims.iter().collect();
        ranges.sort_by_key(PortRange::start);

        // Everything below the well-known limit is off the table anyway, so coverage starts there.
        let mut covered_through = IANA_WELLKNOWN_PORT_LIMIT - 1;
        for range in ranges {
            if range.start() > covered_through.saturating_add(1) {
                return false;
            }
            covered_through = covered_through.max(range.end());
        }
        covered_through == u16::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(start: u16, end: u16) -> PortRange {
        PortRange::new(start, end).unwrap_or_else(|_| unreachable!())
    }

    fn claims(ranges: &[(u16, u16)]) -> PortClaims {
        ranges.iter().map(|&(s, e)| ports(s, e)).collect()
    }

    #[test]
    fn no_claims_cover_nothing() {
        assert!(!PortClaims::default().covers_block(1024));
        assert!(PortClaims::default().is_empty());
    }

    #[test]
    fn a_claim_over_the_whole_block_covers_it() {
        assert!(claims(&[(1024, 1279)]).covers_block(1024));
    }

    #[test]
    fn a_claim_over_part_of_the_block_does_not() {
        assert!(!claims(&[(1024, 1200)]).covers_block(1024));
        assert!(!claims(&[(1100, 1279)]).covers_block(1024));
    }

    // The case a per-claim test gets wrong: neither claim covers the block, but together they do.
    #[test]
    fn two_claims_covering_between_them_cover_the_block() {
        assert!(claims(&[(1024, 1150), (1151, 1279)]).covers_block(1024));
        assert!(claims(&[(1024, 1150), (1150, 1279)]).covers_block(1024));
    }

    #[test]
    fn two_claims_leaving_a_gap_do_not_cover_the_block() {
        assert!(!claims(&[(1024, 1150), (1152, 1279)]).covers_block(1024));
    }

    // Port 0 is never allocatable, so covering 1..=255 leaves the first block useless.
    #[test]
    fn the_first_block_is_covered_without_port_zero() {
        assert!(claims(&[(1, 255)]).covers_block(0));
        assert!(claims(&[(0, 255)]).covers_block(0));
        assert!(!claims(&[(1, 254)]).covers_block(0));
    }

    #[test]
    fn claims_are_clipped_to_the_block() {
        // A claim spanning two blocks reaches each of them, clipped.
        let spanning = claims(&[(1000, 1300)]);
        let in_first: Vec<_> = spanning.within_block(1024).collect();
        assert_eq!(in_first, vec![ports(1024, 1279)]);
        let in_second: Vec<_> = spanning.within_block(1280).collect();
        assert_eq!(in_second, vec![ports(1280, 1300)]);
        // And not blocks it does not touch.
        assert_eq!(spanning.within_block(2048).count(), 0);
    }

    #[test]
    fn claims_outside_the_block_are_ignored() {
        assert!(!claims(&[(2048, 2303)]).covers_block(1024));
    }
}
