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

use crate::ranges::IpRange;
use lpm::prefix::PortRange;
use std::net::IpAddr;

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
