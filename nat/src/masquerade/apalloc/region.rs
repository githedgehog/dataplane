// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Decomposition of the public address space into disjoint regions.
//!
//! Several exposes may masquerade onto public ranges that overlap, and they may overlap partially:
//! `10.0.0.0/24` and `10.0.0.128/25` share half their addresses. Every public `(address, port)`
//! still has to be handed out at most once, because the reverse flow key that carries return
//! traffic back is built from the public address and port, the remote endpoint and the peer VPC,
//! and nothing in it identifies which VPC the traffic came from.
//!
//! Rather than give each expose an allocator over its own range, we cut the address space at every
//! point where the set of exposes covering it changes. That yields maximal intervals over which the
//! set of owners is constant, and no two of them overlap, so one allocator per interval is enough
//! to keep allocations unique. Each expose then allocates from the intervals its own range covers,
//! and only those.
//!
//! The decomposition is over addresses only. Public ranges can carry port ranges too, which the
//! pools do not model yet (see the two `FIXME`s about port ranges in `setup.rs`); when
//! they do, the same cutting has to happen over the port dimension.

use std::collections::{BTreeMap, BTreeSet};

/// An inclusive range of addresses, as raw bits, so that IPv4 and IPv6 can be cut the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AddrInterval {
    pub(crate) start: u128,
    pub(crate) end: u128,
}

impl AddrInterval {
    pub(crate) fn new(start: u128, end: u128) -> Self {
        debug_assert!(start <= end, "an interval cannot end before it starts");
        Self { start, end }
    }

    pub(crate) fn contains(&self, addr: u128) -> bool {
        self.start <= addr && addr <= self.end
    }

    /// Number of addresses covered, saturating at [`u128::MAX`] for the whole space.
    pub(crate) fn len(&self) -> u128 {
        (self.end - self.start).saturating_add(1)
    }
}

/// A stretch of public address space over which the set of exposes entitled to allocate does not
/// change. Owners are indices into the slice handed to [`decompose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Region {
    pub(crate) range: AddrInterval,
    pub(crate) owners: BTreeSet<usize>,
}

/// Cut the space covered by `owner_ranges` into maximal disjoint regions, each labelled with the
/// set of owners covering it. Owners are identified by their index in `owner_ranges`.
///
/// The result is ordered by address, covers exactly the union of the inputs, and contains no
/// overlapping regions. Every input range is exactly the union of some subset of the regions, which
/// is what lets an expose allocate from whole regions and never from an address outside its range.
pub(crate) fn decompose(owner_ranges: &[Vec<AddrInterval>]) -> Vec<Region> {
    // Coverage can only change at the start of a range, or just past the end of one. Cutting at
    // every such point gives elementary intervals that each range either covers entirely or does
    // not touch at all, so testing a single address per interval decides ownership.
    let mut cuts = BTreeSet::new();
    for ranges in owner_ranges {
        for range in ranges {
            cuts.insert(range.start);
            // A range ending at the top of the space has nothing past it to cut at.
            if let Some(past_end) = range.end.checked_add(1) {
                cuts.insert(past_end);
            }
        }
    }

    let cuts: Vec<u128> = cuts.into_iter().collect();
    let mut regions: Vec<Region> = Vec::new();
    for (index, &start) in cuts.iter().enumerate() {
        let end = match cuts.get(index + 1) {
            Some(&next_cut) => next_cut - 1,
            None => u128::MAX,
        };
        let owners: BTreeSet<usize> = owner_ranges
            .iter()
            .enumerate()
            .filter(|(_, ranges)| ranges.iter().any(|range| range.contains(start)))
            .map(|(owner, _)| owner)
            .collect();
        if owners.is_empty() {
            // A gap between ranges, or the tail past the last one.
            continue;
        }
        debug_assert!(
            owner_ranges.iter().enumerate().all(|(owner, ranges)| {
                owners.contains(&owner) == ranges.iter().any(|range| range.contains(end))
            }),
            "an elementary interval must be covered as a whole or not at all"
        );
        regions.push(Region {
            range: AddrInterval::new(start, end),
            owners,
        });
    }

    merge_adjacent(regions)
}

// Neighbouring elementary intervals with the same owners describe one region. This happens when an
// expose lists several adjacent prefixes, and keeps the number of allocators down.
fn merge_adjacent(regions: Vec<Region>) -> Vec<Region> {
    let mut merged: Vec<Region> = Vec::with_capacity(regions.len());
    for region in regions {
        match merged.last_mut() {
            Some(previous)
                if previous.range.end.checked_add(1) == Some(region.range.start)
                    && previous.owners == region.owners =>
            {
                previous.range.end = region.range.end;
            }
            _ => merged.push(region),
        }
    }
    merged
}

/// The regions each owner may allocate from, in the order they should be tried.
///
/// Regions an owner has to itself come first: allocating there cannot contend with another VPC, and
/// leaves the shared regions for the exposes that have nowhere else to go.
pub(crate) fn regions_by_owner(regions: &[Region]) -> BTreeMap<usize, Vec<usize>> {
    let mut by_owner: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, region) in regions.iter().enumerate() {
        for &owner in &region.owners {
            by_owner.entry(owner).or_default().push(index);
        }
    }
    for indices in by_owner.values_mut() {
        indices.sort_by_key(|&index| {
            // Fewest sharers first, then widest, then by address so the order is deterministic.
            (
                regions[index].owners.len(),
                std::cmp::Reverse(regions[index].range.len()),
                regions[index].range.start,
            )
        });
    }
    by_owner
}

#[cfg(test)]
mod bolero_tests {
    use super::*;
    use bolero::{Driver, TypeGenerator};

    // Ranges are drawn from a small window of the address space. Independently generated u128
    // ranges would essentially never overlap, and overlap is the whole point; a narrow window
    // makes it the common case, and makes it cheap enough to check every property against every
    // address in the window rather than against a sampled few.
    const WINDOW: u128 = 48;
    const MAX_OWNERS: u8 = 5;
    const MAX_RANGES_PER_OWNER: u8 = 3;
    const MAX_RANGE_LEN: u8 = 12;

    // Where the window sits. Includes both ends of the space, so the cut just past the end of a
    // range is exercised where it can overflow and where the first address has nothing below it.
    const BASES: [u128; 4] = [
        0,
        1,
        (u32::MAX as u128) - WINDOW + 1,
        u128::MAX - WINDOW + 1,
    ];

    /// A generated set of owner ranges: a window position, and per owner a list of ranges given as
    /// an offset into the window and a length.
    #[derive(Debug, Clone)]
    struct Scenario {
        base: u128,
        owners: Vec<Vec<(u8, u8)>>,
    }

    impl TypeGenerator for Scenario {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let base = BASES[usize::from(driver.produce::<u8>()? % 4)];
            let owner_count = usize::from(driver.produce::<u8>()? % MAX_OWNERS + 1);
            let mut owners = Vec::with_capacity(owner_count);
            for _ in 0..owner_count {
                let range_count = usize::from(driver.produce::<u8>()? % MAX_RANGES_PER_OWNER + 1);
                let mut ranges = Vec::with_capacity(range_count);
                for _ in 0..range_count {
                    let offset = driver.produce::<u8>()? % u8::try_from(WINDOW).ok()?;
                    let length = driver.produce::<u8>()? % MAX_RANGE_LEN + 1;
                    ranges.push((offset, length));
                }
                owners.push(ranges);
            }
            Some(Self { base, owners })
        }
    }

    impl Scenario {
        // Materialize the ranges, clipped to the window so that every address a region can cover
        // is one the oracle below walks.
        fn owner_ranges(&self) -> Vec<Vec<AddrInterval>> {
            self.owners
                .iter()
                .map(|ranges| {
                    ranges
                        .iter()
                        .map(|&(offset, length)| {
                            let start = u128::from(offset);
                            let end = (start + u128::from(length) - 1).min(WINDOW - 1);
                            AddrInterval::new(self.base + start, self.base + end)
                        })
                        .collect()
                })
                .collect()
        }

        fn addresses(&self) -> impl Iterator<Item = u128> + '_ {
            (0..WINDOW).map(move |offset| self.base + offset)
        }

        // The oracle: who covers this address, straight from the inputs.
        fn owners_covering(ranges: &[Vec<AddrInterval>], address: u128) -> BTreeSet<usize> {
            ranges
                .iter()
                .enumerate()
                .filter(|(_, ranges)| ranges.iter().any(|range| range.contains(address)))
                .map(|(owner, _)| owner)
                .collect()
        }
    }

    #[test]
    fn decompose_properties() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|scenario: Scenario| {
                let owner_ranges = scenario.owner_ranges();
                let regions = decompose(&owner_ranges);

                for region in &regions {
                    assert!(
                        region.range.start <= region.range.end,
                        "region {:?} ends before it starts",
                        region.range
                    );
                    assert!(
                        !region.owners.is_empty(),
                        "region {:?} has no owner, so nothing may allocate from it",
                        region.range
                    );
                    assert!(
                        region.owners.iter().all(|&o| o < owner_ranges.len()),
                        "region {:?} names an owner that does not exist",
                        region.range
                    );
                }

                // Regions are ordered and never overlap. Overlap is what would let two allocators
                // hand out the same address.
                for pair in regions.windows(2) {
                    assert!(
                        pair[0].range.end < pair[1].range.start,
                        "regions {:?} and {:?} overlap or are out of order",
                        pair[0].range,
                        pair[1].range
                    );
                }

                // The load-bearing property, checked at every address in the window: an address is
                // covered by exactly the owners that claimed it, no more and no fewer. "No more"
                // is what keeps an expose from being handed an address it never asked for; "no
                // fewer" is what keeps two exposes that both claimed it on one allocator.
                for address in scenario.addresses() {
                    let expected = Scenario::owners_covering(&owner_ranges, address);
                    match regions.iter().find(|region| region.range.contains(address)) {
                        Some(region) => assert_eq!(
                            region.owners, expected,
                            "address {address} is owned by {:?} but was claimed by {expected:?}",
                            region.owners
                        ),
                        None => assert!(
                            expected.is_empty(),
                            "address {address} was claimed by {expected:?} but is in no region"
                        ),
                    }
                }

                // Regions are maximal: neighbours that touch must differ in their owners, or they
                // should have been one region.
                for pair in regions.windows(2) {
                    if pair[0].range.end.checked_add(1) == Some(pair[1].range.start) {
                        assert_ne!(
                            pair[0].owners, pair[1].owners,
                            "adjacent regions {:?} and {:?} have the same owners",
                            pair[0].range, pair[1].range
                        );
                    }
                }

                // Building the pools twice for one config must give the same answer.
                assert_eq!(
                    decompose(&owner_ranges),
                    regions,
                    "decompose is not a function"
                );
            });
    }

    #[test]
    fn regions_by_owner_properties() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|scenario: Scenario| {
                let owner_ranges = scenario.owner_ranges();
                let regions = decompose(&owner_ranges);
                let by_owner = regions_by_owner(&regions);

                for (owner, _) in owner_ranges.iter().enumerate() {
                    let listed = by_owner.get(&owner).map_or(&[][..], Vec::as_slice);

                    // An owner is offered exactly the regions it owns: nothing it may not use, and
                    // nothing it may use left out.
                    let expected: BTreeSet<usize> = regions
                        .iter()
                        .enumerate()
                        .filter(|(_, region)| region.owners.contains(&owner))
                        .map(|(index, _)| index)
                        .collect();
                    assert_eq!(
                        listed.iter().copied().collect::<BTreeSet<_>>(),
                        expected,
                        "owner {owner} was offered the wrong regions"
                    );

                    // No region is offered twice, or the same space would be tried repeatedly.
                    assert_eq!(
                        listed.len(),
                        expected.len(),
                        "owner {owner} was offered a region more than once"
                    );

                    // Space the owner has to itself comes first.
                    for pair in listed.windows(2) {
                        assert!(
                            regions[pair[0]].owners.len() <= regions[pair[1]].owners.len(),
                            "owner {owner} is offered shared space before exclusive space"
                        );
                    }

                    // Every address the owner claimed is in one of the regions it was offered.
                    for address in scenario.addresses() {
                        if owner_ranges[owner]
                            .iter()
                            .any(|range| range.contains(address))
                        {
                            assert!(
                                listed
                                    .iter()
                                    .any(|&index| regions[index].range.contains(address)),
                                "owner {owner} claimed address {address} but was offered no region holding it"
                            );
                        }
                    }
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interval(start: u128, end: u128) -> AddrInterval {
        AddrInterval::new(start, end)
    }

    fn owners(indices: &[usize]) -> BTreeSet<usize> {
        indices.iter().copied().collect()
    }

    #[test]
    fn decompose_single_range_is_left_whole() {
        let regions = decompose(&[vec![interval(10, 20)]]);
        assert_eq!(
            regions,
            vec![Region {
                range: interval(10, 20),
                owners: owners(&[0])
            }]
        );
    }

    #[test]
    fn decompose_disjoint_ranges_stay_separate() {
        let regions = decompose(&[vec![interval(10, 20)], vec![interval(30, 40)]]);
        assert_eq!(
            regions,
            vec![
                Region {
                    range: interval(10, 20),
                    owners: owners(&[0])
                },
                Region {
                    range: interval(30, 40),
                    owners: owners(&[1])
                },
            ]
        );
    }

    #[test]
    fn decompose_identical_ranges_share_one_region() {
        let regions = decompose(&[vec![interval(10, 20)], vec![interval(10, 20)]]);
        assert_eq!(
            regions,
            vec![Region {
                range: interval(10, 20),
                owners: owners(&[0, 1])
            }]
        );
    }

    #[test]
    fn decompose_partial_overlap_splits_into_three() {
        // 0: [10, 20], 1: [15, 25] -> [10,14] {0}, [15,20] {0,1}, [21,25] {1}
        let regions = decompose(&[vec![interval(10, 20)], vec![interval(15, 25)]]);
        assert_eq!(
            regions,
            vec![
                Region {
                    range: interval(10, 14),
                    owners: owners(&[0])
                },
                Region {
                    range: interval(15, 20),
                    owners: owners(&[0, 1])
                },
                Region {
                    range: interval(21, 25),
                    owners: owners(&[1])
                },
            ]
        );
    }

    #[test]
    fn decompose_nested_range_splits_into_three() {
        // 1 sits strictly inside 0.
        let regions = decompose(&[vec![interval(10, 30)], vec![interval(15, 20)]]);
        assert_eq!(
            regions,
            vec![
                Region {
                    range: interval(10, 14),
                    owners: owners(&[0])
                },
                Region {
                    range: interval(15, 20),
                    owners: owners(&[0, 1])
                },
                Region {
                    range: interval(21, 30),
                    owners: owners(&[0])
                },
            ]
        );
    }

    #[test]
    fn decompose_three_way_overlap() {
        // A staircase: every combination of owners shows up.
        let regions = decompose(&[
            vec![interval(0, 30)],
            vec![interval(10, 40)],
            vec![interval(20, 50)],
        ]);
        assert_eq!(
            regions,
            vec![
                Region {
                    range: interval(0, 9),
                    owners: owners(&[0])
                },
                Region {
                    range: interval(10, 19),
                    owners: owners(&[0, 1])
                },
                Region {
                    range: interval(20, 30),
                    owners: owners(&[0, 1, 2])
                },
                Region {
                    range: interval(31, 40),
                    owners: owners(&[1, 2])
                },
                Region {
                    range: interval(41, 50),
                    owners: owners(&[2])
                },
            ]
        );
    }

    #[test]
    fn decompose_adjacent_ranges_of_one_owner_are_merged() {
        let regions = decompose(&[vec![interval(10, 19), interval(20, 29)]]);
        assert_eq!(
            regions,
            vec![Region {
                range: interval(10, 29),
                owners: owners(&[0])
            }]
        );
    }

    #[test]
    fn decompose_gap_between_ranges_is_not_covered() {
        let regions = decompose(&[vec![interval(10, 19), interval(30, 39)]]);
        assert_eq!(
            regions,
            vec![
                Region {
                    range: interval(10, 19),
                    owners: owners(&[0])
                },
                Region {
                    range: interval(30, 39),
                    owners: owners(&[0])
                },
            ]
        );
    }

    #[test]
    fn decompose_range_reaching_the_top_of_the_space() {
        let regions = decompose(&[vec![interval(u128::MAX - 1, u128::MAX)]]);
        assert_eq!(
            regions,
            vec![Region {
                range: interval(u128::MAX - 1, u128::MAX),
                owners: owners(&[0])
            }]
        );
    }

    #[test]
    fn decompose_empty_input() {
        assert_eq!(decompose(&[]), vec![]);
        assert_eq!(decompose(&[vec![]]), vec![]);
    }

    // The properties the allocator depends on: regions never overlap, and every owner's range is
    // covered exactly by the regions it owns.
    #[test]
    fn decompose_regions_are_disjoint_and_cover_each_owner_exactly() {
        let inputs = vec![
            vec![interval(0, 30), interval(60, 70)],
            vec![interval(10, 40)],
            vec![interval(20, 50), interval(65, 80)],
            vec![interval(100, 100)],
        ];
        let regions = decompose(&inputs);

        for pair in regions.windows(2) {
            assert!(
                pair[0].range.end < pair[1].range.start,
                "regions {:?} and {:?} overlap",
                pair[0].range,
                pair[1].range
            );
        }

        for (owner, ranges) in inputs.iter().enumerate() {
            for address in 0..=120u128 {
                let in_owner_range = ranges.iter().any(|range| range.contains(address));
                let in_owned_region = regions
                    .iter()
                    .any(|region| region.owners.contains(&owner) && region.range.contains(address));
                assert_eq!(
                    in_owner_range, in_owned_region,
                    "address {address} disagrees for owner {owner}"
                );
            }
        }
    }

    #[test]
    fn regions_by_owner_prefers_exclusive_regions() {
        // 0 owns [0,9] alone and shares [10,19] with 1.
        let regions = decompose(&[vec![interval(0, 19)], vec![interval(10, 19)]]);
        let by_owner = regions_by_owner(&regions);

        let for_zero = &by_owner[&0];
        assert_eq!(regions[for_zero[0]].range, interval(0, 9));
        assert_eq!(regions[for_zero[1]].range, interval(10, 19));

        // 1 only has the shared region.
        assert_eq!(by_owner[&1].len(), 1);
        assert_eq!(regions[by_owner[&1][0]].range, interval(10, 19));
    }
}
