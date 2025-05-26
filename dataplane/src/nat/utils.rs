// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use routing::prefix::Prefix;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum InvalidNatPort {
    #[error("reserved port ({0})")]
    ReservedPort(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatPort(u16);

impl NatPort {
    pub const MIN: u16 = 1024 + 1;

    /// Create a new [`NatPort`] from a `u16`.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidNatPort`] error if the value is strictly lower than [`NatPort::MIN`].
    pub fn new_checked(port: u16) -> Result<NatPort, InvalidNatPort> {
        if port < Self::MIN {
            return Err(InvalidNatPort::ReservedPort(port));
        }
        Ok(Self(port))
    }

    /// Get the value of the [`NatPort`] as a `u16`.
    #[must_use]
    pub fn as_u16(self) -> u16 {
        self.0
    }
}

// ------------------------------------------------------------------------------------------------

pub fn collapse_prefix_lists(
    prefixes: &BTreeSet<Prefix>,
    excludes: &BTreeSet<Prefix>,
) -> BTreeSet<Prefix> {
    let mut result = prefixes.clone();
    // Sort the exclusion prefixes by length in ascending order (meaning a /16 is _smaller_ than a
    // /24, and comes first). If there are some exclusion prefixes with overlap, this ensures that
    // we take out the biggest chunk from the allowed prefix first (and don't need to process the
    // smaller exclusion prefix at all).
    let mut excludes_sorted = excludes.iter().collect::<Vec<_>>();
    excludes_sorted.sort_by_key(|p| p.length());

    // Iterate over all exclusion prefixes
    for exclude in &excludes_sorted {
        let result_clone = result.clone();
        for prefix in &result_clone {
            // If exclusion prefix is bigger or equal to the allowed prefix, remove the allowed
            // prefix. Given that we remove it, there's no need to compare it with the remaining
            // exclusion prefixes.
            if exclude.covers(prefix) {
                result.remove(prefix);
                break;
            }

            // If allowed prefix covers the exclusion prefix, then it means the exclusion prefix
            // excludes a portion of this allowed prefix. We need to remove the allowed prefix, and
            // add instead the smaller fragments resulting from the application of the exclusion
            // prefix.
            if prefix.covers(exclude) {
                result.remove(prefix);
                result.append(&mut apply_exclude(&prefix, &exclude));
            }
        }
    }

    result
}

fn apply_exclude(prefix: &Prefix, exclude: &Prefix) -> BTreeSet<Prefix> {
    let mut result = BTreeSet::new();
    let mut prefix_covering_exclude = prefix.clone();
    let len_diff = exclude.length() - prefix.length();

    for _ in 0..len_diff {
        let prefix_len = prefix_covering_exclude.length();
        let prefix_address = prefix_covering_exclude.as_address();
        let split_address = address_split(&prefix_covering_exclude);

        let subprefix_low = Prefix::from((prefix_address, prefix_len + 1));
        let subprefix_high = Prefix::from((split_address, prefix_len + 1));

        if subprefix_low.covers(exclude) {
            result.insert(subprefix_high);
            prefix_covering_exclude = subprefix_low;
        } else {
            result.insert(subprefix_low);
            prefix_covering_exclude = subprefix_high;
        }
    }

    result
}

fn address_split(prefix: &Prefix) -> IpAddr {
    // 1.0.0.0/16 splits as 1.0.0.0/17 and 1.0.128.0/17
    // 1.0.0.0/24 splits as 1.0.0.0/25 and 1.0.0.128/25
    // 1.0.0.0/31 splits as 1.0.0.0/32 and 1.0.0.1/32
    // We do: base_address + (1 << (32 - prefix_len - 1))

    let prefix_len = prefix.length();
    match prefix.as_address() {
        IpAddr::V4(addr) => {
            let new_addr = addr | Ipv4Addr::from_bits(1 << (32 - prefix_len - 1));
            IpAddr::V4(new_addr)
        }
        IpAddr::V6(addr) => {
            let new_addr = addr | Ipv6Addr::from_bits(1 << (128 - prefix_len - 1));
            IpAddr::V6(new_addr)
        }
    }
}

// ------------------------------------------------------------------------------------------------

mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_natport() {
        assert_eq!(
            NatPort::new_checked(0),
            Err(InvalidNatPort::ReservedPort(0))
        );
        assert_eq!(
            NatPort::new_checked(1024),
            Err(InvalidNatPort::ReservedPort(1024))
        );
        assert_eq!(NatPort::new_checked(1025), Ok(NatPort(1025)));
        assert_eq!(NatPort::new_checked(2000), Ok(NatPort(2000)));
        assert_eq!(NatPort::new_checked(20000), Ok(NatPort(20000)));
        assert_eq!(NatPort::new_checked(65535), Ok(NatPort(65535)));

        assert_eq!(
            NatPort::new_checked(3456)
                .expect("failed to create NatPort")
                .as_u16(),
            3456
        );
    }

    // ------------------------------------------------------------------------------------------------

    #[test]
    fn test_address_split() {
        assert_eq!(
            address_split(&"1.0.0.0/16".into()),
            IpAddr::V4(Ipv4Addr::from_str("1.0.128.0").unwrap())
        );
        assert_eq!(
            address_split(&"1.0.0.0/17".into()),
            IpAddr::V4(Ipv4Addr::from_str("1.0.64.0").unwrap())
        );
        assert_eq!(
            address_split(&"1.0.128.0/17".into()),
            IpAddr::V4(Ipv4Addr::from_str("1.0.192.0").unwrap())
        );
        assert_eq!(
            address_split(&"1.0.0.0/24".into()),
            IpAddr::V4(Ipv4Addr::from_str("1.0.0.128").unwrap())
        );
        assert_eq!(
            address_split(&"1.0.0.0/31".into()),
            IpAddr::V4(Ipv4Addr::from_str("1.0.0.1").unwrap())
        );
    }

    #[test]
    fn test_collapse_prefix_lists() {
        fn btree_from(prefixes: Vec<&str>) -> BTreeSet<Prefix> {
            prefixes.into_iter().map(|s| Prefix::from(s)).collect()
        }

        // Empty sets
        let prefixes = BTreeSet::new();
        let excludes = BTreeSet::new();
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Empty prefixes, non-empty excludes
        let prefixes = BTreeSet::new();
        let excludes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/24"]);
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Excludes outside prefix
        let prefixes = btree_from(vec!["10.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/24"]);
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Non-empty prefixes, empty excludes
        let prefixes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/16"]);
        let excludes = BTreeSet::new();
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Differing IP versions
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1::/112"]);
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Actual collapsing

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/16"]);
        let expected = btree_from(vec![]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/17"]);
        let expected = btree_from(vec!["1.0.128.0/17"]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.128.0/17"]);
        let expected = btree_from(vec!["1.0.0.0/17"]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.1.0/24"]);
        let expected = btree_from(vec![
            "1.0.128.0/17",
            "1.0.64.0/18",
            "1.0.32.0/19",
            "1.0.16.0/20",
            "1.0.8.0/21",
            "1.0.4.0/22",
            "1.0.2.0/23",
            "1.0.0.0/24",
        ]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Multiple prefixes
        let prefixes = btree_from(vec!["1.0.0.0/16", "2.0.17.0/24"]);
        let excludes = btree_from(vec!["1.0.1.0/24", "2.0.17.64/26"]);
        let expected = btree_from(vec![
            "1.0.128.0/17",
            "1.0.64.0/18",
            "1.0.32.0/19",
            "1.0.16.0/20",
            "1.0.8.0/21",
            "1.0.4.0/22",
            "1.0.2.0/23",
            "1.0.0.0/24",
            "2.0.17.128/25",
            "2.0.17.0/26",
        ]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Multiple excludes on one prefix
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.1.0/24", "1.0.3.0/24", "1.0.8.0/21"]);
        let expected = btree_from(vec![
            "1.0.128.0/17",
            "1.0.64.0/18",
            "1.0.32.0/19",
            "1.0.16.0/20",
            "1.0.4.0/22",
            "1.0.2.0/24",
            "1.0.0.0/24",
        ]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Overlapping excludes
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/17", "1.0.0.0/24"]);
        let expected = btree_from(vec!["1.0.128.0/17"]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);
    }
}
