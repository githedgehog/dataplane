// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Open Network Fabric Authors

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

fn v4cdir_from_bytes(addr_bytes: u32, mask: u8) -> String {
    let and_mask = u32::MAX.unbounded_shl(32 - u32::from(mask));
    let addr = Ipv4Addr::from(addr_bytes & and_mask);
    format!("{addr}/{mask}")
}

fn v6cdir_from_bytes(addr_bytes: u128, mask: u8) -> String {
    let and_mask = u128::MAX.unbounded_shl(128 - u32::from(mask));
    let addr = Ipv6Addr::from(addr_bytes & and_mask);
    format!("{addr}/{mask}")
}

pub struct UniqueV4CidrGenerator {
    count: u16,
    mask: u8,
}

impl UniqueV4CidrGenerator {
    #[must_use]
    pub fn new(count: u16, mask: u8) -> Self {
        Self { count, mask }
    }
}

impl ValueGenerator for UniqueV4CidrGenerator {
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.mask == 0 && self.count > 0 {
            d.produce::<u32>(); // generate a value to satisfy the bolero driver
            return Some(vec!["0.0.0.0/0".to_string()]);
        }

        let available_addrs = 1_u32.unbounded_shl(u32::from(self.mask));
        let max_to_generate = if available_addrs > 0 {
            // Unwrap should never fail here because count is u16 and we take the min
            // The - 1 is to discount the 0 address which we won't generate
            #[allow(clippy::unwrap_used)]
            u16::try_from((available_addrs - 1).min(u32::from(self.count))).unwrap()
        } else {
            self.count
        };

        let addr_bytes_seed = d.gen_u32(
            Bound::Included(&0x1000_0000_u32),
            Bound::Included(&u32::MAX),
        )?;
        let mut cidrs = Vec::with_capacity(usize::from(self.count));
        let mut addrs_left = max_to_generate;
        let mut addr_bytes = addr_bytes_seed.unbounded_shr(u32::from(32 - self.mask));
        let addr_bytes_mask = u32::MAX.unbounded_shr(u32::from(32 - self.mask));
        while addrs_left > 0 {
            if addr_bytes & addr_bytes_mask == 0 {
                // Smallest valid v4 address with given mask
                addr_bytes = 1;
            }
            let cidr = v4cdir_from_bytes(
                addr_bytes.unbounded_shl(u32::from(32 - self.mask)),
                self.mask,
            );
            cidrs.push(cidr);
            addrs_left -= 1;
            addr_bytes = addr_bytes.wrapping_add(1);
        }
        Some(cidrs)
    }
}

#[derive(Debug)]
pub struct UniqueV6CidrGenerator {
    pub count: u16,
    pub mask: u8,
}

impl UniqueV6CidrGenerator {
    #[must_use]
    pub fn new(count: u16, mask: u8) -> Self {
        Self { count, mask }
    }
}

impl ValueGenerator for UniqueV6CidrGenerator {
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.mask == 0 && self.count > 0 {
            d.produce::<u32>(); // generate a value to satisfy the bolero driver
            return Some(vec!["::/0".to_string()]);
        }

        let available_addrs = 1_u128.unbounded_shl(u32::from(self.mask));

        let max_to_generate = if available_addrs > 0 {
            // Unwrap should never fail here because count is u16 and we take the min
            // The - 1 is to discount the 0 address which we won't generate
            #[allow(clippy::unwrap_used)]
            u16::try_from((available_addrs - 1).min(u128::from(self.count))).unwrap()
        } else {
            self.count
        };

        let addr_bytes_seed = d.gen_u128(Bound::Included(&1_u128), Bound::Included(&u128::MAX))?;
        let mut cidrs = Vec::with_capacity(usize::from(self.count));
        let mut addrs_left = max_to_generate;
        let mut addr_bytes = addr_bytes_seed.unbounded_shr(u32::from(128 - self.mask));
        let addr_bytes_mask = u128::MAX.unbounded_shr(u32::from(128 - self.mask));
        while addrs_left > 0 {
            if addr_bytes & addr_bytes_mask == 0 {
                // Smallest valid v6 address with mask
                addr_bytes = 1;
            }
            let cidr = v6cdir_from_bytes(
                addr_bytes.unbounded_shl(u32::from(128 - self.mask)),
                self.mask,
            );
            cidrs.push(cidr);
            addrs_left -= 1;
            addr_bytes = addr_bytes.wrapping_add(1);
        }
        Some(cidrs)
    }
}

pub struct UniqueV4InterfaceAddressGenerator {
    pub count: u16,
}

impl UniqueV4InterfaceAddressGenerator {
    #[must_use]
    pub fn new(count: u16) -> Self {
        Self { count }
    }
}

pub struct UniqueV6InterfaceAddressGenerator {
    pub count: u16,
}

impl UniqueV6InterfaceAddressGenerator {
    #[must_use]
    pub fn new(count: u16) -> Self {
        Self { count }
    }
}
impl ValueGenerator for UniqueV4InterfaceAddressGenerator {
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.count == 0 {
            return Some(vec![]);
        }
        // Calculate a mask to get a unique prefix for each address
        // plus 1 because all 0s for the first octect is not a valid prefix
        let num_prefix_bits = u32::BITS - self.count.next_power_of_two().leading_zeros();
        let largest_num_addr_bits = 32 - num_prefix_bits;
        let smallest_mask = num_prefix_bits;

        let largest_prefix = 1_u32.unbounded_shl(num_prefix_bits) - 1;
        let mut prefix = d.gen_u32(Bound::Included(&0), Bound::Included(&largest_prefix))?;
        let mut addrs = Vec::with_capacity(usize::from(self.count));
        for _ in 0..self.count {
            let mask_len = d.gen_u32(Bound::Included(&smallest_mask), Bound::Included(&32))?;
            let current_num_prefix_bits = 32 - mask_len;
            let addr_mask = u32::MAX.unbounded_shr(mask_len);
            // /31 addresses are special case where the first and last address are not broadcast or network addresses
            #[allow(clippy::bool_to_int_with_if)]
            let smallest_addr = if current_num_prefix_bits == 0 || mask_len >= 31 {
                0
            } else {
                1
            };
            #[allow(clippy::bool_to_int_with_if)]
            let largest_addr = if current_num_prefix_bits == 0 {
                0 // The address is all prefix, no address bits
            } else {
                addr_mask - (if mask_len >= 31 { 0 } else { 1 })
            };
            let addr_data = d.gen_u32(
                Bound::Included(&smallest_addr),
                Bound::Included(&largest_addr),
            )?;

            let addr_as_u32 = prefix.unbounded_shl(largest_num_addr_bits) | addr_data;
            let addr = Ipv4Addr::from(addr_as_u32);
            addrs.push(format!("{addr}/{mask_len}"));
            prefix += 1;
            if prefix > largest_prefix {
                prefix = 0;
            }
        }
        Some(addrs)
    }
}

impl ValueGenerator for UniqueV6InterfaceAddressGenerator {
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.count == 0 {
            return Some(vec![]);
        }
        // Calculate a mask so that we get a unique prefix for each address
        let num_prefix_bits = u128::BITS - self.count.next_power_of_two().leading_zeros();
        let largest_num_addr_bits = 128 - num_prefix_bits;
        let smallest_mask = num_prefix_bits;

        let largest_prefix = 1_u128.unbounded_shl(num_prefix_bits) - 1;
        let mut prefix = d.gen_u128(Bound::Excluded(&0), Bound::Included(&largest_prefix))?;
        let mut addrs = Vec::with_capacity(usize::from(self.count));
        for _ in 0..self.count {
            let mask_len = d.gen_u32(Bound::Included(&smallest_mask), Bound::Included(&128))?;
            let current_num_prefix_bits = 128 - mask_len;
            let addr_mask = u128::MAX.unbounded_shr(mask_len);
            // /127 addresses are special case where the first and last address are not broadcast or network addresses
            #[allow(clippy::bool_to_int_with_if)]
            let smallest_addr = if current_num_prefix_bits == 0 || mask_len >= 127 {
                0
            } else {
                1
            };
            #[allow(clippy::bool_to_int_with_if)]
            let largest_addr = if current_num_prefix_bits == 0 {
                0 // The address is all prefix, no address bits
            } else {
                addr_mask - (if mask_len >= 127 { 0 } else { 1 })
            };
            let addr_data = d.gen_u128(
                Bound::Included(&smallest_addr),
                Bound::Included(&largest_addr),
            )?;

            let addr_as_u128 = prefix.unbounded_shl(largest_num_addr_bits) | addr_data;
            let addr = Ipv6Addr::from(addr_as_u128);
            addrs.push(format!("{addr}/{mask_len}"));
            prefix += 1;
            if prefix > largest_prefix {
                prefix = 0;
            }
        }
        Some(addrs)
    }
}

pub fn choose<T: Clone, D: Driver>(d: &mut D, choices: &[T]) -> Option<T> {
    let index = d.gen_usize(Bound::Included(&0), Bound::Excluded(&choices.len()))?;
    Some(choices[index].clone())
}

/// Characters legal anywhere in an RFC 1123 DNS label.
const NAME_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
/// Characters legal in the interior of an RFC 1123 DNS label.
const NAME_INNER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

/// Maximum length of an RFC 1123 DNS label.
const NAME_MAX_LEN: usize = 63;

/// A syntactically legal k8s object name.
///
/// k8s object names are RFC 1123 DNS labels: lowercase alphanumerics plus `-`, starting and
/// ending with an alphanumeric, at most 63 characters.  `bolero`'s [`String`] generator produces
/// arbitrary Unicode, which is *not* a legal name, so any CRD field naming a k8s object must draw
/// from here instead — a `TypeGenerator` must never produce an illegal value (see
/// `development/code/property-testing.md`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct K8sName(String);

impl K8sName {
    #[must_use]
    pub fn take(self) -> String {
        self.0
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for K8sName {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for K8sName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Covers every legal RFC 1123 DNS label.
impl TypeGenerator for K8sName {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        K8sNameGenerator::new(1, NAME_MAX_LEN).generate(d)
    }
}

/// A [`K8sName`] restricted to a length range.
///
/// Prefer this over [`K8sName`]'s [`TypeGenerator`] where 63-character names would only bloat the
/// generated config without exercising anything.
pub struct K8sNameGenerator {
    min_len: usize,
    max_len: usize,
}

impl K8sNameGenerator {
    /// # Panics
    ///
    /// Panics if the requested length range is not a sub-range of `1..=63`.
    #[must_use]
    pub fn new(min_len: usize, max_len: usize) -> Self {
        assert!(
            min_len >= 1 && min_len <= max_len && max_len <= NAME_MAX_LEN,
            "illegal k8s name length range {min_len}..={max_len}"
        );
        Self { min_len, max_len }
    }
}

impl ValueGenerator for K8sNameGenerator {
    type Output = K8sName;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let len = d.gen_usize(
            Bound::Included(&self.min_len),
            Bound::Included(&self.max_len),
        )?;
        let mut name = String::with_capacity(len);
        for position in 0..len {
            // Only the interior may hold a `-`; the first and last character must be alphanumeric.
            let alphabet = if position == 0 || position == len - 1 {
                NAME_ALNUM
            } else {
                NAME_INNER
            };
            let index = d.gen_usize(Bound::Included(&0), Bound::Excluded(&alphabet.len()))?;
            name.push(alphabet[index] as char);
        }
        Some(K8sName(name))
    }
}

/// Generate the textual form of a legal port range: `"<port>"` or `"<start>-<end>"`.
///
/// Both forms parse to an `lpm::prefix::PortRange`, which requires only `start <= end`.
pub fn generate_port_range<D: Driver>(d: &mut D) -> Option<String> {
    let a = d.produce::<u16>()?;
    let b = d.produce::<u16>()?;
    if a == b && d.gen_bool(None)? {
        // Cover the single-port spelling, which takes a distinct branch in `PortRange::from_str`.
        return Some(format!("{a}"));
    }
    Some(format!("{}-{}", a.min(b), a.max(b)))
}

/// Generate a legal `ports` list entry: one or more comma-separated port ranges.
///
/// The converters split these on `,` before parsing each element, and reject a present-but-empty
/// list, so this never yields an empty string.
pub fn generate_port_list<D: Driver>(d: &mut D) -> Option<String> {
    let count = d.gen_usize(Bound::Included(&1), Bound::Included(&4))?;
    let mut ranges = Vec::with_capacity(count);
    for _ in 0..count {
        ranges.push(generate_port_range(d)?);
    }
    Some(ranges.join(","))
}

/// [`generate_port_list`] as a standalone [`ValueGenerator`].
pub struct PortListGenerator;

impl ValueGenerator for PortListGenerator {
    type Output = String;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        generate_port_list(d)
    }
}

pub fn generate_v4_prefixes<D: Driver>(d: &mut D, count: u16) -> Option<Vec<String>> {
    let cidr4_gen =
        UniqueV4CidrGenerator::new(count, d.gen_u8(Bound::Included(&0), Bound::Included(&32))?);
    cidr4_gen.generate(d)
}

pub fn generate_v6_prefixes<D: Driver>(d: &mut D, count: u16) -> Option<Vec<String>> {
    let cidr6_gen =
        UniqueV6CidrGenerator::new(count, d.gen_u8(Bound::Included(&0), Bound::Included(&128))?);
    cidr6_gen.generate(d)
}

/// Reserved IPv4 blocks that may not appear in a `VpcExpose`, as `(base, prefix_len)`.
///
/// This mirrors `SPECIAL_USE_PREFIXES` in `config::external::overlay::vpcpeering`.  The two lists
/// are not mechanically linked -- `config` depends on this crate, not the other way round -- but
/// they do not need to be: `config`'s `test_gateway_config_validates` fails if this list ever
/// falls behind the one validation actually enforces.
const RESERVED_V4: &[(u32, u8)] = &[
    (0x0000_0000, 8),  // unspecified
    (0x7f00_0000, 8),  // loopback
    (0xa9fe_0000, 16), // link-local
    (0xe000_0000, 4),  // multicast
    (0xf000_0000, 4),  // reserved, includes the limited broadcast address
];

/// Reserved IPv6 blocks that may not appear in a `VpcExpose`.  See [`RESERVED_V4`].
const RESERVED_V6: &[(u128, u8)] = &[
    (0, 128),                                       // unspecified
    (1, 128),                                       // loopback
    (0xfe80 << 112, 10),                            // link-local
    (0xff00_0000_0000_0000_0000_0000_0000_0000, 8), // multicast
];

/// Shortest prefix length this module will generate for an expose.
///
/// Validation rejects a prefix that *overlaps* a reserved block, not merely one contained in it,
/// so every prefix shorter than this necessarily spans reserved space and cannot be legal.  Very
/// short prefixes that happen to dodge every reserved block (`8.0.0.0/7`, say) are legal but not
/// generated; expressing "everything" is what a `default` expose is for.
const MIN_ROUTABLE_MASK: u8 = 8;

/// Whether two prefixes overlap.
///
/// Both bases are assumed aligned to their own length, so overlap reduces to "the shorter prefix
/// contains the longer one's base".
fn v4_overlaps(a_base: u32, a_len: u8, b_base: u32, b_len: u8) -> bool {
    let len = u32::from(a_len.min(b_len));
    let mask = u32::MAX.unbounded_shl(32 - len);
    (a_base & mask) == (b_base & mask)
}

fn v6_overlaps(a_base: u128, a_len: u8, b_base: u128, b_len: u8) -> bool {
    let len = u32::from(a_len.min(b_len));
    let mask = u128::MAX.unbounded_shl(128 - len);
    (a_base & mask) == (b_base & mask)
}

/// Whether a prefix overlaps any reserved block.  Exposed for this module's own tests only; the
/// generators go through the skip-ahead helpers below.
#[cfg(test)]
pub(crate) fn test_only_v4_is_reserved(base: u32, len: u8) -> bool {
    RESERVED_V4
        .iter()
        .any(|&(r_base, r_len)| v4_overlaps(base, len, r_base, r_len))
}

#[cfg(test)]
pub(crate) fn test_only_v6_is_reserved(base: u128, len: u8) -> bool {
    RESERVED_V6
        .iter()
        .any(|&(r_base, r_len)| v6_overlaps(base, len, r_base, r_len))
}

/// The first prefix base at or after `base` that is not reserved.
///
/// Stepping one prefix at a time would be unusable: `240.0.0.0/4` alone holds 2^28 `/32`s.  So on
/// a hit, jump past the whole offending block instead, aligned back down to a prefix boundary.
fn v4_skip_reserved(mut base: u32, len: u8) -> u32 {
    let align = u32::MAX.unbounded_shl(u32::from(32 - len));
    let step = 1_u32.unbounded_shl(u32::from(32 - len));
    // At most one pass per reserved block: each jump lands strictly past the block it skipped, and
    // the only way to revisit lower addresses is the single wrap at the top of the space.
    for _ in 0..=RESERVED_V4.len() {
        let Some(&(r_base, r_len)) = RESERVED_V4
            .iter()
            .find(|&&(r_base, r_len)| v4_overlaps(base, len, r_base, r_len))
        else {
            return base;
        };
        // Round *up* to the next prefix boundary past the reserved block.  Rounding down would
        // land back inside the block whenever the block is narrower than the prefix being
        // generated -- a `/8` containing `169.254.0.0/16`, for instance.
        let block_end = r_base | !u32::MAX.unbounded_shl(u32::from(32 - r_len));
        base = block_end.wrapping_add(step) & align;
    }
    // Falling out of the loop would mean returning a reserved base, which surfaces downstream as a
    // validation failure a long way from its cause.  Say so here instead.
    unreachable!(
        "v4 reserved-block skip did not converge at /{len}; the loop bound assumes every jump \
         lands strictly past the block it skipped, so a new entry in RESERVED_V4 has broken that"
    )
}

fn v6_skip_reserved(mut base: u128, len: u8) -> u128 {
    let align = u128::MAX.unbounded_shl(u32::from(128 - len));
    let step = 1_u128.unbounded_shl(u32::from(128 - len));
    for _ in 0..=RESERVED_V6.len() {
        let Some(&(r_base, r_len)) = RESERVED_V6
            .iter()
            .find(|&&(r_base, r_len)| v6_overlaps(base, len, r_base, r_len))
        else {
            return base;
        };
        let block_end = r_base | !u128::MAX.unbounded_shl(u32::from(128 - r_len));
        base = block_end.wrapping_add(step) & align;
    }
    // See [`v4_skip_reserved`].
    unreachable!(
        "v6 reserved-block skip did not converge at /{len}; the loop bound assumes every jump \
         lands strictly past the block it skipped, so a new entry in RESERVED_V6 has broken that"
    )
}

/// Generate `count` distinct IPv4 prefixes, none overlapping a reserved block.
///
/// Use this wherever a prefix ends up in a `VpcExpose`; [`UniqueV4CidrGenerator`] is fine for
/// contexts with no such restriction (ACL matches, for instance).
pub struct RoutableV4CidrGenerator {
    count: u16,
    mask: u8,
}

impl RoutableV4CidrGenerator {
    /// # Panics
    ///
    /// Panics unless `mask` is in `MIN_ROUTABLE_MASK..=32`.
    #[must_use]
    pub fn new(count: u16, mask: u8) -> Self {
        assert!(
            (MIN_ROUTABLE_MASK..=32).contains(&mask),
            "illegal v4 prefix length /{mask}"
        );
        Self { count, mask }
    }
}

impl ValueGenerator for RoutableV4CidrGenerator {
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.count == 0 {
            return Some(Vec::new());
        }
        let step = 1_u32.unbounded_shl(u32::from(32 - self.mask));
        let seed = d.gen_u32(Bound::Included(&0), Bound::Included(&u32::MAX))?;
        // Align the seed down to a prefix boundary so the walk stays aligned.
        let mut base = seed & u32::MAX.unbounded_shl(u32::from(32 - self.mask));

        let mut cidrs = Vec::with_capacity(usize::from(self.count));
        for _ in 0..self.count {
            base = v4_skip_reserved(base, self.mask);
            cidrs.push(format!("{}/{}", Ipv4Addr::from(base), self.mask));
            base = base.wrapping_add(step);
        }
        Some(cidrs)
    }
}

/// Generate `count` distinct IPv6 prefixes, none overlapping a reserved block.
pub struct RoutableV6CidrGenerator {
    count: u16,
    mask: u8,
}

impl RoutableV6CidrGenerator {
    /// # Panics
    ///
    /// Panics unless `mask` is in `MIN_ROUTABLE_MASK..=128`.
    #[must_use]
    pub fn new(count: u16, mask: u8) -> Self {
        assert!(
            (MIN_ROUTABLE_MASK..=128).contains(&mask),
            "illegal v6 prefix length /{mask}"
        );
        Self { count, mask }
    }
}

impl ValueGenerator for RoutableV6CidrGenerator {
    type Output = Vec<String>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        if self.count == 0 {
            return Some(Vec::new());
        }
        let step = 1_u128.unbounded_shl(u32::from(128 - self.mask));
        let seed = d.gen_u128(Bound::Included(&0), Bound::Included(&u128::MAX))?;
        let mut base = seed & u128::MAX.unbounded_shl(u32::from(128 - self.mask));

        let mut cidrs = Vec::with_capacity(usize::from(self.count));
        for _ in 0..self.count {
            base = v6_skip_reserved(base, self.mask);
            cidrs.push(format!("{}/{}", Ipv6Addr::from(base), self.mask));
            base = base.wrapping_add(step);
        }
        Some(cidrs)
    }
}

/// Hands out mutually non-overlapping, non-reserved prefixes.
///
/// `VpcManifest::validate` rejects a manifest whose exposes overlap each other, so prefixes cannot
/// be drawn independently per expose -- something has to own the address space for the whole
/// config.  Every prefix a pool returns has the same length as its siblings and a distinct base,
/// which makes non-overlap immediate rather than something to check.
///
/// Uses interior mutability so it can be shared by `&` through the generator tree, since
/// [`ValueGenerator::generate`] takes `&self`.
pub struct PrefixPool {
    v4_next: std::cell::Cell<u32>,
    v6_next: std::cell::Cell<u128>,
}

impl PrefixPool {
    /// Block sizes handed out.  Small enough that a config can hold plenty, large enough to be
    /// realistic tenant blocks.
    const V4_MASK: u8 = 24;
    const V6_MASK: u8 = 64;

    /// Seed a pool at a driver-chosen point in the address space.
    pub fn new<D: Driver>(d: &mut D) -> Option<Self> {
        let v4_seed = d.gen_u32(Bound::Included(&0), Bound::Included(&u32::MAX))?;
        let v6_seed = d.gen_u128(Bound::Included(&0), Bound::Included(&u128::MAX))?;
        Some(Self {
            v4_next: std::cell::Cell::new(
                v4_seed & u32::MAX.unbounded_shl(u32::from(32 - Self::V4_MASK)),
            ),
            v6_next: std::cell::Cell::new(
                v6_seed & u128::MAX.unbounded_shl(u32::from(128 - Self::V6_MASK)),
            ),
        })
    }

    /// The next unused IPv4 prefix.
    pub fn next_v4(&self) -> String {
        let base = v4_skip_reserved(self.v4_next.get(), Self::V4_MASK);
        let step = 1_u32.unbounded_shl(u32::from(32 - Self::V4_MASK));
        self.v4_next.set(base.wrapping_add(step));
        format!("{}/{}", Ipv4Addr::from(base), Self::V4_MASK)
    }

    /// The next unused IPv6 prefix.
    pub fn next_v6(&self) -> String {
        let base = v6_skip_reserved(self.v6_next.get(), Self::V6_MASK);
        let step = 1_u128.unbounded_shl(u32::from(128 - Self::V6_MASK));
        self.v6_next.set(base.wrapping_add(step));
        format!("{}/{}", Ipv6Addr::from(base), Self::V6_MASK)
    }

    /// `count` unused prefixes, all of one family.
    pub fn take(&self, count: u16, v4: bool) -> Vec<String> {
        (0..count)
            .map(|_| if v4 { self.next_v4() } else { self.next_v6() })
            .collect()
    }
}

/// [`generate_prefixes`], restricted to prefixes legal inside a `VpcExpose`.
pub fn generate_routable_prefixes<D: Driver>(
    d: &mut D,
    v4_count: u16,
    v6_count: u16,
) -> Option<Vec<String>> {
    let mut prefixes = Vec::with_capacity(usize::from(v4_count) + usize::from(v6_count));
    if v4_count > 0 {
        let mask = d.gen_u8(Bound::Included(&MIN_ROUTABLE_MASK), Bound::Included(&32))?;
        prefixes.extend(RoutableV4CidrGenerator::new(v4_count, mask).generate(d)?);
    }
    if v6_count > 0 {
        let mask = d.gen_u8(Bound::Included(&MIN_ROUTABLE_MASK), Bound::Included(&128))?;
        prefixes.extend(RoutableV6CidrGenerator::new(v6_count, mask).generate(d)?);
    }
    Some(prefixes)
}

pub fn generate_prefixes<D: Driver>(
    d: &mut D,
    v4_count: u16,
    v6_count: u16,
) -> Option<Vec<String>> {
    let mut prefixes = Vec::with_capacity(usize::from(v4_count) + usize::from(v6_count));
    if v4_count > 0 {
        let v4_prefixes = generate_v4_prefixes(d, v4_count)?;
        prefixes.extend(v4_prefixes);
    }
    if v6_count > 0 {
        let v6_prefixes = generate_v6_prefixes(d, v6_count)?;
        prefixes.extend(v6_prefixes);
    }
    Some(prefixes)
}

#[cfg(test)]
mod test {
    #[cfg(not(miri))]
    const UNIQUE_COUNTS: [u16; 5] = [0, 1, 10, 16, 100];
    #[cfg(miri)]
    const UNIQUE_COUNTS: [u16; 4] = [0, 1, 10, 16];
    const ITERATIONS: usize = cfg_select! {
        emulated => 3,
        _ => 1000,
    };

    /// A generated name must be a legal RFC 1123 DNS label, which is the whole reason this
    /// generator exists in place of `produce::<String>()`.
    #[test]
    fn test_k8s_name_generator_is_rfc1123() {
        bolero::check!()
            .with_type::<crate::bolero::support::K8sName>()
            .for_each(|name| {
                let name = name.as_str();
                assert!(!name.is_empty(), "empty name");
                assert!(name.len() <= 63, "name too long: {name}");
                assert!(
                    name.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
                    "illegal character in {name}"
                );
                let first = name.bytes().next().unwrap();
                let last = name.bytes().next_back().unwrap();
                assert!(first.is_ascii_alphanumeric(), "leading '-' in {name}");
                assert!(last.is_ascii_alphanumeric(), "trailing '-' in {name}");
            });
    }

    /// Both spellings a port list can take must parse, and the range spelling must be ordered.
    #[test]
    fn test_generated_port_lists_parse() {
        bolero::check!()
            .with_generator(crate::bolero::support::PortListGenerator)
            .for_each(|ports| {
                for range in ports.split(',') {
                    let range = range
                        .parse::<lpm::prefix::PortRange>()
                        .unwrap_or_else(|e| panic!("failed to parse port range {range}: {e}"));
                    assert!(range.start() <= range.end());
                }
            });
    }

    /// Routable prefixes must be distinct and must avoid every reserved block.
    ///
    /// `config`'s validation is the real authority here; this test exists so that a regression in
    /// the skip-ahead logic fails locally and quickly rather than as a mystifying failure (or, as
    /// happened once, a hang) inside a downstream config property test.
    #[test]
    fn test_routable_v4_prefixes_avoid_reserved() {
        for mask in 8..=32 {
            let generator = crate::bolero::support::RoutableV4CidrGenerator::new(8, mask);
            bolero::check!()
                .with_generator(generator)
                .with_iterations(ITERATIONS)
                .for_each(|cidrs| {
                    let mut seen = std::collections::HashSet::new();
                    assert_eq!(cidrs.len(), 8);
                    for cidr in cidrs {
                        assert!(seen.insert(cidr), "duplicate prefix {cidr}");
                        let (addr, len) = cidr.split_once('/').unwrap();
                        let addr = addr.parse::<std::net::Ipv4Addr>().unwrap();
                        let len = len.parse::<u8>().unwrap();
                        assert_eq!(len, mask);
                        assert!(
                            !crate::bolero::support::test_only_v4_is_reserved(addr.to_bits(), len),
                            "generated reserved prefix {cidr}"
                        );
                    }
                });
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "just too slow on miri")]
    fn test_routable_v6_prefixes_avoid_reserved() {
        for mask in [8, 16, 32, 48, 64, 96, 127, 128] {
            let generator = crate::bolero::support::RoutableV6CidrGenerator::new(8, mask);
            bolero::check!()
                .with_generator(generator)
                .with_iterations(ITERATIONS)
                .for_each(|cidrs| {
                    let mut seen = std::collections::HashSet::new();
                    assert_eq!(cidrs.len(), 8);
                    for cidr in cidrs {
                        assert!(seen.insert(cidr), "duplicate prefix {cidr}");
                        let (addr, len) = cidr.split_once('/').unwrap();
                        let addr = addr.parse::<std::net::Ipv6Addr>().unwrap();
                        let len = len.parse::<u8>().unwrap();
                        assert_eq!(len, mask);
                        assert!(
                            !crate::bolero::support::test_only_v6_is_reserved(addr.to_bits(), len),
                            "generated reserved prefix {cidr}"
                        );
                    }
                });
        }
    }

    #[test]
    fn test_unique_v4_cidr_generator() {
        for mask in 0..=32 {
            let generator = crate::bolero::support::UniqueV4CidrGenerator::new(10, mask);
            bolero::check!()
                .with_generator(generator)
                .with_iterations(ITERATIONS) // Takes too long with auto-iterations
                .for_each(|cidrs| {
                    let mut seen = std::collections::HashSet::new();
                    for cidr in cidrs {
                        assert!(seen.insert(cidr), "Duplicate CIDR found: {cidr}");
                    }
                    assert!(
                        !cidrs.is_empty(),
                        "No CIDRs generated for mask={mask}, count=10"
                    );
                    assert!(cidrs.iter().all(|cidr| {
                        let (ip, mask) = cidr.split_once('/').unwrap();
                        assert!(mask.parse::<u8>().unwrap() <= 32);
                        ip.parse::<std::net::Ipv4Addr>().is_ok()
                    }));
                });
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "just too slow on miri")]
    fn test_unique_v6_cidr_generator() {
        for mask in 0..=128 {
            let generator = crate::bolero::support::UniqueV6CidrGenerator::new(10, mask);
            bolero::check!()
                .with_generator(generator)
                .with_iterations(ITERATIONS) // Takes too long with auto-iterations
                .for_each(|cidrs| {
                    let mut seen = std::collections::HashSet::new();
                    assert!(
                        !cidrs.is_empty(),
                        "No CIDRs generated for mask={mask}, count=10"
                    );
                    for cidr in cidrs {
                        assert!(seen.insert(cidr), "Duplicate CIDR found: {cidr}");
                    }
                    assert!(cidrs.iter().all(|cidr| {
                        let (ip, mask) = cidr.split_once('/').unwrap();
                        assert!(mask.parse::<u8>().unwrap() <= 128);
                        ip.parse::<std::net::Ipv6Addr>().is_ok()
                    }));
                });
        }
    }

    #[test]
    fn test_unique_v4_interface_address_generator() {
        for count in UNIQUE_COUNTS {
            let generator = crate::bolero::support::UniqueV4InterfaceAddressGenerator::new(count);
            bolero::check!()
                .with_generator(generator)
                .for_each(|addrs| {
                    let mut seen = std::collections::HashSet::new();
                    assert!(
                        addrs.len() == usize::from(count),
                        "Expected {count} addresses, got {}, {addrs:?}",
                        addrs.len(),
                    );
                    for addr in addrs {
                        let (ip_str, mask_str) = addr.split_once('/').unwrap();
                        let mask = mask_str.parse::<u32>().unwrap();
                        let ip = ip_str.parse::<std::net::Ipv4Addr>().unwrap();
                        assert!(seen.insert(ip), "Duplicate address found: {addr}");
                        if mask < 31 {
                            let addr_mask = u32::MAX.unbounded_shr(mask);
                            let addr_data = ip.to_bits();
                            assert!(
                                (addr_data & addr_mask) != 0 || mask == 0,
                                "Address is network address: {addr}"
                            );
                            assert!(
                                (addr_data & addr_mask) != addr_mask,
                                "Address is broadcast address: {addr}"
                            );
                        }
                    }
                });
        }
    }

    #[test]
    fn test_unique_v6_interface_address_generator() {
        for count in UNIQUE_COUNTS {
            let generator = crate::bolero::support::UniqueV6InterfaceAddressGenerator::new(count);
            bolero::check!()
                .with_generator(generator)
                .for_each(|addrs| {
                    let mut seen = std::collections::HashSet::new();
                    assert!(
                        addrs.len() == usize::from(count),
                        "Expected {count} addresses, got {}, {addrs:?}",
                        addrs.len(),
                    );
                    for addr in addrs {
                        let (ip_str, mask_str) = addr.split_once('/').unwrap();
                        let mask = mask_str.parse::<u32>().unwrap();
                        let ip = ip_str.parse::<std::net::Ipv6Addr>().unwrap();
                        assert!(seen.insert(ip), "Duplicate address found: {addr}");
                        assert!(mask <= 128, "Invalid mask: {mask}");
                        if mask < 127 {
                            let addr_mask = u128::MAX.unbounded_shr(mask);
                            let addr_data = u128::from(ip);
                            assert!(
                                (addr_data & addr_mask) != 0 || mask == 0,
                                "Address is network address: {addr}"
                            );
                            assert!(
                                (addr_data & addr_mask) != addr_mask,
                                "Address is broadcast address: {addr}"
                            );
                        }
                    }
                });
        }
    }
}
