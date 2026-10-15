// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The RSS redirection table (RETA): which receive queue each hash bucket lands in.
//!
//! RSS hashes a packet into one of the table's entries and delivers it to the queue that entry names.
//! By default every configured receive queue appears in the table. Laying the table out over a subset
//! of the queues keeps RSS off the others, which then only receive what a flow rule sends them, e.g. a
//! control-plane queue no data flood can fill.

use alloc::vec::Vec;

use dpdk_sys::{RTE_ETH_RETA_GROUP_SIZE, rte_eth_rss_reta_entry64};

use crate::queue::rx::RxQueueIndex;

/// Entries per group of the table, as the DPDK API reads and writes it.
const GROUP: usize = RTE_ETH_RETA_GROUP_SIZE as usize;

/// The largest table DPDK defines (`RTE_ETH_RSS_RETA_SIZE_512`).
pub(crate) const LARGEST: u16 = 512;

/// Why a redirection table could not be laid out or applied.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RetaError {
    /// The device has no redirection table (no RSS, or a PMD that does not expose one).
    #[error("the device has no RSS redirection table")]
    NoTable,
    /// A table must send every bucket somewhere.
    #[error("a redirection table needs at least one queue")]
    NoQueues,
    /// The driver refused the table.
    #[error(transparent)]
    Driver(#[from] errno::ErrorCode),
}

/// The groups the DPDK API takes for a table of `size` entries, each entry `entry(i)`, every entry
/// selected by the masks. The last group is partial when `size` is not a multiple of the group
/// size, as on mlx5 with a power of two of queues.
fn groups(
    size: u16,
    entry: impl Fn(usize) -> u16,
) -> Result<Vec<rte_eth_rss_reta_entry64>, RetaError> {
    if size == 0 {
        return Err(RetaError::NoTable);
    }
    let size = usize::from(size);
    Ok((0..size.div_ceil(GROUP))
        .map(|group| {
            let first = group * GROUP;
            let entries = (size - first).min(GROUP);
            rte_eth_rss_reta_entry64 {
                mask: u64::MAX >> (GROUP - entries),
                reta: core::array::from_fn(|i| if i < entries { entry(first + i) } else { 0 }),
            }
        })
        .collect())
}

/// Lay a table of `size` entries out round-robin over `queues`, in the groups the DPDK API takes.
///
/// Every entry names one of `queues`, every one of `queues` is named, and no two queues' shares
/// differ by more than one entry (given at least as many entries as queues).
///
/// # Errors
///
/// [`RetaError::NoTable`] for a size of zero, [`RetaError::NoQueues`] for an empty `queues`.
pub(crate) fn layout(
    size: u16,
    queues: &[RxQueueIndex],
) -> Result<Vec<rte_eth_rss_reta_entry64>, RetaError> {
    if queues.is_empty() {
        return Err(RetaError::NoQueues);
    }
    groups(size, |i| queues[i % queues.len()].0)
}

/// Whether a table of `size` entries splits evenly over `queues` queues.
pub(crate) fn even(size: u16, queues: usize) -> bool {
    queues != 0 && usize::from(size).is_multiple_of(queues)
}

/// An empty set of groups to read a table of `size` entries into: every entry is asked for.
pub(crate) fn query_groups(size: u16) -> Result<Vec<rte_eth_rss_reta_entry64>, RetaError> {
    groups(size, |_| 0)
}

/// The queue each of the first `size` entries names, in table order.
pub(crate) fn flatten(groups: &[rte_eth_rss_reta_entry64], size: u16) -> Vec<RxQueueIndex> {
    groups
        .iter()
        .flat_map(|group| group.reta.iter().copied().map(RxQueueIndex))
        .take(usize::from(size))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_layout_uses_exactly_the_given_queues_evenly() {
        bolero::check!()
            .with_type::<(u16, Vec<u16>)>()
            .for_each(|(size, queues)| {
                let size = size % (LARGEST + 1);
                let queues: Vec<_> = queues.iter().take(64).copied().map(RxQueueIndex).collect();
                let laid = layout(size, &queues);
                if queues.is_empty() {
                    assert_eq!(laid.err(), Some(RetaError::NoQueues));
                    return;
                }
                if size == 0 {
                    assert_eq!(laid.err(), Some(RetaError::NoTable));
                    return;
                }
                let groups = laid.unwrap();
                // Exactly `size` entries are selected, the first ones.
                let selected: u32 = groups.iter().map(|g| g.mask.count_ones()).sum();
                assert_eq!(selected, u32::from(size));
                assert!(
                    groups
                        .iter()
                        .all(|g| (g.mask.wrapping_add(1) & g.mask) == 0)
                );
                let entries = flatten(&groups, size);
                assert_eq!(entries.len(), usize::from(size));
                // Every entry names a given queue, and, given room, every given queue is named.
                assert!(entries.iter().all(|q| queues.contains(q)));
                if usize::from(size) >= queues.len() {
                    assert!(queues.iter().all(|q| entries.contains(q)));
                }
                // Round-robin over the list: a queue listed k times gets k shares, each share
                // differing from the others by at most one entry.
                let share = |q| entries.iter().filter(|e| **e == q).count();
                let listed = |q| queues.iter().filter(|e| **e == q).count();
                let (lo, hi) = (
                    usize::from(size) / queues.len(),
                    usize::from(size).div_ceil(queues.len()),
                );
                for q in &queues {
                    let (got, k) = (share(*q), listed(*q));
                    assert!(
                        got >= lo * k && got <= hi * k,
                        "{got} entries for {k} listing(s)"
                    );
                }
                assert_eq!(even(size, queues.len()), lo == hi);
            });
    }

    #[test]
    fn a_table_smaller_than_a_group_is_one_partial_group() {
        let groups = layout(4, &[RxQueueIndex(0), RxQueueIndex(1), RxQueueIndex(2)]).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].mask, 0b1111);
        assert_eq!(flatten(&groups, 4), [0, 1, 2, 0].map(RxQueueIndex).to_vec());
    }
}
