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

/// Why a redirection table could not be laid out or applied.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RetaError {
    /// The device has no redirection table (no RSS, or a PMD that does not expose one).
    #[error("the device has no RSS redirection table")]
    NoTable,
    /// The table's size is not a whole number of groups, which the DPDK API cannot address.
    #[error("a redirection table of {0} entries is not a whole number of {GROUP}-entry groups")]
    Ragged(u16),
    /// A table must send every bucket somewhere.
    #[error("a redirection table needs at least one queue")]
    NoQueues,
    /// The driver refused the table.
    #[error(transparent)]
    Driver(#[from] errno::ErrorCode),
}

/// Lay a table of `size` entries out round-robin over `queues`, in the groups the DPDK API takes.
///
/// Every entry names one of `queues`, every one of `queues` is named, and no two queues' shares
/// differ by more than one entry (given at least as many entries as queues).
///
/// # Errors
///
/// [`RetaError::NoTable`] for a size of zero, [`RetaError::Ragged`] for a size that is not a
/// multiple of the group size, [`RetaError::NoQueues`] for an empty `queues`.
pub(crate) fn layout(
    size: u16,
    queues: &[RxQueueIndex],
) -> Result<Vec<rte_eth_rss_reta_entry64>, RetaError> {
    if size == 0 {
        return Err(RetaError::NoTable);
    }
    if usize::from(size) % GROUP != 0 {
        return Err(RetaError::Ragged(size));
    }
    if queues.is_empty() {
        return Err(RetaError::NoQueues);
    }
    let groups = usize::from(size) / GROUP;
    Ok((0..groups)
        .map(|group| rte_eth_rss_reta_entry64 {
            // Every entry of every group is written.
            mask: u64::MAX,
            reta: core::array::from_fn(|entry| queues[(group * GROUP + entry) % queues.len()].0),
        })
        .collect())
}

/// An empty set of groups to read a table of `size` entries into: every entry is asked for.
pub(crate) fn query_groups(size: u16) -> Result<Vec<rte_eth_rss_reta_entry64>, RetaError> {
    if size == 0 {
        return Err(RetaError::NoTable);
    }
    if usize::from(size) % GROUP != 0 {
        return Err(RetaError::Ragged(size));
    }
    Ok((0..usize::from(size) / GROUP)
        .map(|_| rte_eth_rss_reta_entry64 {
            mask: u64::MAX,
            reta: [0; GROUP],
        })
        .collect())
}

/// The queue each entry names, in table order.
pub(crate) fn flatten(groups: &[rte_eth_rss_reta_entry64]) -> Vec<RxQueueIndex> {
    groups
        .iter()
        .flat_map(|group| group.reta.iter().copied().map(RxQueueIndex))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_layout_uses_exactly_the_given_queues_evenly() {
        bolero::check!()
            .with_type::<(u8, Vec<u16>)>()
            .for_each(|(groups, queues)| {
                let size = u16::from(groups % 9) * 64;
                let queues: Vec<_> = queues.iter().take(64).copied().map(RxQueueIndex).collect();
                let laid = layout(size, &queues);
                if size == 0 {
                    assert_eq!(laid.err(), Some(RetaError::NoTable));
                    return;
                }
                if queues.is_empty() {
                    assert_eq!(laid.err(), Some(RetaError::NoQueues));
                    return;
                }
                let groups = laid.unwrap();
                assert!(groups.iter().all(|g| g.mask == u64::MAX));
                let entries = flatten(&groups);
                assert_eq!(entries.len(), usize::from(size));
                // Every entry names a given queue, and every given queue is named.
                assert!(entries.iter().all(|q| queues.contains(q)));
                assert!(queues.iter().all(|q| entries.contains(q)));
                // Round-robin over the list: a queue listed k times gets k shares, each share
                // differing from the others by at most one entry.
                let share = |q| entries.iter().filter(|e| **e == q).count();
                let listed = |q| queues.iter().filter(|e| **e == q).count();
                let per_listing: Vec<_> = queues.iter().map(|q| (share(*q), listed(*q))).collect();
                let (lo, hi) = (
                    usize::from(size) / queues.len(),
                    usize::from(size).div_ceil(queues.len()),
                );
                for (got, k) in per_listing {
                    assert!(
                        got >= lo * k && got <= hi * k,
                        "{got} entries for {k} listing(s)"
                    );
                }
            });
    }

    #[test]
    fn a_size_that_is_not_whole_groups_is_refused() {
        assert_eq!(
            layout(65, &[RxQueueIndex(0)]).err(),
            Some(RetaError::Ragged(65))
        );
        assert_eq!(query_groups(100).err(), Some(RetaError::Ragged(100)));
    }
}
