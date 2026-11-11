// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ports freed inside blocks that are still handed out must stay allocatable.
//!
//! A block of 256 ports stays handed out while any one of its ports is live, so after churn an
//! address can have every block handed out and most of their ports free. Each test below reaches
//! that state and then asks for one more port, which the address (or the pool) has room for.

#![cfg(test)]

use concurrency::concurrency_mode;

#[concurrency_mode(std)]
mod std_tests {
    use crate::masquerade::apalloc::alloc::{IpAllocator, NatPool};
    use crate::masquerade::apalloc::port_alloc::AllocatedPort;
    use crate::masquerade::apalloc::region::AddrInterval;
    use crate::masquerade::apalloc::reserved::ReservedPorts;
    use crate::masquerade::apalloc::tests::alloc::context::addr_v4_bits;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    /// A pool of `count` consecutive public addresses from 10.1.0.0, with no ports claimed and the
    /// well-known ports excluded, built the way `build_region_allocators` builds one.
    fn pool_of(count: u32) -> IpAllocator<Ipv4Addr> {
        let start = u128::from(addr_v4_bits("10.1.0.0"));
        let pool = NatPool::for_range(
            AddrInterval::new(start, start + u128::from(count) - 1),
            ReservedPorts::default(),
            true,
        );
        IpAllocator::new(pool, false)
    }

    /// Allocate until the pool refuses, returning every port handed out in order.
    fn drain(allocator: &IpAllocator<Ipv4Addr>) -> Vec<AllocatedPort<Ipv4Addr>> {
        std::iter::from_fn(|| allocator.allocate(false).ok()).collect()
    }

    /// Ports, by the block they come from.
    type Blocks = BTreeMap<u16, Vec<AllocatedPort<Ipv4Addr>>>;

    /// `held`, all on address `ip`, grouped by block.
    fn by_block(held: Vec<AllocatedPort<Ipv4Addr>>, ip: Ipv4Addr) -> Blocks {
        let mut blocks = Blocks::new();
        for port in held {
            assert_eq!(port.ip(), ip);
            blocks
                .entry(port.port().as_u16() / 256)
                .or_default()
                .push(port);
        }
        blocks
    }

    /// Free one port in every block of `blocks` except `keep_full`, returning what is still held.
    fn free_one_per_block_except(blocks: Blocks, keep_full: u16) -> Vec<AllocatedPort<Ipv4Addr>> {
        blocks
            .into_iter()
            .flat_map(|(block, mut ports)| {
                if block != keep_full {
                    drop(ports.pop());
                }
                ports
            })
            .collect()
    }

    /// The baseline: one address, filled to the last port, refuses the next one.
    #[test]
    #[cfg_attr(miri, ignore = "fills a whole address, 64k allocations")]
    fn a_full_address_refuses_another_port() {
        let allocator = pool_of(1);
        let held = drain(&allocator);
        // 252 blocks of 256 ports, from 1024 up.
        assert_eq!(held.len(), 252 * 256);
        assert!(allocator.allocate(false).is_err());
    }

    /// Two addresses. The first is filled, then one port is freed in every block but the worker's
    /// current one, so every block stays handed out; the second is in use with nearly all of its
    /// blocks still free. Asking for a port must not stop at the first address.
    #[test]
    #[cfg_attr(miri, ignore = "fills a whole address, 64k allocations")]
    fn a_fragmented_address_does_not_hide_the_next_one() {
        let allocator = pool_of(2);
        let first: Vec<_> = (0..252 * 256)
            .map(|_| {
                allocator
                    .allocate(false)
                    .expect("the first address has room")
            })
            .collect();
        let ip = first[0].ip();
        assert!(first.iter().all(|port| port.ip() == ip));
        let current = first.last().unwrap().port().as_u16() / 256;
        // The pool moves to the second address, which is now in use.
        let second = allocator
            .allocate(false)
            .expect("the second address has room");
        assert_ne!(second.ip(), ip);

        let blocks = by_block(first, ip);
        let first = free_one_per_block_except(blocks, current);

        // Whichever address it comes from, there is room: 251 ports on the first, 251 blocks on
        // the second.
        let port = allocator.allocate(false).expect("both addresses have room");
        drop((port, first, second));
    }

    /// As above, from a worker new to both addresses, with a port freed in every block of the
    /// first.
    #[test]
    #[cfg_attr(miri, ignore = "fills a whole address, 64k allocations")]
    fn a_second_worker_is_not_stopped_by_a_fragmented_address() {
        let allocator = pool_of(2);
        let first: Vec<_> = (0..252 * 256)
            .map(|_| {
                allocator
                    .allocate(false)
                    .expect("the first address has room")
            })
            .collect();
        let ip = first[0].ip();
        let second = allocator
            .allocate(false)
            .expect("the second address has room");
        let blocks = by_block(first, ip);
        let first = free_one_per_block_except(blocks, u16::MAX);

        let other = std::thread::scope(|s| s.spawn(|| allocator.allocate(false)).join().unwrap());

        other.expect("both addresses have room");
        drop((first, second));
    }
}
