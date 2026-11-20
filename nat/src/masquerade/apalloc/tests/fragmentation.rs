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

    /// One worker filled an address and then most of the ports were freed, one per block, leaving
    /// every block handed out. A second worker, which has never drawn from the address, asks for a
    /// port: there are 252 free ones.
    #[test]
    #[cfg_attr(miri, ignore = "fills a whole address, 64k allocations")]
    fn a_second_worker_gets_a_port_freed_inside_a_handed_out_block() {
        let allocator = pool_of(1);
        let held = drain(&allocator);
        let ip = held[0].ip();
        let blocks = by_block(held, ip);
        // Leave no block untouched, so no block can be handed out afresh.
        let held = free_one_per_block_except(blocks, u16::MAX);
        assert_eq!(held.len(), 252 * 255);

        let other = std::thread::scope(|s| s.spawn(|| allocator.allocate(false)).join().unwrap());

        let port = other.expect("252 ports are free on the address");
        assert_eq!(port.ip(), ip);
        drop(held);
    }

    /// The same, for the worker that filled the address: its current block is still full, but
    /// every other block has a free port.
    #[test]
    #[cfg_attr(miri, ignore = "fills a whole address, 64k allocations")]
    fn a_worker_whose_block_is_full_gets_a_port_freed_in_another_block() {
        let allocator = pool_of(1);
        let held = drain(&allocator);
        let ip = held[0].ip();
        let current = held.last().unwrap().port().as_u16() / 256;
        let blocks = by_block(held, ip);
        let held = free_one_per_block_except(blocks, current);
        assert_eq!(held.len(), 252 * 256 - 251);

        let port = allocator
            .allocate(false)
            .expect("251 ports are free on the address");
        assert_eq!(port.ip(), ip);
        assert_ne!(port.port().as_u16() / 256, current);
        drop(held);
    }

    /// A port caller drawing from a block opened for an identifier, where port 0 is free, gets a
    /// port rather than port 0's failure. Production pools serve one or the other, but a block
    /// another caller opened is now one any caller may draw from, and an error other than "full"
    /// ends the search.
    #[test]
    fn a_port_caller_skips_port_0_of_an_identifier_block() {
        let start = u128::from(addr_v4_bits("10.1.0.0"));
        let allocator = IpAllocator::<Ipv4Addr>::new(
            NatPool::for_range(
                AddrInterval::new(start, start),
                ReservedPorts::default(),
                false,
            ),
            false,
        );
        let zero = allocator.allocate(true).unwrap();
        let one = allocator.allocate(true).unwrap();
        assert_eq!([zero.port().as_u16(), one.port().as_u16()], [0, 1]);
        // Block 0 stays handed out, with identifier 0 free again.
        drop(zero);

        let port = allocator
            .allocate(false)
            .expect("block 0 has 254 free ports");
        assert_eq!(port.port().as_u16(), 2);
        drop(one);
    }

    /// Two addresses. The first is filled, then fragmented as above; the second is in use with
    /// nearly all of its blocks still free. Asking for a port must not stop at the first address.
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

    /// As above, from a worker new to both addresses.
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

/// The same state reached the way a gateway reaches it: mappings created through the allocator,
/// most of them reaped once idle, a few kept alive by flows that are still running.
#[concurrency_mode(std)]
mod mapping_tests {
    use crate::masquerade::apalloc::tests::alloc::context::*;
    use net::ip::NextHeader;
    use std::time::Duration;

    /// One public address. A worker opened a mapping on every one of its ports; all but one per
    /// block went idle and were reaped, the others are held by long-running flows. The flow table
    /// would now hold 252 flows. A second worker opens a new mapping.
    #[tokio::test]
    #[cfg_attr(miri, ignore = "fills a whole address, 64k allocations")]
    async fn a_few_long_lived_flows_do_not_starve_a_second_worker() {
        let timers = TestTimers::default();
        tokio::time::pause();
        let idle = Duration::from_secs(120);
        let allocator = build_allocator_short_timeout(idle);
        let open = |src_port: u16, timers: &TestTimers| {
            allocator.allocate_typed(
                vpcd1(),
                vpcd2(),
                PrivateTuple::new(addr_v4("1.1.0.1"), port(src_port), dst_v4(), None),
                NextHeader::TCP,
                timers,
            )
        };

        let mut seen_blocks = std::collections::BTreeSet::new();
        let mut long_lived = Vec::new();
        for src_port in 1..=252 * 256 {
            let mapping = open(src_port, &timers)
                .expect("the address has room")
                .allocation;
            // The first mapping of each block is the one whose flow keeps running.
            if seen_blocks.insert(mapping.port().as_u16() / 256) {
                long_lived.push(mapping);
            }
        }
        assert_eq!(long_lived.len(), 252);
        assert!(open(252 * 256 + 1, &timers).is_err(), "the address is full");

        // Everything else idles out and is reaped. The long-lived flows hold their mappings.
        timers.advance(idle * 2).await;

        let other = std::thread::scope(|s| {
            s.spawn(|| open(60_000, &TestTimers::default()))
                .join()
                .unwrap()
        });
        other.expect("all but 252 ports of the address are free");
        drop(long_lived);
    }
}
