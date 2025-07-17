// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::AllocatorError;
use super::NatIp;
use super::port_alloc::PortBlockAllocator;
use crate::stateful::port::NatPort;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
struct AllocatedIpsList<I: NatIp> {
    in_use: VecDeque<AllocatedIp<I>>,
    full: Vec<AllocatedIp<I>>,
}

impl<I: NatIp> AllocatedIpsList<I> {
    fn add_in_use(&mut self, ip: AllocatedIp<I>) {
        self.in_use.push_back(ip);
    }

    fn get_first(&self) -> Option<&AllocatedIp<I>> {
        self.in_use.front()
    }

    fn get_first_mut(&mut self) -> Option<&mut AllocatedIp<I>> {
        self.in_use.front_mut()
    }

    fn pull_first_usable(&mut self) {
        loop {
            let Some(front_entry) = self.in_use.front() else {
                // Empty list, nothing to pull; return
                return;
            };
            if front_entry.port_allocator.has_usable_ports() {
                // Front entry is usable, return
                return;
            }
            // Front entry is not usable, move it to full and loop again
            self.move_front_to_full();
        }
    }

    fn move_front_to_full(&mut self) {
        if let Some(ip) = self.in_use.pop_front() {
            self.full.push(ip);
        }
    }
}

#[derive(Debug)]
pub struct NatPool<I: NatIp> {
    bitmap: RoaringBitmap,
    bitmap_mapping: BTreeMap<u32, u128>,
    allocated_ips: AllocatedIpsList<I>,
}

impl<I: NatIp> NatPool<I> {
    pub fn new() -> Self {
        Self {
            bitmap: RoaringBitmap::new(),
            bitmap_mapping: BTreeMap::new(),
            allocated_ips: AllocatedIpsList {
                in_use: VecDeque::new(),
                full: Vec::new(),
            },
        }
    }
}

impl NatPool<Ipv4Addr> {
    pub fn allocate(&mut self) -> Result<(Ipv4Addr, NatPort), AllocatorError> {
        let ip = self.get_ip()?;
        let port = ip.allocate_port()?;

        Ok((ip.ip(), port))
    }

    fn use_new_ip(&mut self) -> Result<(), AllocatorError> {
        // Retrieve the first available IP address
        let offset = self.bitmap.min().ok_or(AllocatorError::NoFreeIp)?;
        self.bitmap.remove(offset);
        let alloc_ip = AllocatedIp::new(Ipv4Addr::from(offset));

        // Move the new IP to the front of the list of IP in use for allocation
        self.allocated_ips.add_in_use(alloc_ip.clone());
        Ok(())
    }

    fn get_ip(&mut self) -> Result<&mut AllocatedIp<Ipv4Addr>, AllocatorError> {
        // Clean up any full allocated IP address from the list
        self.allocated_ips.pull_first_usable();

        // If we have no entry left, allocate a new one
        if self.allocated_ips.get_first().is_none() {
            self.use_new_ip()?;
        }

        // Return the first entry from the list of available allocated IP addresses
        self.allocated_ips
            .get_first_mut()
            .ok_or(AllocatorError::NoFreeIp)
    }
}

impl NatPool<Ipv6Addr> {
    pub fn allocate(&mut self) -> Result<(Ipv6Addr, NatPort), AllocatorError> {
        let ip = self.get_ip()?;
        let port = ip.allocate_port()?;

        Ok((ip.ip(), port))
    }

    fn map_offset(&self, offset: u32) -> Result<Ipv6Addr, AllocatorError> {
        // Field bitmap_mapping is a BTreeMap that associates, to each given u32 offset, an IPv6
        // address, as a u128, corresponding to the network address of the corresponding prefix in
        // the list.
        // Here we lookup for the closest lower offset in the tree, which returns the network
        // address for the prefix start address and its offset, and we deduce the IPv6 address we're
        // looking for.
        let (prefix_offset, prefix_start_bits) = self
            .bitmap_mapping
            .range(..=offset)
            .next_back()
            .ok_or(AllocatorError::InternalIssue)?;

        // Generate the IPv6 address: prefix network address - prefix offset + address offset
        Ok(Ipv6Addr::from(
            prefix_start_bits + u128::from(offset - prefix_offset),
        ))
    }

    fn use_new_ip(&mut self) -> Result<(), AllocatorError> {
        // Retrieve the first available offset
        let offset = self.bitmap.min().ok_or(AllocatorError::NoFreeIp)?;
        self.bitmap.remove(offset);

        // For IPv6, the offset does not directly convert to an IP address because the bitmap space
        // is lower than the IPv6 addressing space. Instead, we need to map the offset to the
        // corresponding address within our list of prefixes.
        let alloc_ip = AllocatedIp::new(self.map_offset(offset)?);

        // Move the new IP to the front of the list of IP in use for allocation
        self.allocated_ips.add_in_use(alloc_ip.clone());
        Ok(())
    }

    fn get_ip(&mut self) -> Result<&mut AllocatedIp<Ipv6Addr>, AllocatorError> {
        // Clean up any full allocated IP address from the list
        self.allocated_ips.pull_first_usable();

        // If we have no entry left, allocate a new one
        if self.allocated_ips.get_first().is_none() {
            self.use_new_ip()?;
        }

        // Return the first entry from the list of available allocated IP addresses
        self.allocated_ips
            .get_first_mut()
            .ok_or(AllocatorError::NoFreeIp)
    }
}

#[derive(Debug, Clone)]
struct AllocatedIp<I: NatIp> {
    ip: I,
    port_allocator: PortBlockAllocator,
}

impl<I: NatIp> AllocatedIp<I> {
    fn new(ip: I) -> Self {
        Self {
            ip,
            port_allocator: PortBlockAllocator::new(),
        }
    }

    fn ip(&self) -> I {
        self.ip
    }

    fn allocate_port(&mut self) -> Result<NatPort, AllocatorError> {
        self.port_allocator.allocate_port()
    }
}
