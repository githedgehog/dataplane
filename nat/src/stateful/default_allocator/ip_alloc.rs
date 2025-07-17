// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::AllocatorError;
use super::NatIp;
use super::port_alloc::PortBlockAllocator;
use crate::stateful::port::NatPort;
use roaring::RoaringBitmap;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct NatPool<I: NatIp> {
    bitmap: RoaringBitmap,
    bitmap_mapping: BTreeMap<u32, u128>,
    in_use: Vec<AllocatedIp<I>>,
    full: Vec<AllocatedIp<I>>,
}

impl<I: NatIp> NatPool<I> {
    pub fn new() -> Self {
        Self {
            bitmap: RoaringBitmap::new(),
            bitmap_mapping: BTreeMap::new(),
            in_use: Vec::new(),
            full: Vec::new(),
        }
    }
}

impl NatPool<Ipv4Addr> {
    pub fn allocate(&mut self) -> Result<(Ipv4Addr, NatPort), AllocatorError> {
        let ip = self.get_ip()?;
        let port = ip.allocate_port()?;

        Ok((ip.ip(), port))
    }

    fn get_new_ip(&mut self) -> Result<&mut AllocatedIp<Ipv4Addr>, AllocatorError> {
        // Retrieve the first available IP address
        let offset = self.bitmap.min().ok_or(AllocatorError::NoFreeIp)?;
        self.bitmap.remove(offset);
        let alloc_ip = AllocatedIp::new(Ipv4Addr::from(offset));

        // Make it the current IP to process
        self.in_use.push(alloc_ip.clone());
        let ip = self
            .in_use
            .last_mut()
            .ok_or(AllocatorError::InternalIssue)?;

        Ok(ip)
    }

    fn get_ip(&mut self) -> Result<&mut AllocatedIp<Ipv4Addr>, AllocatorError> {
        if let Some(ip) = self.in_use.first() {
            if ip.port_allocator.has_usable_blocks() {
                return self.in_use.first_mut().ok_or(AllocatorError::InternalIssue);
            }
        }
        self.get_new_ip()
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

    fn get_new_ip(&mut self) -> Result<&mut AllocatedIp<Ipv6Addr>, AllocatorError> {
        // Retrieve the first available offset
        let offset = self.bitmap.min().ok_or(AllocatorError::NoFreeIp)?;
        self.bitmap.remove(offset);

        // For IPv6, the offset does not directly convert to an IP address because the bitmap space
        // is lower than the IPv6 addressing space. Instead, we need to map the offset to the
        // corresponding address within our list of prefixes.
        let alloc_ip = AllocatedIp::new(self.map_offset(offset)?);

        // Make it the current IP to process
        self.in_use.push(alloc_ip.clone());
        let ip = self
            .in_use
            .last_mut()
            .ok_or(AllocatorError::InternalIssue)?;
        Ok(ip)
    }

    fn get_ip(&mut self) -> Result<&mut AllocatedIp<Ipv6Addr>, AllocatorError> {
        if let Some(ip) = self.in_use.first() {
            if ip.port_allocator.has_usable_blocks() {
                return self.in_use.first_mut().ok_or(AllocatorError::InternalIssue);
            }
        }
        self.get_new_ip()
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
