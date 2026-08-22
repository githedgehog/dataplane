// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for allocator types

use super::alloc::{AllocatedIp, IpAllocator, PoolSet};
use super::port_alloc::PortAllocator;
use super::{IpAddress, NatAllocator, NatIpWithBitmap, PoolTable, PoolTableKey};
use common::cliprovider::{CliSource, Heading};
use indenter::indented;
use std::fmt::{Display, Error, Formatter, Result, Write};

const INDENT: &str = "  ";
macro_rules! with_indent {
    ($f:expr) => {
        indented($f).with_str(INDENT)
    };
}

impl CliSource for NatAllocator {}

impl Display for NatAllocator {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Heading("Masquerade NAT allocator table").fmt(f)?;

        writeln!(f, "randomize: {}", self.config.randomize())?;

        writeln!(f, "source pools (IPv4):")?;
        writeln!(with_indent!(f), "{}", self.pools_src44)?;
        writeln!(f, "source pools (IPv6):")?;
        writeln!(with_indent!(f), "{}", self.pools_src66)?;
        Ok(())
    }
}

impl<I, J> Display for PoolTable<I, J>
where
    I: NatIpWithBitmap + Display,
    J: NatIpWithBitmap + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        if self.0.is_empty() {
            return writeln!(f, "(empty)");
        }
        for (key, value) in &self.0 {
            writeln!(f, "{key}")?;
            write!(indented(f).with_str(INDENT), "{value}")?;
        }
        Ok(())
    }
}

impl<I> Display for PoolTableKey<I>
where
    I: IpAddress,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{} | source VPC: {}, dest VPC: {}, for IPs: [ {} .. {} ]",
            self.protocol, self.src_vpcd, self.dst_vpcd, self.addr, self.addr_range_end
        )
    }
}

impl<I> Display for PoolSet<I>
where
    I: NatIpWithBitmap + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(f, "idle timeout: {:?}", self.idle_timeout())?;
        let mut empty = true;
        for region in self.regions() {
            empty = false;
            let range = region.range();
            let start = I::try_from_bits(range.start).map_err(|_| Error)?;
            let end = I::try_from_bits(range.end).map_err(|_| Error)?;
            writeln!(f, "region [ {start} .. {end} ]:")?;
            write!(with_indent!(f), "{}", region.allocator())?;
        }
        if empty {
            writeln!(f, "(no region)")?;
        }
        Ok(())
    }
}

impl<I> Display for IpAllocator<I>
where
    I: NatIpWithBitmap + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        //
        //
        let snapshot = {
            let pool = self.read();
            let ranges = pool.ips_in_bitmap().map_err(|()| Error)?;
            let mut live = Vec::new();
            let mut dropped = 0u32;
            for weak in pool.ips_in_use() {
                match weak.upgrade() {
                    Some(ip) => live.push(ip),
                    None => dropped += 1,
                }
            }
            (ranges, live, dropped)
        };
        let (ranges, live, dropped) = snapshot;

        writeln!(f, "IP ranges in pool:")?;
        for range in &ranges {
            writeln!(with_indent!(f), "{range}")?;
        }

        writeln!(f, "allocated IPs:")?;
        for ip in &live {
            write!(with_indent!(f), "{}", **ip)?;
        }
        if dropped > 0 {
            writeln!(with_indent!(f), "<{dropped} weak references dropped>")?;
        } else if live.is_empty() {
            writeln!(with_indent!(f), "(empty)")?;
        }
        Ok(())
    }
}

impl<I> Display for AllocatedIp<I>
where
    I: NatIpWithBitmap + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(f, "{}:", self.ip())?;
        write!(with_indent!(f), "{}", self.port_allocator())?;
        Ok(())
    }
}

impl<I> Display for PortAllocator<I>
where
    I: NatIpWithBitmap + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(f, "allocated ports:")?;
        if !self.has_free_ports() {
            return writeln!(with_indent!(f), "[all ports allocated]");
        }
        let allocated_port_ranges = self.allocated_port_ranges();
        if allocated_port_ranges.is_empty() {
            return writeln!(with_indent!(f), "(empty)");
        }
        write!(f, "{INDENT}")?;
        for (index, range) in allocated_port_ranges.iter().enumerate() {
            if index > 0 {
                write!(f, ", ")?;
                if index.is_multiple_of(16) {
                    write!(f, "\n{INDENT}")?;
                }
            }
            if range.start() == range.end() {
                write!(f, "{}", range.start())?;
            } else {
                write!(f, "{range}")?;
            }
        }
        writeln!(f)?;
        Ok(())
    }
}
