// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for allocator types

use super::alloc::{AllocatedIp, IpAllocator, NatPool};
use super::port_alloc::PortAllocator;
use super::{NatAllocator, NatIp, NatIpWithBitmap, PoolTable, PoolTableKey};
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

        #[cfg(test)]
        if self.disable_randomness {
            writeln!(f, "[randomness disabled]")?;
        }

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
    I: NatIp + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{} | dest VPC: {}, for IPs: [ {} .. {} ]",
            self.protocol, self.dst_id, self.addr, self.addr_range_end
        )
    }
}

impl<I> Display for IpAllocator<I>
where
    I: NatIpWithBitmap + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let pool = self.read().map_err(|_| Error)?;
        write!(f, "{pool}")
    }
}

impl<I> Display for NatPool<I>
where
    I: NatIpWithBitmap + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(f, "idle timeout: {:?}", self.idle_timeout())?;

        if let Some(reserved) = self.reserved_prefixes_ports() {
            writeln!(f, "reserved ranges:")?;
            for (ips, ports) in reserved {
                writeln!(with_indent!(f), "{ips}:{ports}")?;
            }
        }

        writeln!(f, "IP ranges in pool:")?;
        for range in self.ips_in_bitmap().map_err(|()| Error)? {
            writeln!(with_indent!(f), "{range}")?;
        }

        writeln!(f, "allocated IPs:")?;
        let (mut found, mut dropped) = (false, 0u32);
        for weak_ip in self.ips_in_use() {
            if let Some(ip) = weak_ip.upgrade() {
                write!(with_indent!(f), "{}", *ip)?;
                found = true;
            } else {
                dropped += 1;
            }
        }
        if dropped > 0 {
            writeln!(with_indent!(f), "<{dropped} weak references dropped>")?;
        } else if !found {
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
        if let Some(reserved) = self.reserved_port_range() {
            writeln!(f, "reserved port range: {reserved}")?;
        }

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
