// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for allocator types

use super::alloc::{AllocatedIp, IpAllocator, NatPool, PoolSet};
use super::port_alloc::PortAllocator;
use super::{NatAllocator, NatIp, NatIpWithBitmap, PoolTable, PoolTableKey};
use common::cliprovider::{CliSource, Heading};
use concurrency::sync::{Arc, Weak};
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

        writeln!(f, "randomize: {}", self.randomize)?;

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
            let start = I::try_from_bits(range.start).map_err(|()| Error)?;
            let end = I::try_from_bits(range.end).map_err(|()| Error)?;
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
        // The same hazard the allocation paths guard against, reached by printing the table.
        //
        // The pool holds weak references to the addresses in use; the strong ones belong to the
        // blocks handed out from each. `NatPool`'s own `fmt` upgrades each weak reference to print
        // it, and the guard below is held for all of that. Another thread ending the last flow on
        // an address at that moment leaves one of those upgrades as the only strong reference, and
        // letting it go runs `AllocatedIp::drop` here, which takes this same lock for writing.
        //
        // Holding an upgrade of every address across the guard keeps the ones taken while printing
        // from ever being last. They are released below, once the guard is gone.
        let mut examined: Vec<Arc<AllocatedIp<I>>> = Vec::new();
        let outcome = {
            let pool = self.read();
            examined.extend(pool.ips_in_use().filter_map(Weak::upgrade));
            write!(f, "{pool}")
        };
        drop(examined);
        outcome
    }
}

impl<I> Display for NatPool<I>
where
    I: NatIpWithBitmap + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        if let Some(reserved) = self.reserved_ports() {
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
        let reserved = self.reserved_ports();
        if !reserved.is_empty() {
            writeln!(f, "reserved port ranges:")?;
            for ports in reserved.iter() {
                writeln!(with_indent!(f), "{ports}")?;
            }
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
