// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Object to represent port ranges for port-forwarding and methods

#![allow(unused)] // Temporary

use super::PortFwTableError;
use std::fmt::Display;
use std::num::NonZero;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PortRange {
    first: NonZero<u16>,
    last: NonZero<u16>,
}

impl Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_singleton() {
            write!(f, "{}", self.first)
        } else {
            write!(f, "[{}-{}]", self.first, self.last)
        }
    }
}

impl PortRange {
    /// Create a `PortRange` from two `u16`. Both must be non-zero and well-ordered
    ///
    /// # Errors
    ///
    /// Returns `PortFwTableError` if any of the ports is zero or last is smaller than first
    pub fn new(first: u16, last: u16) -> Result<Self, PortFwTableError> {
        if last < first {
            Err(PortFwTableError::InvalidPortRange(first, last))
        } else {
            let first =
                NonZero::try_from(first).map_err(|_| PortFwTableError::InvalidPort(first))?;
            let last = NonZero::try_from(last).map_err(|_| PortFwTableError::InvalidPort(last))?;
            Ok(Self { first, last })
        }
    }

    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    /// Returns number of ports contained in a `PortRange`
    pub fn len(self) -> u16 {
        self.last.get() - self.first.get() + 1
    }

    #[must_use]
    /// Returns true if a `PortRange` contains a single port
    pub fn is_singleton(self) -> bool {
        self.last == self.first
    }

    #[must_use]
    /// Returns a port at a certain index within the `PortRange` if the index is within the bounds
    pub fn get_port_at(self, index: u16) -> Option<NonZero<u16>> {
        if index >= self.len() {
            None
        } else {
            NonZero::new(self.first.get() + index)
        }
    }

    #[must_use]
    /// Tell if a given port is contained within this `PortRange`
    pub fn contains(&self, port: NonZero<u16>) -> bool {
        port >= self.first && port <= self.last
    }

    #[must_use]
    /// Returns the index of a port within a `PortRange` if it is contained in the range
    pub fn indexof(self, port: NonZero<u16>) -> Option<u16> {
        if self.contains(port) {
            Some(port.get() - self.first.get())
        } else {
            None
        }
    }

    #[must_use]
    /// Given a `PortRange` and a port, provide the corresponding port in another `PortRange`,
    /// provided that the port falls within ranges. Both ranges need to be of the same size.
    pub fn map_port_to(self, port: NonZero<u16>, other: Self) -> Option<NonZero<u16>> {
        debug_assert!(self.len() == other.len());
        let index = self.indexof(port)?;
        other.get_port_at(index)
    }

    #[must_use]
    /// Tell if this `PortRange` overlaps with another
    pub fn overlaps_with(&self, other: Self) -> bool {
        other.contains(self.first) || other.contains(self.last)
    }
}

#[cfg(test)]
mod test {
    use std::num::NonZero;

    use super::PortFwTableError;
    use super::PortRange;

    #[test]
    fn test_port_range_checks() {
        assert!(PortRange::new(0, 0).is_err_and(|e| e == PortFwTableError::InvalidPort(0)));
        assert!(PortRange::new(0, 1).is_err_and(|e| e == PortFwTableError::InvalidPort(0)));
        assert!(PortRange::new(2, 1).is_err_and(|e| e == PortFwTableError::InvalidPortRange(2, 1)));
        assert!(PortRange::new(1, 1).is_ok());
    }

    #[test]
    fn test_port_range_methods_single_port() {
        let range = PortRange::new(100, 100).unwrap();
        assert_eq!(range.len(), 1);
        assert!(range.is_singleton());
        assert_eq!(range.indexof(100.try_into().unwrap()), Some(0));
        assert_eq!(range.get_port_at(0), Some(100.try_into().unwrap()));
        assert!(range.get_port_at(1).is_none());
    }

    #[test]
    fn test_port_range_methods_multiple_ports() {
        let range = PortRange::new(100, 200).unwrap();
        assert_eq!(range.len(), 101);
        assert!(!range.is_singleton());
        assert_eq!(range.indexof(100.try_into().unwrap()), Some(0));
        assert_eq!(range.get_port_at(0), Some(100.try_into().unwrap()));

        assert_eq!(range.indexof(200.try_into().unwrap()), Some(100));
        assert_eq!(range.get_port_at(100), Some(200.try_into().unwrap()));

        assert_eq!(range.indexof(201.try_into().unwrap()), None);
        assert_eq!(range.get_port_at(101), None);
    }

    #[test]
    fn test_port_range_methods_all_ports() {
        let range = PortRange::new(1, u16::MAX).unwrap();
        assert_eq!(range.len(), u16::MAX);
        assert!(!range.is_singleton());

        assert_eq!(range.indexof(100.try_into().unwrap()), Some(100 - 1));
        assert_eq!(range.get_port_at(100 - 1), Some(100.try_into().unwrap()));

        assert_eq!(
            range.indexof(u16::MAX.try_into().unwrap()),
            Some(u16::MAX - 1)
        );
        assert_eq!(
            range.get_port_at(u16::MAX - 1),
            Some(u16::MAX.try_into().unwrap())
        );
    }

    #[test]
    fn test_port_mapping() {
        // mapping between identical ranges
        let range1 = PortRange::new(100, 200).unwrap();
        let range2 = PortRange::new(100, 200).unwrap();
        let port = NonZero::new(100).unwrap();
        let mapped = range1.map_port_to(port, range2).unwrap();
        assert_eq!(port, mapped);

        // mapping between distinct, disjoint ranges
        let range1 = PortRange::new(100, 200).unwrap();
        let range2 = PortRange::new(1100, 1200).unwrap();
        let port = NonZero::new(100).unwrap();
        let mapped = range1.map_port_to(port, range2).unwrap();
        assert_eq!(mapped.get(), 1100);

        // mapping between distinct, overlapping ranges
        let range1 = PortRange::new(100, 200).unwrap();
        let range2 = PortRange::new(150, 250).unwrap();
        let port = NonZero::new(100).unwrap();
        let mapped = range1.map_port_to(port, range2).unwrap();
        assert_eq!(mapped.get(), 150);
        let port = NonZero::new(200).unwrap();
        let mapped = range1.map_port_to(port, range2).unwrap();
        assert_eq!(mapped.get(), 250);

        // single port ranges
        let range1 = PortRange::new(80, 80).unwrap();
        let range2 = PortRange::new(8080, 8080).unwrap();
        let port = NonZero::new(80).unwrap();
        let mapped = range1.map_port_to(port, range2).unwrap();
        assert_eq!(mapped.get(), 8080);
    }
}
