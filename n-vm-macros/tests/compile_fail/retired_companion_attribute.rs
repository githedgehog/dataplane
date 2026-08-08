// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A leftover `#[hypervisor]` must be rejected, not ignored.
//!
//! Nothing consumes these attributes any more, so without an explicit check
//! this compiles and the VM quietly boots with the default configuration --
//! the test would appear to ask for an IOMMU and silently not get one.  That
//! is the worst possible outcome for a migration, so it is a hard error that
//! names the replacement.

#[n_vm::test]
#[hypervisor(iommu)]
fn retired_companion_attribute() {}

fn main() {}
