// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::test_support::{RingPort, start_eal};

/// Marks a port as owned so `rte_eth_find_next_owned_by` skips it, and unmarks it on drop.
struct Owned(crate::dev::DevIndex, u64);

impl Owned {
    fn new(port: crate::dev::DevIndex) -> Owned {
        let mut id = 0;
        // SAFETY: plain FFI calls; `record` is a valid owner struct for the duration of the call.
        unsafe {
            assert_eq!(dpdk_sys::rte_eth_dev_owner_new(&raw mut id), 0);
            let mut record: dpdk_sys::rte_eth_dev_owner = core::mem::zeroed();
            record.id = id;
            for (dst, src) in record.name.iter_mut().zip(c"iter_tests".to_bytes()) {
                *dst = *src as core::ffi::c_char;
            }
            assert_eq!(
                dpdk_sys::rte_eth_dev_owner_set(port.0, &raw const record),
                0
            );
        }
        Owned(port, id)
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: plain FFI calls on the port and owner id set up in `new`.
        unsafe {
            assert_eq!(dpdk_sys::rte_eth_dev_owner_unset(self.0.0, self.1), 0);
            assert_eq!(dpdk_sys::rte_eth_dev_owner_delete(self.1), 0);
        }
    }
}

#[test]
fn iteration_yields_the_port_it_found_after_an_owned_port() {
    let shared = start_eal();
    let first = RingPort::new();
    let second = first.another();
    assert!(first.index < second.index);
    let _owned = Owned::new(first.index);

    let available: Vec<_> = shared.dev().iter().map(|dev| dev.index()).collect();
    assert_eq!(available, [second.index]);
}
