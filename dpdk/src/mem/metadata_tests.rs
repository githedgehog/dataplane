// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::test_support::packet_pool;
use net::buffer::DeepCopy;

#[test]
fn rss_and_mark_have_independent_values_and_validity() {
    let pool = packet_pool(3);
    let mut mbuf = pool.alloc_bulk(1).unwrap().into_iter().next().unwrap();
    let rss = u64::from(dpdk_sys::RTE_MBUF_F_RX_RSS_HASH);
    let mark = u64::from(dpdk_sys::RTE_MBUF_F_RX_FDIR_ID);
    let matched = u64::from(dpdk_sys::RTE_MBUF_F_RX_FDIR);
    for (hash, id) in [(0, 0), (0x1234_5678, 0xfeed_beef), (u32::MAX, 1)] {
        // SAFETY: the test owns the mbuf; RSS and MARK occupy separate union slots.
        unsafe {
            let raw = mbuf.raw.as_mut();
            raw.annon2.annon1.annon2.hash.rss = hash;
            raw.annon2.annon1.annon2.hash.fdir.hi = id;
        }
        for (flags, want_hash, want_mark) in [
            (0, None, None),
            (matched, None, None),
            (rss, Some(hash), None),
            (matched | mark, None, Some(id)),
            (rss | matched | mark, Some(hash), Some(id)),
        ] {
            // SAFETY: only receive flags on an exclusively owned, direct mbuf are changed.
            unsafe { mbuf.raw.as_mut().ol_flags = flags };
            assert_eq!(mbuf.ol_flags(), flags);
            assert_eq!(mbuf.rss_hash(), want_hash);
            assert_eq!(mbuf.rx_mark(), want_mark);
            let copy = mbuf.deep_copy().unwrap();
            assert_eq!(copy.rss_hash(), want_hash);
            assert_eq!(copy.rx_mark(), want_mark);
        }
    }
    drop(mbuf);
    for mbuf in pool.alloc_bulk(3).unwrap() {
        assert_eq!(mbuf.rss_hash(), None);
        assert_eq!(mbuf.rx_mark(), None);
    }
}

#[test]
fn eal_registers_meta_and_presence_is_separate_from_value() {
    let pool = packet_pool(3);
    let mut mbuf = pool.alloc_bulk(1).unwrap().into_iter().next().unwrap();
    // SAFETY: creating the pool initialized EAL, which registers metadata once.
    let mask = unsafe { dpdk_sys::rte_flow_dynf_metadata_mask };
    assert_ne!(mask, 0);
    assert_eq!(mbuf.rx_meta(), None);
    for value in [0, 0xdead_beef, u32::MAX] {
        // SAFETY: EAL registered the field and the test exclusively owns this mbuf.
        // Use DPDK's C setter to check the Rust getter's offset and value handling.
        unsafe {
            dpdk_sys::rte_flow_dynf_metadata_set(mbuf.raw.as_ptr(), value);
            mbuf.raw.as_mut().ol_flags &= !mask;
        }
        assert_eq!(mbuf.rx_meta(), None);
        // SAFETY: only the receive metadata flag on this owned mbuf is changed.
        unsafe { mbuf.raw.as_mut().ol_flags |= mask };
        assert_eq!(mbuf.rx_meta(), Some(value));
        let copy = mbuf.deep_copy().unwrap();
        assert_eq!(copy.rx_meta(), Some(value));
    }
    drop(mbuf);
    // Allocating the entire pool checks that recycled buffers hide stale metadata.
    for mbuf in pool.alloc_bulk(3).unwrap() {
        assert_eq!(mbuf.rx_meta(), None);
    }
}
