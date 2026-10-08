// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::{Mbuf, MbufCopyError, Pool};
use crate::test_support::{available, packet_pool, packet_pool_with_data_size};
use net::buffer::{Append, DeepCopy, Headroom, Prepend, Tailroom, TrimFromEnd, TrimFromStart};
use net::packet::Packet;

fn segment<'eal>(pool: &Pool<'eal>, headroom: u16, len: u16, byte: u8) -> Mbuf<'eal> {
    let mut mbuf = pool.alloc_bulk(1).unwrap().into_iter().next().unwrap();
    mbuf.append(mbuf.tailroom()).unwrap();
    mbuf.prepend(mbuf.headroom()).unwrap().fill(byte);
    mbuf.trim_from_start(headroom).unwrap();
    let excess = u16::try_from(mbuf.as_ref().len()).unwrap() - len;
    mbuf.trim_from_end(excess).unwrap();
    mbuf
}

fn append_segment(head: &mut Mbuf, tail: Mbuf) {
    // SAFETY: both chains are live and independently owned; the test chains fit in u16.
    assert_eq!(
        unsafe { dpdk_sys::rte_pktmbuf_chain(head.raw.as_ptr(), tail.raw.as_ptr()) },
        0
    );
    let _ = tail.into_raw();
}

fn layout(mbuf: &Mbuf) -> Vec<(u16, u16, Vec<u8>)> {
    let mut segments = Vec::new();
    let mut next = mbuf.raw.as_ptr();
    // SAFETY: the owner keeps the chain and its data live throughout the walk.
    unsafe {
        while let Some(segment) = next.as_ref() {
            let offset = segment.annon1.annon1.data_off;
            let len = segment.annon2.annon1.data_len;
            let room = segment.annon2.annon1.buf_len;
            let bytes = core::slice::from_raw_parts(
                segment.buf_addr.cast::<u8>().add(usize::from(offset)),
                usize::from(len),
            );
            segments.push((offset, room - offset - len, bytes.to_vec()));
            next = segment.next;
        }
        assert_eq!(
            segments.len(),
            usize::from(mbuf.raw.as_ref().annon1.annon1.nb_segs)
        );
        assert_eq!(
            segments
                .iter()
                .map(|(_, _, bytes)| bytes.len())
                .sum::<usize>(),
            mbuf.raw.as_ref().annon2.annon1.pkt_len as usize,
        );
    }
    segments
}

#[test]
fn deep_copy_preserves_segment_layout() {
    let pool = packet_pool(15);
    let check = |layouts: &[(u16, u16, u8)], drop_source: bool| {
        let &(offset, len, byte) = &layouts[0];
        let mut original = segment(&pool, offset, len, byte);
        for &(offset, len, byte) in &layouts[1..] {
            append_segment(&mut original, segment(&pool, offset, len, byte));
        }
        let expected = layout(&original);
        let copy = original.deep_copy().unwrap();
        assert_ne!(original.raw, copy.raw);
        assert_eq!(layout(&copy), expected);
        assert_eq!(available(&pool), 15 - 2 * layouts.len());
        let remaining = if drop_source {
            drop(original);
            copy
        } else {
            drop(copy);
            original
        };
        assert_eq!(available(&pool), 15 - layouts.len());
        assert_eq!(layout(&remaining), expected);
        drop(remaining);
        assert_eq!(available(&pool), 15);
    };

    for case in [
        vec![(0, 2048, 42)],
        vec![(128, 0, 0)],
        vec![(2048, 0, 0)],
        vec![(270, 4, 1), (0, 2048, 2), (512, 8, 3)],
        vec![(128, 0, 0), (256, 1, 1), (2048, 0, 0)],
    ] {
        check(&case, true);
        check(&case, false);
    }
    bolero::check!()
        .with_type::<(u8, [(u16, u16, u8); 3], bool)>()
        .for_each(|(count, inputs, drop_source)| {
            let cases: Vec<_> = inputs[..usize::from(count % 3 + 1)]
                .iter()
                .map(|&(offset, len, byte)| {
                    let offset = offset % 2049;
                    (offset, len % (2049 - offset), byte)
                })
                .collect();
            check(&cases, *drop_source);
        });
}

#[test]
fn deep_copy_of_a_full_buffer_is_independently_mutable() {
    let pool = packet_pool(7);
    let mut original = segment(&pool, 0, 2048, 42);
    let mut copy = original.deep_copy().unwrap();
    assert_eq!(copy.as_ref(), &[42; 2048]);
    original.as_mut()[0] = 1;
    copy.as_mut()[2047] = 2;
    assert_eq!(copy.as_ref()[0], 42);
    assert_eq!(original.as_ref()[2047], 42);
    drop(original);
    assert_eq!(copy.as_ref()[2047], 2);
    drop(copy);
    assert_eq!(available(&pool), 7);
}

#[test]
fn deep_copy_preserves_room_for_parsed_headers() {
    let pool = packet_pool(7);
    // Ethernet + IPv6 + an 80-byte Hop-by-Hop header + UDP exceeds default mbuf headroom.
    let mut frame = vec![0u8; 14 + 40 + 80 + 8 + 4];
    frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&92u16.to_be_bytes());
    frame[21] = 64;
    frame[22..38].copy_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame[38..54].copy_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame[54] = 17;
    frame[55] = 9;
    frame[134..136].copy_from_slice(&1234u16.to_be_bytes());
    frame[136..138].copy_from_slice(&4321u16.to_be_bytes());
    frame[138..140].copy_from_slice(&12u16.to_be_bytes());
    frame[142..].copy_from_slice(b"data");
    let mut original = segment(&pool, 128, u16::try_from(frame.len()).unwrap(), 0);
    original.as_mut().copy_from_slice(&frame);
    let mut packet = Packet::new(original).unwrap();
    packet.update_checksums();
    let copy = packet.deep_copy().unwrap();
    assert_eq!(packet.header_len().get(), 142);
    assert_eq!(copy.headroom(), packet.headroom());
    assert_eq!(copy.payload().as_ref(), b"data");
    let original = packet.serialize().unwrap();
    let copy = copy.serialize().unwrap();
    assert_eq!(copy.as_ref(), original.as_ref());
    drop(original);
    assert_eq!(&copy.as_ref()[142..], b"data");
    drop(copy);
    assert_eq!(available(&pool), 7);
}

#[test]
fn deep_copy_exhaustion_releases_partial_chains() {
    let pool = packet_pool(7);
    let mut original = segment(&pool, 128, 1800, 1);
    append_segment(&mut original, segment(&pool, 128, 1800, 2));
    append_segment(&mut original, segment(&pool, 128, 1800, 3));
    let expected = layout(&original);
    for free in 0..3 {
        let held = pool.alloc_bulk(4 - free).unwrap();
        assert!(matches!(
            original.deep_copy(),
            Err(MbufCopyError::Exhausted)
        ));
        assert_eq!(available(&pool), free);
        assert_eq!(layout(&original), expected);
        drop(held);
    }
    let copy = original.deep_copy().unwrap();
    assert_eq!(layout(&copy), expected);
    drop(original);
    drop(copy);
    assert_eq!(available(&pool), 7);
}

#[test]
fn deep_copy_uses_each_segments_pool() {
    let small = packet_pool(7);
    let large = packet_pool_with_data_size(7, 4096);
    let mut original = segment(&small, 200, 100, 1);
    append_segment(&mut original, segment(&large, 700, 3000, 2));
    let expected = layout(&original);

    let held = large.alloc_bulk(6).unwrap();
    assert!(matches!(
        original.deep_copy(),
        Err(MbufCopyError::Exhausted)
    ));
    assert_eq!(available(&small), 6);
    assert_eq!(available(&large), 0);
    drop(held);

    let copy = original.deep_copy().unwrap();
    assert_eq!(layout(&copy), expected);
    assert_eq!(available(&small), 5);
    assert_eq!(available(&large), 5);
    drop(original);
    assert_eq!(layout(&copy), expected);
    drop(copy);
    assert_eq!(available(&small), 7);
    assert_eq!(available(&large), 7);
}

#[test]
fn deep_copy_of_indirect_mbuf_preserves_metadata_without_sharing_data() {
    let pool = packet_pool(7);
    let mut original = segment(&pool, 200, 100, 42);
    let indirect = pool.alloc_bulk(1).unwrap().into_iter().next().unwrap();
    let flags = u64::from(dpdk_sys::RTE_MBUF_F_RX_RSS_HASH) | dpdk_sys::RTE_MBUF_F_TX_IPV4;
    // SAFETY: initialize metadata while the original is uniquely owned, then attach
    // the empty indirect mbuf. Both owners keep the shared source data immutable.
    unsafe {
        let raw = original.raw.as_mut();
        raw.annon1.annon1.port = 3;
        raw.annon2.annon1.annon1.packet_type = 0x1234;
        raw.annon2.annon1.vlan_tci = 17;
        raw.annon2.annon1.vlan_tci_outer = 18;
        raw.annon2.annon1.annon2.hash.rss = 0x12345678;
        raw.annon3.tx_offload = 0x9876;
        raw.dynfield1[0] = 0xabcdef;
        raw.ol_flags = flags;
        dpdk_sys::rte_pktmbuf_attach(indirect.raw.as_ptr(), original.raw.as_ptr());
    }
    let mut copy = indirect.deep_copy().unwrap();
    assert_eq!(layout(&copy), layout(&original));
    // SAFETY: all three mbufs are live and only the copy's independent data is mutated.
    unsafe {
        let raw = copy.raw.as_ref();
        assert_ne!(raw.buf_addr, original.raw.as_ref().buf_addr);
        assert_eq!(raw.annon1.annon1.port, 3);
        assert_eq!(raw.annon2.annon1.annon1.packet_type, 0x1234);
        assert_eq!(raw.annon2.annon1.vlan_tci, 17);
        assert_eq!(raw.annon2.annon1.vlan_tci_outer, 18);
        assert_eq!(raw.annon2.annon1.annon2.hash.rss, 0x12345678);
        assert_eq!(raw.annon3.tx_offload, 0x9876);
        assert_eq!(raw.dynfield1[0], 0xabcdef);
        assert_eq!(raw.ol_flags, flags);
        assert_eq!(dpdk_sys::rte_mbuf_refcnt_read(copy.raw.as_ptr()), 1);
        assert_eq!(dpdk_sys::rte_mbuf_refcnt_read(original.raw.as_ptr()), 2);
    }
    copy.as_mut()[0] = 99;
    assert_eq!(original.as_ref(), &[42; 100]);
    assert_eq!(indirect.as_ref(), &[42; 100]);
    drop(indirect);
    drop(original);
    assert_eq!(available(&pool), 6);
    assert_eq!(copy.as_ref()[0], 99);
    drop(copy);
    assert_eq!(available(&pool), 7);
}

#[test]
fn deep_copy_rejects_incompatible_indirect_buffers_without_leaking() {
    for (source_size, pool_size) in [(4096, 2048), (2048, 4096)] {
        let data_pool = packet_pool_with_data_size(7, source_size);
        let descriptor_pool = packet_pool_with_data_size(7, pool_size);
        let direct = segment(&data_pool, 256, source_size - 256, 42);
        let indirect = descriptor_pool
            .alloc_bulk(1)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        // SAFETY: attach an empty mbuf to live data; both source owners remain immutable.
        unsafe { dpdk_sys::rte_pktmbuf_attach(indirect.raw.as_ptr(), direct.raw.as_ptr()) };
        let mut head = segment(&descriptor_pool, 128, 10, 1);
        append_segment(&mut head, indirect);
        let expected = layout(&head);

        assert!(matches!(
            head.deep_copy(),
            Err(MbufCopyError::IncompatibleLayout { source_size: actual_source, pool_size: actual_pool })
                if actual_source == source_size && actual_pool == pool_size,
        ));
        assert_eq!(available(&descriptor_pool), 5);
        assert_eq!(available(&data_pool), 6);
        assert_eq!(layout(&head), expected);
        drop(head);
        drop(direct);
        assert_eq!(available(&descriptor_pool), 7);
        assert_eq!(available(&data_pool), 7);
        let all = descriptor_pool.alloc_bulk(7).unwrap();
        for mbuf in &all {
            assert_eq!(mbuf.headroom() + mbuf.tailroom(), pool_size);
        }
    }
}
