// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::{Mbuf, Pool};
use crate::test_support::{available, packet_pool};
use net::buffer::{
    Append, DeepCopy, PacketLength, Tailroom, TestBuffer, TrimFromEnd, TrimFromStart,
};

fn chain<'eal>(pool: &Pool<'eal>, segments: &[&[u8]]) -> Mbuf<'eal> {
    assert!(!segments.is_empty());
    let mut bufs = pool.alloc_bulk(segments.len()).unwrap().into_iter();
    let mut head = bufs.next().unwrap();
    head.append(segments[0].len().try_into().unwrap())
        .unwrap()
        .copy_from_slice(segments[0]);
    for (mut tail, data) in bufs.zip(&segments[1..]) {
        tail.append(data.len().try_into().unwrap())
            .unwrap()
            .copy_from_slice(data);
        // SAFETY: both chains are uniquely owned; success transfers tail ownership to head.
        unsafe {
            assert_eq!(
                dpdk_sys::rte_pktmbuf_chain(head.raw.as_ptr(), tail.raw.as_ptr()),
                0
            );
        }
        let _ = tail.into_raw();
    }
    head
}

fn segments(mbuf: &Mbuf) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut raw = mbuf.raw.as_ptr();
    while !raw.is_null() {
        // SAFETY: mbuf owns the complete live chain, borrowed only for reading here.
        unsafe {
            let seg = &*raw;
            let start = seg
                .buf_addr
                .cast::<u8>()
                .add(seg.annon1.annon1.data_off as usize);
            result.push(
                core::slice::from_raw_parts(start, seg.annon2.annon1.data_len as usize).to_vec(),
            );
            raw = seg.next;
        }
    }
    result
}

#[test]
fn chain_views_and_tail_edits_address_the_correct_segment() {
    let pool = packet_pool(7);
    let mut mbuf = chain(&pool, &[&[1, 2], &[3, 4, 5]]);
    assert_eq!(mbuf.as_ref(), &[1, 2]);
    assert_eq!(mbuf.as_mut(), &[1, 2]);
    assert_eq!(mbuf.packet_len(), 5);
    assert_eq!(mbuf.tailroom(), 2048 - 128 - 3);
    let tail = mbuf.append(2).unwrap();
    assert_eq!(&tail[..3], &[3, 4, 5]);
    tail[3..].copy_from_slice(&[6, 7]);
    assert_eq!(mbuf.packet_len(), 7);
    assert_eq!(mbuf.trim_from_end(1).unwrap(), &[3, 4, 5, 6]);
    assert_eq!(segments(&mbuf), [vec![1, 2], vec![3, 4, 5, 6]]);
}

#[test]
fn deep_copy_preserves_all_bytes_and_survives_source_drop() {
    let pool = packet_pool(15);
    for input in [
        vec![vec![]],
        vec![vec![1, 2, 3]],
        vec![vec![1; 1500], vec![2; 1500], vec![3; 1500]],
    ] {
        let refs: Vec<_> = input.iter().map(Vec::as_slice).collect();
        let mut source = chain(&pool, &refs);
        let copy = source.deep_copy().unwrap();
        let expected = input.concat();
        assert_eq!(segments(&copy).concat(), expected);
        assert_eq!(copy.packet_len(), expected.len());
        let mut raw = copy.raw.as_ptr();
        while !raw.is_null() {
            // SAFETY: every copied segment is uniquely owned and contains valid packet data.
            unsafe {
                let seg = &*raw;
                let start = seg
                    .buf_addr
                    .cast::<u8>()
                    .add(seg.annon1.annon1.data_off as usize);
                core::slice::from_raw_parts_mut(start, seg.annon2.annon1.data_len as usize)
                    .fill(0x5a);
                raw = seg.next;
            }
        }
        assert_eq!(segments(&source).concat(), expected);
        source.as_mut().fill(0xa5);
        drop(source);
        assert_eq!(segments(&copy).concat(), vec![0x5a; expected.len()]);
        drop(copy);
        assert_eq!(available(&pool), 15);
    }
}

#[test]
fn deep_copy_failure_reclaims_partial_chains_and_preserves_source() {
    let pool = packet_pool(7);
    let data = [0x5a; 1500];
    let source = chain(&pool, &[&data, &data, &data]);
    let expected = segments(&source);
    // Each source segment needs one destination mbuf.
    for free in 0..3 {
        let held = pool.alloc_bulk(4 - free).unwrap();
        for _ in 0..3 {
            assert!(source.deep_copy().is_err());
            assert_eq!(available(&pool), free);
            assert_eq!(source.packet_len(), 4500);
            assert_eq!(segments(&source), expected);
        }
        drop(held);
    }
    let copy = source.deep_copy().unwrap();
    assert_eq!(available(&pool), 1);
    assert_eq!(segments(&copy).concat(), expected.concat());
    drop(copy);
    drop(source);
    assert_eq!(available(&pool), 7);
}

fn matching_chain<'eal>(pool: &Pool<'eal>, input: &[&[u8]]) -> Mbuf<'eal> {
    let mbuf = chain(pool, input);
    let mut raw = mbuf.raw.as_ptr();
    for (i, data) in input.iter().enumerate() {
        let headroom = if i == 0 { TestBuffer::HEADROOM } else { 0 };
        let tailroom = if i + 1 == input.len() {
            TestBuffer::TAILROOM
        } else {
            0
        };
        // SAFETY: each segment is uniquely owned, and the reduced data room fits its allocation.
        unsafe {
            let seg = &mut *raw;
            let capacity = headroom as usize + data.len() + tailroom as usize;
            assert!(capacity <= seg.annon2.annon1.buf_len as usize);
            seg.annon2.annon1.buf_len = capacity.try_into().unwrap();
            seg.annon1.annon1.data_off = headroom;
            core::slice::from_raw_parts_mut(
                seg.buf_addr.cast::<u8>().add(headroom as usize),
                data.len(),
            )
            .copy_from_slice(data);
            raw = seg.next;
        }
    }
    mbuf
}

fn edit_sequence<B>(mut buf: B, input: &[&[u8]], operations: &[(u8, u16)]) -> B
where
    B: net::buffer::PacketBufferMut + Append,
{
    let mut expected: Vec<_> = input.iter().map(|s| s.to_vec()).collect();
    let last = expected.len() - 1;
    let mut headroom = TestBuffer::HEADROOM as usize;
    let mut tailroom = TestBuffer::TAILROOM as usize;
    for &(op, selector) in operations {
        let op = op % 4;
        let limit = match op {
            0 => headroom,
            1 => tailroom,
            2 => expected[0].len(),
            _ => expected[last].len(),
        };
        let len = match selector % 4 {
            0 => 0,
            1 => limit,
            2 => limit + 1,
            _ => selector as usize % (limit + 2),
        };
        let result = match op {
            0 => buf.prepend(len as u16).map_err(|_| ()),
            1 => buf.append(len as u16).map_err(|_| ()),
            2 => buf.trim_from_start(len as u16).map_err(|_| ()),
            _ => buf.trim_from_end(len as u16).map_err(|_| ()),
        };
        assert_eq!(
            result.is_ok(),
            len <= limit,
            "op={op}, len={len}, limit={limit}"
        );
        if let Ok(slice) = result {
            let affected = if op == 0 || op == 2 { 0 } else { last };
            match op {
                0 => {
                    assert_eq!(&slice[len..], &expected[0]);
                    slice[..len].fill(0xa5);
                    expected[0].splice(..0, vec![0xa5; len]);
                    headroom -= len;
                }
                1 => {
                    let old_len = expected[last].len();
                    assert_eq!(&slice[..old_len], &expected[last]);
                    slice[old_len..].fill(0x5a);
                    expected[last].extend(vec![0x5a; len]);
                    tailroom -= len;
                }
                2 => {
                    expected[0].drain(..len);
                    headroom += len;
                }
                _ => {
                    let new_len = expected[last].len() - len;
                    expected[last].truncate(new_len);
                    tailroom += len;
                }
            }
            assert_eq!(slice, expected[affected]);
        }
        assert_eq!(buf.as_ref(), expected[0]);
        assert_eq!(buf.append(0).unwrap(), expected[last]);
        assert_eq!(
            buf.packet_len(),
            expected.iter().map(Vec::len).sum::<usize>()
        );
        assert_eq!(buf.headroom() as usize, headroom);
        assert_eq!(buf.tailroom() as usize, tailroom);
    }
    buf
}

fn mbuf_edit_sequence(pool: &Pool<'static>, input: &[&[u8]], steps: &[(u8, u16)]) {
    let mbuf = edit_sequence(matching_chain(pool, input), input, steps);
    let mut raw = mbuf.raw.as_ptr();
    while !raw.is_null() {
        // SAFETY: restore the pool's real data-room size before returning these owned segments.
        // DPDK allocation resets packet fields but preserves buf_len.
        unsafe {
            (*raw).annon2.annon1.buf_len = 2048;
            raw = (*raw).next;
        }
    }
}

#[test]
fn edit_boundaries_match_the_byte_model() {
    let pool = packet_pool(7);
    for input in [
        vec![&[][..]],
        vec![&[1, 2, 3][..]],
        vec![&[1, 2][..], &[][..], &[3, 4, 5][..]],
    ] {
        for op in 0..4 {
            for selector in 0..3 {
                let steps = [(op, selector), (op, 2), (op, 0)];
                mbuf_edit_sequence(&pool, &input, &steps);
                assert_eq!(available(&pool), 7);
            }
        }
    }
}

#[test]
fn generated_edits_match_the_byte_model() {
    let pool = packet_pool(7);
    bolero::check!()
        .with_type::<([u8; 3], [(u8, u16); 32])>()
        .for_each(|(lengths, steps)| {
            let data: Vec<_> = lengths
                .iter()
                .enumerate()
                .map(|(i, len)| vec![i as u8 + 1; (*len % 32) as usize])
                .collect();
            let input: Vec<_> = data.iter().map(Vec::as_slice).collect();
            mbuf_edit_sequence(&pool, &input, steps);
            assert_eq!(available(&pool), 7);
        });
}

fn frame() -> Vec<u8> {
    net::packet::test_utils::build_test_ipv4_packet(64)
        .unwrap()
        .serialize()
        .unwrap()
        .as_ref()
        .to_vec()
}

#[test]
fn packet_copy_propagates_pool_exhaustion() {
    let pool = packet_pool(7);
    let bytes = frame();
    let packet = net::packet::Packet::new(chain(&pool, &[&bytes])).unwrap();
    let before = segments(packet.payload());
    let held = pool.alloc_bulk(6).unwrap();
    assert!(packet.deep_copy().is_err());
    assert_eq!(segments(packet.payload()), before);
    assert_eq!(available(&pool), 0);
    drop(held);
    let copy = packet.deep_copy().unwrap();
    assert_eq!(segments(copy.payload()).concat(), before.concat());
    drop(copy);
    drop(packet);
    assert_eq!(available(&pool), 7);
}

fn packet_copy_and_roundtrip<B>(buffer: B, bytes: &[u8])
where
    B: net::buffer::PacketBufferMut + DeepCopy,
{
    use net::headers::{TryHeaders, TryIpv4, TryIpv4Mut};
    use net::packet::{Packet, TestMeta};

    let mut packet = Packet::new(buffer).unwrap();
    let payload_len = bytes.len() - packet.header_len().get() as usize;
    assert_eq!(packet.payload_len() as usize, payload_len);
    assert_eq!(packet.total_len() as usize, bytes.len());
    packet.meta_mut().vrf = Some(42);
    packet.meta_mut().src_natted(true);
    packet.meta_mut().test = Some(Box::new(TestMeta { id: 7 }));
    let mut copy = packet.deep_copy().unwrap();
    assert_eq!(copy.headers(), packet.headers());
    assert_eq!(copy.meta().vrf, Some(42));
    assert!(copy.meta().is_src_natted());
    assert_eq!(copy.meta().test.as_ref().unwrap().id, 7);
    copy.meta_mut().vrf = Some(43);
    copy.meta_mut().src_natted(false);
    copy.meta_mut().test.as_mut().unwrap().id = 8;
    copy.try_ipv4_mut().unwrap().set_ttl(31);
    copy.trim_from_start(0).unwrap()[0] ^= 0xff;
    assert_eq!(packet.try_ipv4().unwrap().ttl(), 64);
    assert_eq!(packet.meta().vrf, Some(42));
    assert!(packet.meta().is_src_natted());
    assert_eq!(packet.meta().test.as_ref().unwrap().id, 7);
    assert_eq!(
        packet.payload().as_ref()[0],
        bytes[bytes.len() - payload_len]
    );
    let restored = packet.serialize().unwrap();
    assert_eq!(restored.packet_len(), bytes.len());
    assert_eq!(restored.as_ref(), &bytes[..restored.as_ref().len()]);
    drop(restored);
    assert_eq!(copy.payload_len() as usize, payload_len);
    assert_eq!(copy.try_ipv4().unwrap().ttl(), 31);
    assert_eq!(
        copy.payload().as_ref()[0],
        bytes[bytes.len() - payload_len] ^ 0xff
    );
}

#[test]
fn packet_copy_preserves_headers_and_metadata() {
    let pool = packet_pool(7);
    let bytes = frame();
    packet_copy_and_roundtrip(TestBuffer::from_raw_data(&bytes), &bytes);
    packet_copy_and_roundtrip(chain(&pool, &[&bytes]), &bytes);
    assert_eq!(available(&pool), 7);
}

#[test]
fn packets_reject_chained_mbufs_without_leaking() {
    let pool = packet_pool(7);
    let bytes = frame();
    let input = [&bytes[..64], &bytes[64..900], &bytes[900..]];
    assert!(net::packet::Packet::new(chain(&pool, &input)).is_err());
    assert_eq!(available(&pool), 7);
}

fn vxlan_lengths<B: net::buffer::PacketBufferMut>(buffer: B, frame_len: usize, ipv6: bool) {
    use net::headers::{HeadersBuilder, Net, TryUdp};
    use net::packet::Packet;
    use net::udp::UdpEncap;
    use net::vxlan::{Vni, Vxlan, VxlanEncap};

    let mut ipv4 = net::ipv4::Ipv4::default();
    ipv4.set_source("10.0.0.1".parse().unwrap());
    ipv4.set_destination("10.0.0.2".parse().unwrap());
    ipv4.set_ttl(64);
    ipv4.set_next_header(net::ip::NextHeader::UDP);
    let outer = if ipv6 {
        let mut ip = net::ipv6::Ipv6::default();
        ip.set_source("2001:db8::1".parse().unwrap());
        ip.set_destination("2001:db8::2".parse().unwrap());
        ip.set_hop_limit(64);
        ip.set_next_header(net::ip::NextHeader::UDP);
        Net::Ipv6(ip)
    } else {
        Net::Ipv4(ipv4)
    };
    let headers = HeadersBuilder::default()
        .net(Some(outer))
        .udp_encap(Some(UdpEncap::Vxlan(Vxlan::new(
            Vni::new_checked(200).unwrap(),
        ))))
        .build()
        .unwrap();
    let params = VxlanEncap::new(headers).unwrap();
    let mut packet = Packet::new(buffer).unwrap();
    packet.vxlan_encap(&params).unwrap();
    assert_eq!(packet.payload_len() as usize, frame_len);
    assert_eq!(
        packet.try_udp().unwrap().length().get() as usize,
        frame_len + 16
    );
    let wire = packet.serialize().unwrap();
    let (field, expected, overhead) = if ipv6 {
        (&wire.as_ref()[4..6], frame_len + 16, 56)
    } else {
        (&wire.as_ref()[2..4], frame_len + 36, 36)
    };
    assert_eq!(
        u16::from_be_bytes(field.try_into().unwrap()) as usize,
        expected
    );
    assert_eq!(wire.packet_len(), frame_len + overhead);
}

#[test]
fn vxlan_lengths_include_the_whole_payload() {
    let pool = packet_pool(7);
    let bytes = frame();
    for ipv6 in [false, true] {
        vxlan_lengths(TestBuffer::from_raw_data(&bytes), bytes.len(), ipv6);
        vxlan_lengths(chain(&pool, &[&bytes]), bytes.len(), ipv6);
    }
    assert_eq!(available(&pool), 7);
}
