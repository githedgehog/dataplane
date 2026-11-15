// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)]

trait Parse: Sized {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()>;
}

unsafe extern "C" {
    fn opaque(x: u8) -> usize;
}

struct LengthPrefixed;
impl Parse for LengthPrefixed {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()> {
        let n = buf[0] as usize;
        let body = &buf[1..1 + n]; // BAD: packet length field as slice bound
        Ok((LengthPrefixed, 1 + n))
    }
}

struct Indexed;
impl Parse for Indexed {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()> {
        let i = buf[0] as usize;
        let b = buf[i]; // BAD: packet byte as index
        Ok((Indexed, 1))
    }
}

struct HeaderLen;
impl Parse for HeaderLen {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()> {
        let hl = buf[1] as usize;
        let rest = buf.len() - hl; // BAD: underflows when hl > len
        Ok((HeaderLen, rest))
    }
}

struct Alloc;
impl Parse for Alloc {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()> {
        let v: Vec<u8> = Vec::with_capacity(buf[2] as usize * 1024); // BAD: sender picks the allocation
        Ok((Alloc, 3))
    }
}

struct ThroughFfi;
impl Parse for ThroughFfi {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()> {
        let n = unsafe { opaque(buf[0]) };
        let head = &buf[..n]; // BAD: taint passes through the bodiless call
        Ok((ThroughFfi, n))
    }
}

struct CheckedByGet;
impl Parse for CheckedByGet {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()> {
        let n = buf[0] as usize;
        let Some(body) = buf.get(1..n) else {
            return Err(());
        };
        let rest = &buf[n..]; // OK: n checked by get()
        Ok((CheckedByGet, n))
    }
}

struct CheckedByCompare;
impl Parse for CheckedByCompare {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()> {
        let n = buf[0] as usize;
        if n < buf.len() {
            let b = buf[n]; // OK: compared first
        }
        Ok((CheckedByCompare, 1))
    }
}

struct ConstantIndex;
impl Parse for ConstantIndex {
    fn parse(buf: &[u8]) -> Result<(Self, usize), ()> {
        let ty = buf[0]; // OK: constant index
        Ok((ConstantIndex, 1))
    }
}
