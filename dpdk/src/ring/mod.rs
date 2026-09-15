// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::socket;
use core::ffi::{c_int, c_uint};
use core::marker::PhantomData;
use core::ptr::NonNull;
use errno::{Errno, ErrorCode, StandardErrno};
use std::ffi::CString;

#[allow(unused)]
#[derive(Debug)]
pub struct Ring<T> {
    inner: NonNull<dpdk_sys::rte_ring>,
    params: CheckedParams,
    marker: PhantomData<dpdk_sys::rte_ring>,
    marker2: PhantomData<T>,
}

#[derive(Debug, Clone)]
pub struct Params {
    pub name: String,
    pub size: usize,
    pub socket_preference: socket::Preference,
}

#[repr(transparent)]
#[derive(Debug, Clone)]
struct CheckedParams(Params);

#[allow(unused)]
impl CheckedParams {
    fn name(&self) -> &str {
        self.0.name.as_str()
    }

    fn size(&self) -> usize {
        self.0.size
    }
}

impl Params {
    pub const MAX_NAME_LENGTH: usize = 127;

    #[allow(unused)]
    #[cold]
    fn validate(self) -> Result<CheckedParams, err::InvalidArgument> {
        if !self.size.is_power_of_two() {
            return Err(err::InvalidArgument::SizeNotPowerOfTwo(self));
        }
        if !self.name.is_ascii() {
            return Err(err::InvalidArgument::NameNotAscii(self));
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(err::InvalidArgument::IllegalCharacters(self));
        }
        if self.name.len() > Params::MAX_NAME_LENGTH {
            return Err(err::InvalidArgument::NameTooLong(self));
        }
        Ok(CheckedParams(self))
    }
}

impl<T> Ring<T> {
    #[allow(unused)]
    fn new(params: Params) -> Result<Self, err::RingCreateErr> {
        /// TODO: figure out why musl builds don't expose E_RTE_NO_CONFIG
        /// likely a config error for bindgen
        // use dpdk_sys::_bindgen_ty_4::E_RTE_NO_CONFIG;
        const E_RTE_NO_CONFIG: u64 = 1002;
        use err::RingCreateErr::*;
        let params = params.validate().map_err(InvalidArgument)?;
        let name = CString::new(params.name())
            .unwrap_or_else(|_| unreachable!("null characters already excluded"));
        let socket_id = socket::SocketId::try_from(params.0.socket_preference).map_err(|e| {
            UnableToDetermineNumaNode {
                params: params.0.clone(),
                code: e,
            }
        })?;

        /// TODO: expose ring SP vs MC flags from dpdk-sys
        // For now, 0x1 | 0x2 yields a single-producer, single-consumer queue
        const FLAGS: c_uint = 0x1 | 0x2;
        let inner = match NonNull::new(unsafe {
            dpdk_sys::rte_ring_create(
                name.as_ptr(),
                params.size() as c_uint,
                socket_id.0 as c_int,
                FLAGS,
            )
        }) {
            None => {
                let errno = Errno::from(unsafe { dpdk_sys::rte_errno_get() });
                if errno.0 == E_RTE_NO_CONFIG as i32 {
                    return Err(NoConfig(params.0));
                }
                return match ErrorCode::parse_errno(errno) {
                    ErrorCode::Standard(StandardErrno::InvalidArgument) => Err(InvalidArgument(
                        err::InvalidArgument::SizeNotPowerOfTwo(params.0),
                    )),
                    ErrorCode::Standard(StandardErrno::NoSpaceLeftOnDevice) => {
                        Err(NotEnoughMemZones(params.0))
                    }
                    ErrorCode::Standard(StandardErrno::FileExists) => Err(MemZoneExists(params.0)),
                    ErrorCode::Standard(StandardErrno::NoMemory) => {
                        Err(UnableToAllocateMemZone(params.0))
                    }
                    code => Err(UnexpectedErrno {
                        code,
                        params: params.0,
                    }),
                };
            }
            Some(ring_ptr) => ring_ptr,
        };
        Ok(Self {
            inner,
            params,
            marker: PhantomData,
            marker2: PhantomData,
        })
    }
}

impl<T> Drop for Ring<T> {
    /// Free the ring, releasing its memzone.
    ///
    /// Without this the ring leaked unconditionally: `rte_ring_create` reserves a named memzone
    /// and nothing in this crate ever called `rte_ring_free`, so the name stayed taken for the
    /// life of the process and a second ring with the same name failed with
    /// [`MemZoneExists`](err::RingCreateErr::MemZoneExists).
    fn drop(&mut self) {
        // SAFETY: `self.inner` came from a successful `rte_ring_create` and is freed exactly once,
        // since `Ring` is neither `Copy` nor `Clone`.
        unsafe { dpdk_sys::rte_ring_free(self.inner.as_ptr()) };
    }
}

pub mod err {
    use crate::ring::Params;
    use errno::ErrorCode;

    #[derive(thiserror::Error, Debug)]
    pub enum InvalidArgument {
        #[error("size must be a power of two ({size} given)", size=.0.size)]
        SizeNotPowerOfTwo(Params),
        #[error("ring name must be ASCII")]
        NameNotAscii(Params),
        #[error("only alphanumeric ring names are supported (may contain -, _, and .)")]
        IllegalCharacters(Params),
        #[error("name too long (max is 127 ASCII characters)")]
        NameTooLong(Params),
    }

    #[derive(thiserror::Error, Debug)]
    pub enum RingCreateErr {
        #[error("function could not get pointer to rte_config structure")]
        NoConfig(Params),
        #[error(transparent)]
        InvalidArgument(InvalidArgument),
        #[error("unable to determine NUMA node: {code:?}")]
        UnableToDetermineNumaNode { code: ErrorCode, params: Params },
        #[error("insufficient memory zones to create ring")]
        NotEnoughMemZones(Params),
        #[error("memZone with name '{name}' already exists", name=.0.name)]
        MemZoneExists(Params),
        #[error("unable to allocate MemZone")]
        UnableToAllocateMemZone(Params),
        #[error("unexpected error code: {code:?}")]
        UnexpectedErrno { code: ErrorCode, params: Params },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::with_eal;

    fn params(name: &str) -> Params {
        Params {
            name: name.to_string(),
            size: 64,
            socket_preference: socket::Preference::CurrentThread,
        }
    }

    /// The oracle for `Drop`: a ring's name is a process-global memzone name, so it can only be
    /// reused if the first ring's memzone was actually released. Without `rte_ring_free` the
    /// second create fails with `MemZoneExists`.
    #[test]
    #[with_eal]
    fn dropping_a_ring_releases_its_name() {
        let first = Ring::<u8>::new(params("reuse_ring")).expect("first create should succeed");
        // Same name while the first is alive: refused, which is what makes this a real test of
        // release rather than of nothing.
        match Ring::<u8>::new(params("reuse_ring")) {
            Err(err::RingCreateErr::MemZoneExists(_)) => {}
            Err(other) => panic!("expected MemZoneExists, got {other:?}"),
            Ok(_) => panic!("two live rings must not share a name"),
        }

        drop(first);

        Ring::<u8>::new(params("reuse_ring"))
            .expect("the name should be free again once the first ring is dropped");
    }

    /// Rings are independent: dropping one does not disturb another.
    #[test]
    #[with_eal]
    fn rings_are_released_independently() {
        let a = Ring::<u8>::new(params("indep_ring_a")).expect("create a");
        let b = Ring::<u8>::new(params("indep_ring_b")).expect("create b");
        drop(a);
        // `b` is still live, so its name is still taken.
        match Ring::<u8>::new(params("indep_ring_b")) {
            Err(err::RingCreateErr::MemZoneExists(_)) => {}
            other => panic!("expected b's name to still be taken, got {other:?}"),
        }
        // ...and a's is free.
        Ring::<u8>::new(params("indep_ring_a")).expect("a's name should be free");
        drop(b);
    }

    #[test]
    #[with_eal]
    fn a_non_power_of_two_size_is_rejected() {
        let mut p = params("bad_size_ring");
        p.size = 63;
        match Ring::<u8>::new(p) {
            Err(err::RingCreateErr::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }
}
