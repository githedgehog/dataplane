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
