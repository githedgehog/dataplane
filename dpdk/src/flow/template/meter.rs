// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Meter profiles and the meters (`METER_MARK` indirect actions) that use them.

use alloc::string::{String, ToString};
use core::ffi::CStr;
use core::marker::PhantomData;
use core::ptr::{NonNull, from_ref};

use dpdk_sys::{
    rte_flow_action, rte_flow_action_handle, rte_flow_action_handle_create,
    rte_flow_action_handle_destroy, rte_flow_action_meter_mark, rte_flow_action_type as at,
    rte_flow_error, rte_flow_indir_action_conf, rte_flow_meter_profile, rte_mtr_algorithm,
    rte_mtr_error, rte_mtr_meter_profile, rte_mtr_meter_profile_add, rte_mtr_meter_profile_delete,
    rte_mtr_meter_profile_get,
};
use errno::ErrorCode;
use tracing::warn;

use crate::dev::DevIndex;
use crate::flow::{Direction, Domain, FlowError};

/// What a profile's rates and sizes count.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MeterUnit {
    /// Rates in bytes per second, sizes in bytes.
    Bytes,
    /// Rates in packets per second, sizes in packets.
    Packets,
}

/// A metering algorithm and its parameters, in the profile's [`MeterUnit`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MeterAlgorithm {
    /// Single rate three color marker (RFC 2697).
    Srtcm {
        /// Committed information rate.
        cir: u64,
        /// Committed burst size.
        cbs: u64,
        /// Excess burst size.
        ebs: u64,
    },
    /// Two rate three color marker (RFC 2698).
    Trtcm {
        /// Committed information rate.
        cir: u64,
        /// Peak information rate.
        pir: u64,
        /// Committed burst size.
        cbs: u64,
        /// Peak burst size.
        pbs: u64,
    },
    /// Two rate three color marker (RFC 4115).
    ///
    /// mlx5 implements it with MEF 10 coupling: committed overflow fills the excess bucket.
    Rfc4115 {
        /// Committed information rate.
        cir: u64,
        /// Excess information rate.
        eir: u64,
        /// Committed burst size.
        cbs: u64,
        /// Excess burst size.
        ebs: u64,
    },
}

/// A meter profile: the algorithm and its unit.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MeterProfile {
    /// The algorithm and its parameters.
    pub algorithm: MeterAlgorithm,
    /// What the parameters count.
    pub unit: MeterUnit,
}

impl MeterProfile {
    fn raw(&self) -> rte_mtr_meter_profile {
        // SAFETY: zero is valid for every field of this C struct.
        let mut raw: rte_mtr_meter_profile = unsafe { core::mem::zeroed() };
        match self.algorithm {
            MeterAlgorithm::Srtcm { cir, cbs, ebs } => {
                raw.alg = rte_mtr_algorithm::RTE_MTR_SRTCM_RFC2697;
                raw.annon1.srtcm_rfc2697.cir = cir;
                raw.annon1.srtcm_rfc2697.cbs = cbs;
                raw.annon1.srtcm_rfc2697.ebs = ebs;
            }
            MeterAlgorithm::Trtcm { cir, pir, cbs, pbs } => {
                raw.alg = rte_mtr_algorithm::RTE_MTR_TRTCM_RFC2698;
                raw.annon1.trtcm_rfc2698.cir = cir;
                raw.annon1.trtcm_rfc2698.pir = pir;
                raw.annon1.trtcm_rfc2698.cbs = cbs;
                raw.annon1.trtcm_rfc2698.pbs = pbs;
            }
            MeterAlgorithm::Rfc4115 { cir, eir, cbs, ebs } => {
                raw.alg = rte_mtr_algorithm::RTE_MTR_TRTCM_RFC4115;
                raw.annon1.trtcm_rfc4115.cir = cir;
                raw.annon1.trtcm_rfc4115.eir = eir;
                raw.annon1.trtcm_rfc4115.cbs = cbs;
                raw.annon1.trtcm_rfc4115.ebs = ebs;
            }
        }
        raw.packet_mode = i32::from(self.unit == MeterUnit::Packets);
        raw
    }
}

/// The port-wide identifier of a meter profile.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MeterProfileId(pub u32);

/// A traffic metering (`rte_mtr`) error.
#[derive(Debug, thiserror::Error)]
#[error("rte_mtr failed ({code}, error type {error_type}): {message}")]
pub struct MeterError {
    /// The return code.
    pub code: ErrorCode,
    /// The raw `rte_mtr_error_type`.
    pub error_type: u32,
    /// The PMD's detail message.
    pub message: String,
}

impl MeterError {
    fn from_raw(code: i32, error: &rte_mtr_error) -> MeterError {
        let message = if error.message.is_null() {
            "(no detail from PMD)".to_string()
        } else {
            // SAFETY: on failure the PMD sets `message` to a NUL-terminated C string.
            unsafe { CStr::from_ptr(error.message) }
                .to_string_lossy()
                .into_owned()
        };
        MeterError {
            code: ErrorCode::parse_i32(code),
            error_type: error.type_,
            message,
        }
    }
}

/// A meter profile added to a port, deleted on drop.
#[derive(Debug)]
pub struct MeterProfileHandle<'dev> {
    port: DevIndex,
    id: MeterProfileId,
    raw: NonNull<rte_flow_meter_profile>,
    _dev: PhantomData<&'dev ()>,
}

impl<'dev> MeterProfileHandle<'dev> {
    pub(crate) fn add(
        port: DevIndex,
        id: MeterProfileId,
        profile: &MeterProfile,
    ) -> Result<MeterProfileHandle<'dev>, MeterError> {
        let mut raw = profile.raw();
        // SAFETY: an all-zero `rte_mtr_error` is a valid out-parameter.
        let mut error: rte_mtr_error = unsafe { core::mem::zeroed() };
        // SAFETY: `raw` is a valid profile for the duration of the call; the PMD copies it.
        let ret =
            unsafe { rte_mtr_meter_profile_add(port.as_u16(), id.0, &raw mut raw, &raw mut error) };
        if ret != 0 {
            return Err(MeterError::from_raw(ret, &error));
        }
        // SAFETY: as above; the profile was just added.
        let object = unsafe { rte_mtr_meter_profile_get(port.as_u16(), id.0, &raw mut error) };
        let Some(raw) = NonNull::new(object) else {
            // `rte_mtr_meter_profile_get` reports only through `rte_errno`.
            // SAFETY: reads this thread's `rte_errno`.
            let failure = MeterError::from_raw(-unsafe { dpdk_sys::rte_errno_get() }, &error);
            // SAFETY: the profile was added above and nothing uses it.
            unsafe { rte_mtr_meter_profile_delete(port.as_u16(), id.0, &raw mut error) };
            return Err(failure);
        };
        Ok(MeterProfileHandle {
            port,
            id,
            raw,
            _dev: PhantomData,
        })
    }

    /// The profile's identifier.
    #[must_use]
    pub fn id(&self) -> MeterProfileId {
        self.id
    }
}

impl Drop for MeterProfileHandle<'_> {
    fn drop(&mut self) {
        // SAFETY: an all-zero `rte_mtr_error` is a valid out-parameter.
        let mut error: rte_mtr_error = unsafe { core::mem::zeroed() };
        // SAFETY: plain FFI call; meters using the profile borrow this handle, so none remain.
        let ret =
            unsafe { rte_mtr_meter_profile_delete(self.port.as_u16(), self.id.0, &raw mut error) };
        if ret != 0 {
            warn!(
                "failed to delete meter profile {} on port {}: {}",
                self.id.0,
                self.port,
                MeterError::from_raw(ret, &error)
            );
        }
    }
}

/// A meter: a `METER_MARK` indirect action rules share by handle, destroyed on drop.
///
/// It colors packets and does nothing else; match the color in a later group
/// ([`Pattern::meter_color`](super::Pattern::meter_color)).
#[derive(Debug)]
pub struct Meter<'p, D: Domain> {
    port: DevIndex,
    handle: NonNull<rte_flow_action_handle>,
    _profile: PhantomData<&'p ()>,
    _domain: PhantomData<D>,
}

impl<'p, D: Domain> Meter<'p, D> {
    pub(crate) fn new(profile: &'p MeterProfileHandle<'_>) -> Result<Meter<'p, D>, FlowError> {
        // SAFETY: zero is valid for these C structs.
        let mut conf: rte_flow_indir_action_conf = unsafe { core::mem::zeroed() };
        match D::DIRECTION {
            Direction::Ingress => conf.set_ingress(1),
            Direction::Egress => conf.set_egress(1),
            Direction::Transfer => conf.set_transfer(1),
        }
        let mark = rte_flow_action_meter_mark {
            profile: profile.raw.as_ptr(),
            policy: core::ptr::null_mut(),
            // Color blind.
            color_mode: 0,
            // Enabled.
            state: 1,
        };
        let action = rte_flow_action {
            type_: at::RTE_FLOW_ACTION_TYPE_METER_MARK,
            conf: from_ref(&mark).cast(),
        };
        // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: `conf`, `action` and `mark` outlive the call; the PMD copies them.
        let handle = unsafe {
            rte_flow_action_handle_create(
                profile.port.as_u16(),
                &raw const conf,
                &raw const action,
                &raw mut error,
            )
        };
        match NonNull::new(handle) {
            Some(handle) => Ok(Meter {
                port: profile.port,
                handle,
                _profile: PhantomData,
                _domain: PhantomData,
            }),
            None => Err(FlowError::from_raw(&error)),
        }
    }

    pub(crate) fn raw(&self) -> *mut rte_flow_action_handle {
        self.handle.as_ptr()
    }
}

impl<D: Domain> Drop for Meter<'_, D> {
    fn drop(&mut self) {
        // SAFETY: an all-zero `rte_flow_error` is a valid out-parameter.
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: the handle is live and owned by `self`; rules using it borrow `self`.
        let ret = unsafe {
            rte_flow_action_handle_destroy(self.port.as_u16(), self.handle.as_ptr(), &raw mut error)
        };
        if ret != 0 {
            warn!(
                "failed to destroy a meter on port {}: {}",
                self.port,
                FlowError::from_raw(&error)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_lower_to_their_algorithm_and_unit() {
        let srtcm = MeterProfile {
            algorithm: MeterAlgorithm::Srtcm {
                cir: 2_500_000,
                cbs: 65_536,
                ebs: 0,
            },
            unit: MeterUnit::Bytes,
        }
        .raw();
        assert_eq!(srtcm.alg, rte_mtr_algorithm::RTE_MTR_SRTCM_RFC2697);
        assert_eq!(srtcm.packet_mode, 0);
        // SAFETY: the srTCM member was the one written.
        let params = unsafe { srtcm.annon1.srtcm_rfc2697 };
        assert_eq!((params.cir, params.cbs, params.ebs), (2_500_000, 65_536, 0));

        let rfc4115 = MeterProfile {
            algorithm: MeterAlgorithm::Rfc4115 {
                cir: 1,
                eir: 2,
                cbs: 3,
                ebs: 4,
            },
            unit: MeterUnit::Packets,
        }
        .raw();
        assert_eq!(rfc4115.alg, rte_mtr_algorithm::RTE_MTR_TRTCM_RFC4115);
        assert_eq!(rfc4115.packet_mode, 1);
        // SAFETY: the RFC 4115 member was the one written.
        let params = unsafe { rfc4115.annon1.trtcm_rfc4115 };
        assert_eq!(
            (params.cir, params.eir, params.cbs, params.ebs),
            (1, 2, 3, 4)
        );
    }
}
