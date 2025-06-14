// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused_variables)]

mod allocator;
mod sessions;

use super::Nat;
use net::headers::Net;
use net::vxlan::Vni;
use routing::rib::vrf::VrfId;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(thiserror::Error, Debug)]
pub enum StatefulNatError {
    #[error("other error")]
    Other,
}

mod private {
    pub trait Sealed {}
}
pub trait NatIp: private::Sealed {
    fn to_ip_addr(&self) -> IpAddr;
}
impl private::Sealed for IpAddr {}
impl private::Sealed for Ipv4Addr {}
impl private::Sealed for Ipv6Addr {}
impl NatIp for IpAddr {
    fn to_ip_addr(&self) -> IpAddr {
        *self
    }
}
impl NatIp for Ipv4Addr {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V4(*self)
    }
}
impl NatIp for Ipv6Addr {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V6(*self)
    }
}

#[derive(Debug, Clone)]
struct NatState {}

#[derive(Debug, Clone)]
struct NatTuple<I: NatIp> {
    src_ip: I,
    dst_ip: I,
    next_header: u8,
    vrf_id: VrfId,
}

impl NatState {
    fn new<I: NatIp>(net: &Net, pool: &dyn allocator::NatPool<I>) -> Self {
        Self {}
    }
}

impl Nat {
    fn get_vrf_id(net: &Net, vni: Vni) -> VrfId {
        todo!()
    }

    fn extract_tuple<I: NatIp>(net: &Net, vrf_id: VrfId) -> NatTuple<I> {
        todo!()
    }

    fn lookup_state<I: NatIp>(&self, tuple: &NatTuple<I>) -> Option<&NatState> {
        todo!()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn update_state<I: NatIp>(
        &mut self,
        tuple: &NatTuple<I>,
        state: NatState,
    ) -> Result<(), StatefulNatError> {
        todo!()
    }

    fn find_nat_pool<I: NatIp>(
        &self,
        net: &Net,
        vrf_id: VrfId,
    ) -> Option<&dyn allocator::NatPool<I>> {
        todo!()
    }

    fn stateful_translate(&self, net: &mut Net, state: &NatState) {
        todo!();
    }

    pub(crate) fn stateful_nat<I: NatIp, J: NatIp>(&mut self, net: &mut Net, vni_opt: Option<Vni>) {
        // TODO: What if no VNI
        let Some(vni) = vni_opt else {
            return;
        };

        // TODO: Check whether the packet is fragmented
        // TODO: Check whether we need protocol-aware processing

        let vrf_id = Self::get_vrf_id(net, vni);
        let tuple = Self::extract_tuple::<I>(net, vrf_id);

        // Hot path: if we have a session, directly translate the address already
        if let Some(state) = self.lookup_state(&tuple) {
            self.stateful_translate(net, state);
            return;
        }

        // Else, if we need NAT for this packet, create a new session and translate the address
        if let Some(pool) = self.find_nat_pool::<J>(net, vrf_id) {
            let state = NatState::new(net, pool);
            if self.update_state(&tuple, state.clone()).is_ok() {
                self.stateful_translate(net, &state);
            }
            // Drop otherwise??
        }

        // Else, just leave the packet unchanged
    }
}
