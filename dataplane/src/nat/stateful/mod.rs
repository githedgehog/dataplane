// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused_variables)]

mod allocator;
mod sessions;

use super::Nat;
use net::headers::Net;
use net::vxlan::Vni;
use routing::rib::vrf::VrfId;
use std::net::IpAddr;

#[derive(thiserror::Error, Debug)]
pub enum StatefulNatError {
    #[error("other error")]
    Other,
}

#[derive(Debug, Clone)]
struct NatState {}

#[derive(Debug, Clone)]
struct NatTuple {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    next_header: u8,
    vrf_id: VrfId,
}

impl NatState {
    fn new(net: &Net, pool: &dyn allocator::NatPool) -> Self {
        Self {}
    }
}

impl Nat {
    fn get_vrf_id(net: &Net, vni: Vni) -> VrfId {
        todo!()
    }

    fn extract_tuple(net: &Net, vrf_id: VrfId) -> NatTuple {
        todo!()
    }

    fn lookup_state(&self, tuple: &NatTuple) -> Option<&NatState> {
        todo!()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn update_state(&mut self, tuple: &NatTuple, state: NatState) -> Result<(), StatefulNatError> {
        todo!()
    }

    fn find_nat_pool(&self, net: &Net, vrf_id: VrfId) -> Option<&dyn allocator::NatPool> {
        todo!()
    }

    fn stateful_translate(&self, net: &mut Net, state: &NatState) {
        todo!();
    }

    pub(crate) fn stateful_nat(&mut self, net: &mut Net, vni_opt: Option<Vni>) {
        // TODO: What if no VNI
        let Some(vni) = vni_opt else {
            return;
        };

        // TODO: Check whether the packet is fragmented
        // TODO: Check whether we need protocol-aware processing

        let vrf_id = Self::get_vrf_id(net, vni);
        let tuple = Self::extract_tuple(net, vrf_id);

        // Hot path: if we have a session, directly translate the address already
        if let Some(state) = self.lookup_state(&tuple) {
            self.stateful_translate(net, state);
            return;
        }

        // Else, if we need NAT for this packet, create a new session and translate the address
        if let Some(pool) = self.find_nat_pool(net, vrf_id) {
            let state = NatState::new(net, pool);
            if self.update_state(&tuple, state.clone()).is_ok() {
                self.stateful_translate(net, &state);
            }
            // Drop otherwise??
        }

        // Else, just leave the packet unchanged
    }
}
