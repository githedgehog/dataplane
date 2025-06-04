// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused_variables)]

mod allocator;
mod sessions;

use super::Nat;
use net::headers::Net;
use net::vxlan::Vni;
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
    protocol: u8,
    vni: Vni,
}

impl NatState {
    fn new(net: &Net, pool: &allocator::NatPool) -> Self {
        Self {}
    }
}

impl Nat {
    fn hash_tuple(net: &Net, vni: Vni) -> NatTuple {
        todo!()
    }
    fn lookup_state(&self, tuple: &NatTuple) -> Option<&NatState> {
        todo!()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn update_state(&mut self, tuple: &NatTuple, state: NatState) -> Result<(), StatefulNatError> {
        todo!()
    }

    fn find_nat_pool(&self, net: &Net, vni: Vni) -> Option<&allocator::NatPool> {
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

        let tuple = Self::hash_tuple(net, vni);

        // Hot path: if we have a session, directly translate the address already
        if let Some(state) = self.lookup_state(&tuple) {
            self.stateful_translate(net, state);
            return;
        }

        // Else, if we need NAT for this packet, create a new session and translate the address
        if let Some(pool) = self.find_nat_pool(net, vni) {
            let state = NatState::new(net, pool);
            if self.update_state(&tuple, state.clone()).is_ok() {
                self.stateful_translate(net, &state);
            }
            // Drop otherwise??
        }

        // Else, just leave the packet unchanged
    }
}
