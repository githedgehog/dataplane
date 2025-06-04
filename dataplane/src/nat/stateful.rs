// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused_variables)]

use super::Nat;
use net::headers::Net;
use net::vxlan::Vni;

#[derive(Debug, Clone)]
struct NatState {}

impl NatState {
    fn new(net: &Net, pool: &NatPool) -> Self {
        Self {}
    }
}

#[derive(Debug, Clone)]
struct NatPool {}

impl Nat {
    fn lookup_state(&self, net: &Net, vni: Option<Vni>) -> Option<&NatState> {
        todo!()
    }

    fn find_nat_pool(&self, net: &Net, vni: Option<Vni>) -> Option<&NatPool> {
        todo!()
    }

    fn stateful_translate(&self, net: &mut Net, state: &NatState) {
        todo!();
    }

    pub(crate) fn stateful_nat(&self, net: &mut Net, vni: Option<Vni>) {
        // Hot path: if we have a state, directly translate the address already
        if let Some(state) = self.lookup_state(net, vni) {
            self.stateful_translate(net, state);
            return;
        }

        if let Some(pool) = self.find_nat_pool(net, vni) {
            let state = NatState::new(net, pool);
            self.stateful_translate(net, &state);
        }
    }
}
