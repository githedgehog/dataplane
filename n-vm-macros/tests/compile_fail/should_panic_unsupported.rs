// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[n_vm::test]
#[should_panic]
fn should_panic_rejected() {
    panic!("the body runs in the VM guest; should_panic cannot compose");
}

fn main() {}
