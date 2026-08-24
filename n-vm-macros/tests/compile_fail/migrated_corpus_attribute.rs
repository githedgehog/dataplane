// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The corpus grant is part of the machine now. Rejected rather than ignored:
// a fuzz target that quietly lost its writable share does not fail, it runs,
// generates inputs, and saves none of them.
#[n_vm::test]
#[n_vm::corpus]
fn migrated_corpus_attribute() {}

fn main() {}
