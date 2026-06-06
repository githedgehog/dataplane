// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
