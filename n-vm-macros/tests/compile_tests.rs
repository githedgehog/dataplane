// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// trybuild shells out to `cargo` at run time to compile each case for the
// build target.  Under cross emulation (`--cfg emulated`, set by
// `nix/profiles.nix` when the test arch != host arch) the test binary runs
// via qemu-user and that build target's `std`/`core` is not available, so
// the cases fail with E0463 ("can't find crate for `core`") rather than the
// diagnostics they assert.  The macro's compile-time errors are
// arch-independent, so the native (non-emulated) run is full coverage.
#[test]
#[cfg_attr(
    emulated,
    ignore = "trybuild compiles host-side; cross target has no std/core"
)]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
