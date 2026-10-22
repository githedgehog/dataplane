# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
#
# Whether a build links with ThinLTO: shared by `profiles.nix`, which picks the compiler and linker
# flags, and `default.nix`, which turns Cargo's own `lto` off to match.
#
# Coverage and the run-time sanitizers (address, leak, thread) link without it. They instrument each
# module as it is compiled and catch the same bugs without cross-crate inlining, and an instrumented
# ThinLTO link of the whole program, Rust and DPDK together, is the heaviest thing CI builds (see
# `lto_cores` in `ci.just`). The cost is speed: the binaries run slower without inlining, so tests on
# a time budget explore somewhat less. `check/release` still builds and tests the ThinLTO binary we
# ship, which is where LTO-specific breakage shows.
#
# CFI cannot work without LTO, so it keeps it whatever else is selected.
{
  sanitizers,
  instrumentations,
}:
builtins.elem "cfi" sanitizers
|| !(
  builtins.elem "coverage" instrumentations
  || builtins.any (s: builtins.elem s sanitizers) [
    "address"
    "leak"
    "thread"
  ]
)
