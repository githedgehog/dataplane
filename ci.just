# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := ["/usr/bin/env", "bash", "-euo", "pipefail", "-c"]
set script-interpreter := ["/usr/bin/env", "bash", "-euo", "pipefail"]

# Reproducible entry points for `.github/workflows/dev.yml` jobs. Keep
# job-specific build settings here instead of duplicating workflow variables.

debug_justfile := env("CI_DEBUG_JUSTFILE", "false")

# The container cannot discover its ten-core cgroup limit. Keep `jobs * cores`
# within that budget and give single large derivations all of it.
jobs := "1"

cores := "10"

# Limit nextest to the cgroup's CPU budget; host core detection would oversubscribe it.
# Export this limit to nested `just` invocations.
export NEXTEST_TEST_THREADS := cores

# What a ThinLTO profile may use, which is not the same question as how many cores there are.
#
# `cores` becomes `NIX_BUILD_CORES`, which crane turns into `CARGO_BUILD_JOBS`, so it also sets
# how many `rustc` link steps may be in flight -- and in a profile carrying `lto = "thin"` plus
# `-Clinker-plugin-lto`, every one of those spawns an `ld.lld` that ThinLTOs the whole program,
# Rust and DPDK together. `tests.all` archives 65 binaries, so the peak is set by how many of
# those links overlap, not by how much work there is in total.
#
# Measured building `tests.all` at `profile=release`, summing the resident size of every
# compiler and linker process once every two seconds:
#
#     cores=10   25.93 GiB   28 procs   367s      <- over budget
#     cores=6    19.75 GiB   16 procs   472s      <- 99% of budget
#     cores=4    14.29 GiB   12 procs   585s
#     cores=2     9.34 GiB    6 procs   924s
#
# The runner gets 20 GiB in its own cgroup. `cores=10` is what killed `check/release`: the
# runner stopped answering inside the `test` step twice, at 21 and 32 minutes, the second time
# with no other job on the lab, and no log survived either time. At the peak seven `ld.lld`
# processes were resident at once, the largest 3.68 GiB.
#
# `cores=4` is the largest value with real headroom, and it costs about 60% more wall time on
# that derivation than `cores=10` did.
#
# Changing this forks nothing: `--cores` is deliberately outside the derivation hash, and
# `nix path-info --derivation` returns the same `.drv` at 10, 4 and 1. It is a scheduling knob,
# not a build input.
#
# Those numbers predate the test archive bounding its own links; see `release_test_cores`.
lto_cores := "4"

# The `check/release` test step. Its test archive now bounds how many of its ThinLTO links run at
# once (`LINK_SLOTS` in default.nix) and carries line-table debug info, so its peak no longer
# depends on how many links happen to overlap. Measured building the step's whole chain cold on 8
# cores, one derivation at a time as here, summing every process of each build every two seconds:
#
#     dataplane-deps                     74 s    6.2 GiB
#     dataplane-tests-deps               98 s    4.9 GiB
#     dataplane (ships: full debug info) 252 s    6.7 GiB
#     dataplane-cli                      26 s    1.4 GiB
#     dataplane-init                     51 s    2.3 GiB
#     tests.all                         650 s   12.4 GiB
#
# against `tests.all` alone taking 929 s and peaking at 22 GiB on `lto_cores` before. The other
# jobs on `lto_cores` were not measured with these changes and stay there.
release_test_cores := "8"

[private]
_lab-common := " docker_sock=/run/docker/docker.sock" + " oci_repo=ghcr.io" + " debug_justfile=" + debug_justfile

[private]
_lab := "jobs=" + jobs + " cores=" + cores + _lab-common

# For the profiles that link with ThinLTO. See `lto_cores`.
[private]
_lab-lto := "jobs=" + jobs + " cores=" + lto_cores + _lab-common

# See `release_test_cores`.
[private]
_lab-release-test := "jobs=" + jobs + " cores=" + release_test_cores + _lab-common

[default]
[private]
@default:
    just --list --justfile {{ justfile() }}

# Separate recipes keep failures visible as individual workflow steps.
# `cargo fmt` is profile-independent, so `check-fmt` accepts no profile.
check-fmt:
    just {{ _lab }} fmt --check

check-test profile:
    just {{ if profile == "debug" { _lab } else if profile == "release" { _lab-release-test } else { _lab-lto } }} profile={{ profile }} test

check-clippy profile:
    just {{ _lab }} profile={{ profile }} clippy

check-doctest profile:
    just {{ if profile == "debug" { _lab } else { _lab-lto } }} profile={{ profile }} doctest

check-docs profile:
    just {{ _lab }} profile={{ profile }} docs

sanitize san profile="checked":
    just {{ if profile == "debug" { _lab } else { _lab-lto } }} profile={{ profile }} sanitize={{ san }} test

# Each package checked on its own, all targets, in one derivation; see `check-each` in
# `default.nix`. It replaces building and running each package's tests separately, which
# recompiled the shared workspace crates once per package and never reused the results.
check-each profile="debug":
    just {{ _lab }} profile={{ profile }} check-each-target

# The same check against musl, whose C types are not glibc's (`ioctl`'s request is an `int`, not an
# `unsigned long`), so code that compiles here can fail there. The cross jobs that build for musl
# are opt-in on a pull request and do not compile tests unless asked, which is how a test that
# named glibc's type first failed on a release tag.
check-musl platform="bluefield3":
    just {{ _lab }} platform={{ platform }} libc=musl profile=debug check-each-target

# An instrumented link of the whole program is the heaviest the lab runs with or without LTO, and
# `coverage/checked` kept losing its runner, so every profile gets the smaller link budget.
coverage profile="debug":
    just {{ _lab-lto }} profile={{ profile }} instrument=coverage coverage-archive

# Optimized fuzz builds let schedule explorers cover more interleavings.
shuttle profile="checked":
    just {{ if profile == "debug" { _lab } else { _lab-lto } }} profile={{ profile }} features=shuttle test

loom profile="checked":
    just {{ if profile == "debug" { _lab } else { _lab-lto } }} profile={{ profile }} features=loom test

wasm:
    just {{ _lab }} platform=wasm32-wasip1 profile=release libc=none check

cross platform libc +args:
    just {{ _lab }} platform={{ platform }} libc={{ libc }} profile=debug {{ args }}

# Bound individual tests when running them under qemu-user.
cross-test platform libc:
    NEXTEST_PROFILE=cross-qemu just {{ _lab }} platform={{ platform }} libc={{ libc }} profile=debug test

# Publish both content-derived and discoverable per-commit tags.
[script]
push-container target profile version:
    declare platform="x86-64-v3"
    if [ "{{ target }}" = "validator" ]; then
      platform="wasm32-wasip1"
    fi
    declare -ra base=( {{ _lab }} profile="{{ profile }}" platform="${platform}" )
    just "${base[@]}" push-container "{{ target }}"
    just "${base[@]}" version="{{ version }}-{{ profile }}" push-container "{{ target }}"
