# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := ["/usr/bin/env", "bash", "-euo", "pipefail", "-c"]
set script-interpreter := ["/usr/bin/env", "bash", "-euo", "pipefail"]

# Reproducible entry points for `.github/workflows/dev.yml` jobs. Keep
# job-specific build settings here instead of duplicating workflow variables.

debug_justfile := env("CI_DEBUG_JUSTFILE", "false")

# Concurrent matrix entries sharing the runner's core budget. Set this only
# when the workflow sets `strategy.max-parallel` explicitly.
parallel := "1"

# Non-matrix jobs pass an empty `strategy.max-parallel`.
[private]
_parallel := if parallel == "" { "1" } else { parallel }

[private]
_share := if _parallel == "1" { "1" } else { "1/" + _parallel }

# Nix build budget for a lab runner.
#
# The cgroup allows ten cores.  Nothing inside the container can see that:
# `nproc` reports the node's 32 and the cgroup files are not readable from the
# pod.  Measuring throughput from inside cannot recover it either, since a load
# that fits within ten cores shows no contention.  Treat the ten as given.
#
# `jobs * cores` is the request, so it has to come to ten.  One derivation at a
# time with the whole budget suits the heavy jobs, which each build a single
# large derivation -- `check`, the sanitizers, and the container builds all do.
jobs := "1"

cores := "10"

# `test_each` is the exception.  It builds one derivation per package, so a
# single job leaves most of the budget idle whenever a package is too small to
# saturate ten cores: it cost 887s at `jobs=1 cores=10` against 613s at
# `jobs=4 cores=8`, and the latter is faster only because it overcommits the
# cgroup.  Split the ten two ways instead.
test_each_jobs := "2"

test_each_cores := "5"

[private]
_lab-common := " docker_sock=/run/docker/docker.sock" + " oci_repo=ghcr.io" + " debug_justfile=" + debug_justfile

[private]
_lab := "jobs=" + jobs + " cores=" + cores + _lab-common

[private]
_lab-test-each := "jobs=" + test_each_jobs + " cores=" + test_each_cores + _lab-common

[default]
[private]
@default:
    just --list --justfile {{ justfile() }}

# Separate recipes preserve per-step results in the GitHub UI.
check-fmt profile:
    just {{ _lab }} profile={{ profile }} fmt --check

check-test profile:
    just {{ _lab }} profile={{ profile }} test

check-clippy profile:
    just {{ _lab }} profile={{ profile }} clippy

check-doctest profile:
    just {{ _lab }} profile={{ profile }} doctest

check-docs profile:
    just {{ _lab }} profile={{ profile }} docs

sanitize san profile="fuzz":
    just {{ _lab }} profile={{ profile }} sanitize={{ san }} test

test-each profile="debug":
    just {{ _lab-test-each }} profile={{ profile }} test-each

coverage profile="debug":
    just {{ _lab }} profile={{ profile }} instrument=coverage coverage-archive

# Shuttle and loom explore schedules rather than run the suite once, so they
# want `fuzz`: `release` optimization with debug-assertions and overflow-checks
# still on.  Under `debug` they explore far fewer schedules per unit time, and
# say nothing about it.
shuttle profile="fuzz":
    just {{ _lab }} profile={{ profile }} features=shuttle test

loom profile="fuzz":
    just {{ _lab }} profile={{ profile }} features=loom test

wasm:
    just {{ _lab }} platform=wasm32-wasip1 profile=release libc=none check

cross platform libc +args:
    just {{ _lab }} share={{ _share }} platform={{ platform }} libc={{ libc }} profile=debug {{ args }}

# Bound individual tests when running them under qemu-user.
cross-test platform libc:
    NEXTEST_PROFILE=cross-qemu just {{ _lab }} share={{ _share }} platform={{ platform }} libc={{ libc }} profile=debug test

# Push both the derived and temporary per-commit tags.
[script]
push-container target profile version:
    declare platform="x86-64-v3"
    if [ "{{ target }}" = "validator" ]; then
      platform="wasm32-wasip1"
    fi
    declare -ra base=( {{ _lab }} profile="{{ profile }}" platform="${platform}" )
    just "${base[@]}" push-container "{{ target }}"
    just "${base[@]}" version="{{ version }}-{{ profile }}" push-container "{{ target }}"
