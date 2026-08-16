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

# Small per-package derivations use the budget better when split two ways.
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

# Separate recipes keep failures visible as individual workflow steps.
# `cargo fmt` is profile-independent, so `check-fmt` accepts no profile.
check-fmt:
    just {{ _lab }} fmt --check

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

# Optimized fuzz builds let schedule explorers cover more interleavings.
shuttle profile="fuzz":
    just {{ _lab }} profile={{ profile }} features=shuttle test

loom profile="fuzz":
    just {{ _lab }} profile={{ profile }} features=loom test

wasm:
    just {{ _lab }} platform=wasm32-wasip1 profile=release libc=none check

cross platform libc +args:
    just {{ _lab }} platform={{ platform }} libc={{ libc }} profile=debug {{ args }}

# Bound individual tests when running them under qemu-user.
cross-test platform libc:
    NEXTEST_PROFILE=cross-qemu just {{ _lab }} platform={{ platform }} libc={{ libc }} profile=debug test

# Verify a debug image's entrypoint actually does its job.
smoke-container target profile:
    just {{ _lab }} profile={{ profile }} platform=x86-64-v3 smoke-container {{ target }}

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
