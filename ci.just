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

# Nix build budget for a 10-core lab runner.
jobs := "1"

cores := "8"

[private]
_lab := "jobs=" + jobs + " cores=" + cores + " docker_sock=/run/docker/docker.sock" + " oci_repo=ghcr.io" + " debug_justfile=" + debug_justfile

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
    just {{ _lab }} profile={{ profile }} test-each

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

# Verify a debug image's entrypoint actually does its job.
smoke-container target profile:
    just {{ _lab }} profile={{ profile }} platform=x86-64-v3 smoke-container {{ target }}

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
