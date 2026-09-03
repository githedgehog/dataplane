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

# Reserve host hugepages on the runner's *host* for the guest-booting tests.
#
# 2 MiB pages, and the count is a VM's worth twice over: a 1024 MiB guest
# backed by 2 MiB pages needs 512 of them, and the `check` and `coverage` jobs
# can be on one machine at once.
#
# Not 1 GiB, though that is the page size that matters most -- it is the only
# thing that makes a guest's memory physically contiguous, which is the only
# thing DPDK-through-an-IOMMU can tell apart. A gigabyte page has to come from
# a physically contiguous gigabyte, and these runners cannot produce one:
# measured, the kernel answers 0 both before and after compaction. That wants
# `default_hugepagesz=1G hugepagesz=1G hugepages=4` on the host command line
# and a reboot. Until then `vm_boots_with_host_hugepages` is `#[ignore]`d and
# its 2 MiB counterpart covers the same code.
#
# The runner is a container with no capabilities at all (measured: `CapEff` is
# zero), so it cannot write `/sys/kernel/mm/hugepages` itself. It can ask the
# host's daemon for a privileged container that can. The pool is not
# namespaced, so this reserves for the machine and every job on it sees the
# result -- which is also why it only ever raises the count, never lowers it.
#
# Never fails the job: a reservation is a request, and a test that does not get
# its page says so far more precisely than a setup step could.
[script]
reserve-hugepages count="1024" size_kb="2048":
    # The lab's daemon socket, overridable so this recipe can be exercised
    # against an ordinary local daemon.
    export DOCKER_HOST="${DOCKER_HOST:-unix:///run/docker/docker.sock}"
    declare -r pool="/sys/kernel/mm/hugepages/hugepages-{{ size_kb }}kB"
    # Already pulled on these runners; a tag rather than latest so a silent
    # upstream change cannot alter what runs privileged here.
    declare -r img="busybox:1.37.0-uclibc"

    # stdout only; stderr is kept for the diagnostic below rather than thrown
    # away, because "got 0" with no explanation is not something anyone can act
    # on -- which is exactly where the first attempt at this left us.
    # `--privileged` alone: it already gives the container a read-write sysfs,
    # and sysfs is not namespaced, so that *is* the host's. An explicit
    # `-v /sys:/sys` on top adds a bind whose mode depends on how the daemon is
    # configured, which is a variable this does not need.
    declare priv_err=""
    priv() {
      priv_err="$(docker run --rm --privileged "${img}" sh -c "$1" 2>&1 >/dev/null)"
      docker run --rm --privileged "${img}" sh -c "$1" 2>/dev/null
    }

    declare have
    have="$(priv "cat ${pool}/nr_hugepages" || true)"
    if [ -z "${have}" ]; then
      echo "::warning::no {{ size_kb }}kB hugepage pool at ${pool}; tests that need one will say so"
      exit 0
    fi
    if [ "${have}" -ge "{{ count }}" ]; then
      echo "{{ size_kb }}kB hugepages: ${have} already reserved, leaving alone"
      exit 0
    fi

    priv "echo {{ count }} > ${pool}/nr_hugepages" || true
    declare got
    got="$(priv "cat ${pool}/nr_hugepages" || echo 0)"

    # Compaction migrates movable pages to free contiguous runs. It costs a few
    # seconds and disturbs nothing else on the host, unlike dropping caches,
    # which would take the page cache from every other job on this machine.
    if [ "${got}" -lt "{{ count }}" ]; then
      priv "echo 1 > /proc/sys/vm/compact_memory" || true
      priv "echo {{ count }} > ${pool}/nr_hugepages" || true
      got="$(priv "cat ${pool}/nr_hugepages" || echo 0)"
    fi

    if [ "${got}" -lt "{{ count }}" ]; then
      echo "::warning::asked for {{ count }} {{ size_kb }}kB hugepages, got ${got} (was ${have}), even after compaction"
      # What the kernel said, and what it had to work with. A reservation can
      # come up short for two quite different reasons -- the write was refused,
      # or the memory was not there -- and the count alone cannot tell them
      # apart.
      if [ -n "${priv_err}" ]; then
        echo "::warning::the write reported: ${priv_err}"
      fi
      priv "grep -E '^(MemFree|MemAvailable|HugePages_|Hugepagesize)' /proc/meminfo" \
        | sed 's/^/  /' || true
      priv "ls /sys/kernel/mm/hugepages" | sed 's/^/  pools: /' || true
    else
      echo "{{ size_kb }}kB hugepages: ${have} -> ${got}"
    fi

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
