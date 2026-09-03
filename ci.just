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

# Reserve 1 GiB hugepages on the runner's *host* for the guest-booting tests.
#
# `vm_boots_with_host_hugepages` asks for a 1 GiB host page, because that is
# the only thing that makes the guest's memory physically contiguous, which is
# the only thing DPDK-through-an-IOMMU can tell apart. Nothing else asks: see
# the `HostPageSize` docs for why the default deliberately leaves this pool
# alone.
#
# The runner is a container with no capabilities at all (measured: `CapEff` is
# zero), so it cannot write `/sys/kernel/mm/hugepages` itself. It can ask the
# host's daemon for a privileged container that can. The pool is not
# namespaced, so this reserves for the machine, and every job on it sees the
# result -- which is also why it only ever raises the count, never lowers it.
#
# Never fails the job. A 1 GiB reservation is a request, not a guarantee: the
# kernel needs that many physically contiguous gigabytes, and on a long-lived
# machine it may not find them. If it comes up short the test that needs a page
# says so precisely, and that is a better place to read it than here.
[script]
reserve-hugepages count="4":
    # The lab's daemon socket, overridable so this recipe can be exercised
    # against an ordinary local daemon.
    export DOCKER_HOST="${DOCKER_HOST:-unix:///run/docker/docker.sock}"
    declare -r pool="/sys/kernel/mm/hugepages/hugepages-1048576kB"
    # Already pulled on these runners; a tag rather than latest so a silent
    # upstream change cannot alter what runs privileged here.
    declare -r img="busybox:1.37.0-uclibc"

    priv() { docker run --rm --privileged -v /sys:/sys "${img}" sh -c "$1" 2>/dev/null; }

    declare have
    have="$(priv "cat ${pool}/nr_hugepages" || true)"
    if [ -z "${have}" ]; then
      echo "::warning::no 1 GiB hugepage pool at ${pool}; tests that need one will say so"
      exit 0
    fi
    if [ "${have}" -ge "{{ count }}" ]; then
      echo "1 GiB hugepages: ${have} already reserved, leaving alone"
      exit 0
    fi

    priv "echo {{ count }} > ${pool}/nr_hugepages" || true
    declare got
    got="$(priv "cat ${pool}/nr_hugepages" || echo 0)"

    # A gigabyte page needs a physically contiguous gigabyte, and a machine
    # that has been up a while rarely has one to hand -- which is why the
    # kernel documentation reserves 1 GiB pages at boot. Compaction is the one
    # thing worth trying first: it migrates movable pages to free contiguous
    # runs, costs a few seconds, and disturbs nothing else on the host (unlike
    # dropping caches, which would take the page cache away from every other
    # job on this machine).
    if [ "${got}" -lt "{{ count }}" ]; then
      priv "echo 1 > /proc/sys/vm/compact_memory" || true
      priv "echo {{ count }} > ${pool}/nr_hugepages" || true
      got="$(priv "cat ${pool}/nr_hugepages" || echo 0)"
    fi

    if [ "${got}" -lt "{{ count }}" ]; then
      echo "::warning::asked for {{ count }} 1 GiB hugepages, got ${got} (was ${have}), even after compaction."
      echo "::warning::runtime allocation of 1 GiB pages needs a contiguous gigabyte. The durable fix is a boot parameter on this host: \`default_hugepagesz=1G hugepagesz=1G hugepages={{ count }}\`."
    else
      echo "1 GiB hugepages: ${have} -> ${got}"
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
