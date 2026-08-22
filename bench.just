# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := ["/usr/bin/env", "bash", "-euo", "pipefail", "-c"]
set script-interpreter := ["/usr/bin/env", "bash", "-euo", "pipefail"]

# enable to debug just recipes
debug_justfile := "false"

[private]
_just_debuggable_ := if debug_justfile == "true" { "set -x" } else { "" }

# The crate and bench target the callgrind recipes drive.
#
# One target today. When there are more, this is the knob that decides which of them a report
# covers, and the recipes below take the same shape for each.
export callgrind_package := "dataplane-routing"
export callgrind_bench := "fib_lookup_callgrind"

# What a benchmark run can tell you, and what it cannot, is in
# `development/code/benchmarking.md`. Read it before drawing a conclusion from one of these.
[private]
default: criterion

# Build and run the criterion benches: wall-clock time on this machine.
#
# The rte_acl benches are gated behind the `dpdk` feature, so run `just features=dpdk bench
# criterion` to exercise them; a plain run builds them as an empty `main()` and only runs the
# reference benches.
#
# Goes through the nix build rather than cargo so the binaries are the ones CI would produce.
#
# Skips the `*_callgrind` targets, which the same build produces. They are not criterion benches:
# run through this loop they respawn themselves under valgrind and, worse, overwrite whatever
# baseline `just bench compare` had stored.
[doc("Wall-clock time, via criterion")]
[script]
criterion *args:
    {{ _just_debuggable_ }}
    just build benches {{ args }}
    shopt -s nullglob
    for bench in ./results/benches/bin/*; do
      case "${bench}" in
        *_callgrind) continue ;;
      esac
      "${bench}" --bench
    done

# Run the iai-callgrind benches: instructions retired and modelled cache traffic, rather than
# wall-clock. Bit-for-bit repeatable run to run, which is what makes them gateable in CI -- and
# blind to anything that changes data layout rather than instruction count.
[doc("Instructions and cache traffic, via iai-callgrind")]
[script]
callgrind *args:
    {{ _just_debuggable_ }}
    cargo bench -p "${callgrind_package}" --bench "${callgrind_bench}" {{ args }}

# Compare the callgrind benches against a baseline and print a markdown report.
#
# On its own this records a baseline from the current tree and has nothing to compare against; run
# it once on the base commit and again on your branch. CI does exactly that, both times in one job
# on one runner, which is what makes the comparison meaningful without anything being stored
# between jobs.
[doc("Compare against a baseline and print a markdown report")]
[script]
compare baseline="base" *args:
    {{ _just_debuggable_ }}
    mkdir -p results/bench
    if [ -d "target/iai" ] && cargo bench -p "${callgrind_package}" --bench "${callgrind_bench}" -- \
        --baseline='{{ baseline }}' --output-format=json > results/bench/run.jsonl 2>/dev/null; then
      ./scripts/bench-report.ts results/bench/run.jsonl {{ args }}
    else
      cargo bench -p "${callgrind_package}" --bench "${callgrind_bench}" -- \
        --save-baseline='{{ baseline }}' --output-format=json > results/bench/run.jsonl
      ./scripts/bench-report.ts results/bench/run.jsonl {{ args }}
    fi

# Record a baseline for `compare` to measure against, without reporting.
#
# CI runs this on the base commit before checking out the head of the branch.
[doc("Record a baseline for `compare`, without reporting")]
[script]
baseline name="base":
    {{ _just_debuggable_ }}
    cargo bench -p "${callgrind_package}" --bench "${callgrind_bench}" -- \
      --save-baseline='{{ name }}' > /dev/null
    echo "recorded baseline '{{ name }}'"
