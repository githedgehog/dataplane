# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := ["/usr/bin/env", "bash", "-euo", "pipefail", "-c"]
set script-interpreter := ["/usr/bin/env", "bash", "-euo", "pipefail"]

# enable to debug just recipes
debug_justfile := "false"

[private]
_just_debuggable_ := if debug_justfile == "true" { "set -x" } else { "" }

# threads miri may use ("0" means every core on the machine).
#
# This module compiles and runs on the host inside `nix-shell`, so the root
# justfile's `cores` (which is just `nix build --cores`) never reaches it.
# We therefore hand the cap to cargo and to nextest ourselves: cargo through
# CARGO_BUILD_JOBS for the build, nextest through --test-threads for the run.
export cores := "0"

export cpu := "powerpc64"
[private]
export target := cpu + "-unknown-linux-gnu"
export provenance := "permissive"
export schedule_seed := choose('5', "0123456789")
export seeds := "1"
export stacked_borrow_check := "disabled"
export preemption_rate := "0.10"
export weak_failure_rate := "0.05"
export randomize_struct_layout := "enabled"
export layout_seed := `printf '%u' "$((16#$(git rev-parse HEAD)))"`

[script]
[default]
test *args="":
    nix-shell --argstr nightly "true" --run '
      set -euo pipefail
      {{ _just_debuggable_ }}
      declare -ri START_SEED="$((10#$schedule_seed))"
      declare -ri END_SEED="$((START_SEED + ${seeds}))"
      declare MIRIFLAGS=""
      declare RUSTFLAGS=""
      MIRIFLAGS+="-Zmiri-compare-exchange-weak-failure-rate=${weak_failure_rate} "
      MIRIFLAGS+="-Zmiri-disable-isolation "
      MIRIFLAGS+="-Zmiri-many-seeds=${START_SEED}..${END_SEED} "
      MIRIFLAGS+="-Zmiri-preemption-rate=${preemption_rate} "
      MIRIFLAGS+="-Zmiri-symbolic-alignment-check "
      MIRIFLAGS+="-Zmiri-${provenance}-provenance "
      if [ "${stacked_borrow_check}" = "disabled" ]; then
        MIRIFLAGS+="-Zmiri-disable-stacked-borrows "
      fi
      declare -rx MIRIFLAGS
      if [ "${randomize_struct_layout}" = "enabled" ]; then
        if [ "${layout_seed}" = "random" ]; then
          layout_seed="${RANDOM}"
        fi
        RUSTFLAGS+="-Zrandomize-layout -Zlayout-seed=${layout_seed} "
      fi
      # Umbrella cfg shared with the qemu-user path in nix/profiles.nix.
      RUSTFLAGS+="--cfg=emulated"
      declare -rx RUSTFLAGS
      declare -a cmd=("nice" "-n" "19" "cargo" "miri" "nextest" "run" "--profile=miri" "--target=${target}")
      if [ "${cores}" != "0" ]; then
        # nextest defaults --test-threads to the core count; the miri profile
        # then spends `threads-required` (== ${seeds}) of those slots per test.
        declare -rx CARGO_BUILD_JOBS="${cores}"
        cmd+=("--test-threads=${cores}")
      fi
      declare -r cmd
      echo "Running Miri with args: {{ args }}"
      echo "MIRIFLAGS=$MIRIFLAGS"
      echo "RUSTFLAGS=$RUSTFLAGS"
      config="$(mktemp --suffix=.nextest.toml)"
      trap "rm ${config}" EXIT
      tomlq --toml-output ". as \$root | \$root.profile.miri[\"threads-required\"] = ${seeds}" .config/nextest.toml > "${config}"
      if [ -z "{{args}}" ]; then
        ${cmd[@]} \
            --workspace \
            $(tomlq --raw-output ".workspace.metadata.package | to_entries[].value | \"--exclude=\" + select(.miri == false).package" Cargo.toml) \
             --config-file "${config}"
      else
        ${cmd[@]} --config-file "${config}" {{ args }}
      fi
    '
