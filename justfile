# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := ["/usr/bin/env", "bash", "-euo", "pipefail", "-c"]
set script-interpreter := ["/usr/bin/env", "bash", "-euo", "pipefail"]

# enable to debug just recipes
debug_justfile := "false"

[private]
_just_debuggable_ := if debug_justfile == "true" { "set -x" } else { "" }

# number of nix jobs to run in parallel
jobs := "8"

# libc
libc := if platform == "wasm32-wasip1" { "unknown" } else { "gnu" }

# kernel (linux or wasip1)
kernel := if platform == "wasm32-wasip1" { "wasip1" } else { "linux" }

# List out the available commands
[private]
[default]
@default:
    just --list --justfile {{ justfile() }}

# cargo build profile (debug/release/fuzz)
profile := "debug"

# sanitizer to use (address/thread/safe-stack/cfi/"")
sanitize := ""

# comma-separated list of cargo features to enable (e.g. "shuttle")
features := ""

# whether to include default cargo features for this workspace (set to "false" to disable)
default_features := "true"

# Private computed cargo flag groups for consistent invocations.
# Recipes should compose these as needed (not all cargo subcommands accept all flags).
[private]
_cargo_feature_flags := \
    (if default_features == "false" { "--no-default-features " } else { "" }) \
    + (if features != "" { "--features " + features } else { "" })

[private]
_cargo_profile_flag := if profile == "debug" { "" } else { "--profile " + profile }

# filters for nextest
filter := if features == "shuttle" { "shuttle" } else { "" }

# instrumentation mode (none/coverage)
instrument := "none"

# target platform (x86-64-v3/bluefield2)
platform := "x86-64-v3"

# ---- Fuzzing configuration ------------------------------------------------

# fuzzing engine (libfuzzer/honggfuzz/afl/kani)
fuzz_engine := "libfuzzer"

# fuzzing duration per target (e.g. "30s", "1m", "1h", "24h")
fuzz_duration := "1m"

# bolero build profile for fuzzing (fuzz/release)
fuzz_profile := "fuzz"

# sanitizer for fuzz builds (address/thread/none); bolero default is "address"
fuzz_sanitizer := "address"

# restrict fuzz targets to a single package (e.g. "dataplane-net"); empty = all
fuzz_package := ""

# Private: resolve the -p / --workspace flag for bolero commands.
[private]
_bolero_pkg_flag := if fuzz_package != "" { "-p " + fuzz_package } else { "--workspace" }

# Private: resolve the sanitizer flag (bolero expects -s <san>, omit for "none"/empty).
[private]
_bolero_san_flag := if fuzz_sanitizer != "" { if fuzz_sanitizer != "none" { "-s " + fuzz_sanitizer } else { "" } } else { "" }

version_extra := ""
version_platform := if platform == "x86-64-v3" { "" } else { "-" + platform }
version_profile := if profile == "release" { "" } else { "-" + profile }
version_san := if sanitize == "" { "" } else { "-san." + replace(sanitize, ",", ".") }
version_feat := if features == "" { "" } else { "-feat." + replace(features, ",", ".") }
version := env("VERSION", "") || `git describe --tags --dirty --always` + version_platform + version_profile + version_san + version_feat + version_extra

# Print version that will be used in the build
version:
  @echo "Using version: {{version}}"

# OCI repo to push images to

oci_repo := "127.0.0.1:30000"
oci_insecure := ""
oci_name := "githedgehog/dataplane"
oci_frr_prefix := "githedgehog/dpdk-sys/frr"
oci_image_dataplane := oci_repo + "/" + oci_name + ":" + version
oci_image_dataplane_debugger := oci_repo + "/" + oci_name + "/debugger:" + version
oci_image_dataplane_validator := oci_repo + "/" + oci_name + "/validator:" + version
oci_image_frr_dataplane := oci_repo + "/" + oci_frr_prefix + ":" + version
oci_image_frr_host := oci_repo + "/" + oci_frr_prefix + "-host:" + version

[private]
_skopeo_dest_insecure := if oci_insecure == "true" { "--dest-tls-verify=false" } else { "" }

[private]
docker_sock := "/var/run/docker.sock"

# Build a nix derivation with standard build arguments
[script]
build target="dataplane.tar" *args:
    {{ _just_debuggable_ }}
    mkdir -p results
    declare -r target="{{target}}"
    nix build -f default.nix "${target}" \
      --argstr profile '{{ profile }}' \
      --argstr sanitize '{{ sanitize }}' \
      --argstr libc '{{ libc }}' \
      --argstr kernel '{{ kernel }}' \
      --argstr features '{{ features }}' \
      --argstr default-features '{{ default_features }}' \
      --argstr instrumentation '{{ instrument }}' \
      --argstr platform '{{ platform }}' \
      --argstr tag '{{version}}' \
      --print-build-logs \
      --show-trace \
      --out-link "results/${target}" \
      --max-jobs {{jobs}} \
      --keep-failed \
      {{ args }}

# run formatters for the code used in this project
[script]
fmt *args:
    {{ _just_debuggable_ }}
    nix-shell --run "cargo fmt {{args}}"

# run a series of pre-flight checks to catch most problems you might find in CI early
[script]
pre-flight: (check-dependencies) (fmt "--check") (test) (lint) (doctest)
    {{ _just_debuggable_ }}
    echo "pre flight checks pass"

[script]
test package="tests.all" *args: (build (if package == "tests.all" { "tests.all" } else { "tests.pkg." + package }) args)
    {{ _just_debuggable_ }}
    declare -r target="{{ if package == "tests.all" { "tests.all" } else { "tests.pkg." + package } }}"
    nix-shell --run "cargo nextest run --archive-file results/${target}/*.tar.zst --workspace-remap $(pwd) {{ filter }}"

[script]
docs package="" *args: (build (if package == "" { "docs.all" } else { "docs.pkg." + package }) args)
    {{ _just_debuggable_ }}

# Create devroot and sysroot symlinks for local development
[script]
setup-roots *args:
    {{ _just_debuggable_ }}
    for root in devroot sysroot; do
      nix build -f default.nix "${root}" \
        --argstr profile '{{ profile }}' \
        --argstr sanitize '{{ sanitize }}' \
        --argstr instrumentation '{{ instrument }}' \
        --argstr platform '{{ platform }}' \
        --argstr tag '{{version}}' \
        --out-link "${root}" \
        {{ args }}
    done

# Build the dataplane container image
[script]
build-container target="dataplane" *args: (build (if target == "dataplane" { "dataplane.tar" } else if target == "validator" { "workspace.validator" } else { "containers." + target }) args)
    {{ _just_debuggable_ }}
    declare -xr DOCKER_HOST="${DOCKER_HOST:-unix://{{docker_sock}}}"
    case "{{target}}" in
        "dataplane")
            declare img
            img="$(docker import --change 'ENTRYPOINT ["/bin/dataplane"]' ./results/dataplane.tar)"
            declare -r img
            docker tag "${img}" "{{oci_image_dataplane}}"
            echo "imported {{ oci_image_dataplane }}"
            ;;
        "dataplane-debugger")
            docker load < ./results/containers.dataplane-debugger
            docker tag "ghcr.io/githedgehog/dataplane/debugger:{{version}}" "{{oci_image_dataplane_debugger}}"
            echo "imported {{ oci_image_dataplane_debugger }}"
            ;;
        "frr.dataplane")
            docker load < ./results/containers.frr.dataplane
            docker tag "ghcr.io/githedgehog/dpdk-sys/frr:{{version}}" "{{oci_image_frr_dataplane}}"
            echo "imported {{oci_image_frr_dataplane}}"
            ;;
        "frr.host")
            docker load < ./results/containers.frr.host
            docker tag "ghcr.io/githedgehog/dpdk-sys/frr-host:{{version}}" "{{oci_image_frr_host}}"
            echo "imported {{oci_image_frr_host}}"
            ;;
        "validator")
            echo "NOTE: validator image is wasm and not containerized"
            ;;
        *)
            >&2 echo "{{target}}" not a valid container
            exit 99
    esac

# Build and push the dataplane container
[script]
push-container target="dataplane" *args: (build-container target args) && version
    {{ _just_debuggable_ }}
    declare -xr DOCKER_HOST="${DOCKER_HOST:-unix://{{docker_sock}}}"
    case "{{target}}" in
        "dataplane")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} docker-daemon:{{ oci_image_dataplane }} docker://{{ oci_image_dataplane }}
            echo "Pushed {{ oci_image_dataplane }}"
            ;;
        "dataplane-debugger")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} docker-daemon:{{ oci_image_dataplane_debugger }} docker://{{ oci_image_dataplane_debugger }}
            echo "Pushed {{ oci_image_dataplane_debugger }}"
            ;;
        "frr.dataplane")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} docker-daemon:{{oci_image_frr_dataplane}} docker://{{oci_image_frr_dataplane}}
            echo "Pushed {{ oci_image_frr_dataplane }}"
            ;;
        "frr.host")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} docker-daemon:{{oci_image_frr_host}} docker://{{oci_image_frr_host}}
            echo "Pushed {{ oci_image_frr_host }}"
            ;;
        "validator")
            if [ "{{platform}}" != "wasm32-wasip1" ]; then
              >&2 echo "Pushing non wasm32-wasip1 validator images is not supported, set platform=wasm32-wasip1"
              exit 1
            fi
            pushd ./results/workspace.validator/bin
            oras push --annotation version="{{ version }}" "{{ oci_image_dataplane_validator }}" ./validator.wasm
            popd
            echo "Pushed {{ oci_image_dataplane_validator }}"
            ;;
        *)
            >&2 echo "{{target}}" not a valid container
            exit 99
    esac

# Note: deliberately ignores all recipe parameters save version, debug_justfile, and oci_repo.
# Pushes all release container images.
[script]
push:
    {{ _just_debuggable_ }}
    for container in dataplane frr.dataplane validator; do
        if [ "${container}" = "validator" ]; then
          platform="wasm32-wasip1"
        else
          platform="x86-64-v3"
        fi
        nix-shell --run "just debug_justfile={{debug_justfile}} oci_repo={{oci_repo}} version={{version}} profile=release platform=${platform} sanitize= instrument=none push-container ${container}"
    done

# Print names of container images to build or push
[script]
print-container-tags:
    echo "{{ oci_image_dataplane }}"

# Check dependency licenses and security advisories
[script]
check-dependencies *args:
    {{ _just_debuggable_ }}
    nix-shell --run "cargo deny {{ _cargo_feature_flags }} check {{ args }}"

# Run linters
[script]
lint *args:
    {{ _just_debuggable_ }}
    nix-shell --run "cargo clippy --all-targets {{ _cargo_feature_flags }} {{ _cargo_profile_flag }} {{ args }} -- -D warnings"

# Run doctests
[script]
doctest *args:
    {{ _just_debuggable_ }}
    nix-shell --run "cargo test --doc {{ _cargo_feature_flags }} {{ _cargo_profile_flag }} {{ args }}"

# Run tests with code coverage. Args will be forwarded to nextest
[script]
coverage target="tests.all" *args: (build (if target == "tests.all" { "tests.all" } else { "tests.pkg." + target }) args)
    {{ _just_debuggable_ }}
    declare -r target="{{ if target == "tests.all" { "tests.all" } else { "tests.pkg." + target } }}"
    export LLVM_COV="$(pwd)/devroot/bin/llvm-cov"
    export LLVM_PROFDATA="$(pwd)/devroot/bin/llvm-profdata"
    export CARGO_LLVM_COV_TARGET_DIR="$(pwd)/target/llvm-cov"
    export CARGO_LLVM_COV_BUILD_DIR="$(pwd)"
    cargo llvm-cov clean
    cargo llvm-cov show-env
    cargo llvm-cov --no-report --branch nextest --archive-file "./results/${target}/"*.tar.zst --workspace-remap . {{ args }}
    # NOTE: --profile="" is intentional. When collecting coverage from a nextest archive, the
    # profile path component that cargo-llvm-cov normally expects in the profdata directory is
    # absent. Passing an empty profile string removes that component from the lookup path so
    # the tool can find the profdata generated by the archive run above.
    cargo llvm-cov report --html --profile="" --output-dir=./target/nextest/coverage
    cargo llvm-cov --branch report --codecov --profile="" --output-path=./target/nextest/coverage/codecov.json

# Regenerate the dependency graph for the project
[script]
depgraph:
    {{ _just_debuggable_ }}
    cargo depgraph --exclude dataplane-test-utils,dataplane-dpdk-sysroot-helper --workspace-only \
      | sed 's/dataplane-//g' \
      | dot -Grankdir=TD -Gsplines=polyline -Granksep=1.5 -Tsvg > workspace-deps.svg

# Bump the minor version in Cargo.toml and reset patch version to 0
[script]
bump_minor_version:
    CURRENT_VERSION="$(tomlq --raw-output '.workspace.package.version' Cargo.toml)"
    echo "Current version: ${CURRENT_VERSION}"
    MAJOR_VNUM="$(cut -d. -f1 <<<"${CURRENT_VERSION}")"
    MINOR_VNUM="$(cut -d. -f2 <<<"${CURRENT_VERSION}")"
    NEW_VERSION="${MAJOR_VNUM}.$((MINOR_VNUM + 1)).0"
    just bump_version "${NEW_VERSION}"

# Bump the version in Cargo.toml to the specified version (for example, "1.2.3")
[script]
bump_version version:
    echo "New version: {{ version }}"
    sed -i "s/^version = \".*\"/version = \"{{ version }}\"/" Cargo.toml
    cargo update --workspace

# ---- Fuzzing recipes -------------------------------------------------------

# List available fuzz targets as JSON lines (pipe through `jq` for formatting)
#
# Each line is a JSON object: {"package":"<crate>","test":"<test::path>"}
#
# Examples:
#   just fuzz-list                                  # all targets, JSON
#   just fuzz-list | jq -r '.test'                  # just test names
#   just fuzz-list fuzz_package=dataplane-net        # one crate
#   just fuzz-list | jq -s '.'                      # as a JSON array
[script]
fuzz-list:
    {{ _just_debuggable_ }}
    cargo bolero list {{ _bolero_pkg_flag }} {{ _cargo_feature_flags }} 2>/dev/null \
      | sed '/^$/d'

# List fuzz targets in a human-readable table
[script]
fuzz-list-pretty:
    {{ _just_debuggable_ }}
    printf "%-40s %s\n" "PACKAGE" "TEST"
    printf "%-40s %s\n" "-------" "----"
    cargo bolero list {{ _bolero_pkg_flag }} {{ _cargo_feature_flags }} 2>/dev/null \
      | sed '/^$/d' \
      | jq -r '[.package, .test] | @tsv' \
      | while IFS=$'\t' read -r pkg test; do
          printf "%-40s %s\n" "${pkg}" "${test}"
        done

# Run a single fuzz target with the configured engine and duration
#
# Examples:
#   just fuzz-run icmp4::test::parse_back
#   just fuzz-run tcp::test::parse_noise fuzz_engine=honggfuzz fuzz_duration=5m
#   just fuzz-run icmp4::test::parse_back fuzz_package=dataplane-net fuzz_sanitizer=thread
[script]
fuzz-run target:
    {{ _just_debuggable_ }}
    echo "fuzz: target={{ target }} engine={{ fuzz_engine }} duration={{ fuzz_duration }} profile={{ fuzz_profile }} sanitizer={{ fuzz_sanitizer }}"
    cargo bolero test "{{ target }}" \
      {{ _bolero_pkg_flag }} \
      -e {{ fuzz_engine }} \
      -T {{ fuzz_duration }} \
      {{ _bolero_san_flag }} \
      --profile {{ fuzz_profile }} \
      {{ _cargo_feature_flags }}

# Run every fuzz target for the configured duration (default 1m each)
#
# Iterates over all bolero targets (optionally filtered by fuzz_package)
# and runs each one sequentially.
#
# Examples:
#   just fuzz-all                                       # all targets, 1m each
#   just fuzz-all fuzz_duration=10s                     # quick smoke test
#   just fuzz-all fuzz_package=dataplane-net fuzz_duration=5m
[script]
fuzz-all:
    {{ _just_debuggable_ }}
    targets="$(cargo bolero list {{ _bolero_pkg_flag }} {{ _cargo_feature_flags }} 2>/dev/null | sed '/^$/d')"
    total="$(echo "${targets}" | wc -l)"
    echo "=== Fuzzing ${total} targets for {{ fuzz_duration }} each ==="
    echo "    engine={{ fuzz_engine }}  profile={{ fuzz_profile }}  sanitizer={{ fuzz_sanitizer }}"
    echo "---"
    i=0
    failed=0
    echo "${targets}" | jq -r '[.package, .test] | @tsv' | while IFS=$'\t' read -r pkg test; do
      i=$((i + 1))
      echo "[${i}/${total}] ${pkg}::${test}"
      if ! cargo bolero test "${test}" \
        -p "${pkg}" \
        -e {{ fuzz_engine }} \
        -T {{ fuzz_duration }} \
        {{ _bolero_san_flag }} \
        --profile {{ fuzz_profile }} \
        {{ _cargo_feature_flags }}; then
        echo "  ^^^ FAILED: ${pkg}::${test}"
        failed=$((failed + 1))
      fi
    done
    echo "---"
    if [ "${failed}" -gt 0 ]; then
      echo "FAIL: ${failed}/${total} fuzz targets had failures"
      exit 1
    fi
    echo "OK: all ${total} fuzz targets completed successfully."

# Enter nix-shell
[script]
shell:
   nix-shell
