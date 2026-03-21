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
jobs := "1"

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

# filters for nextest
filter := ""

# instrumentation mode (none/coverage)
instrument := "none"

# target platform (x86-64-v3/bluefield2)
platform := "x86-64-v3"

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
build-container target="dataplane" *args: (build (if target == "dataplane" { "dataplane.tar" } else { "containers." + target }) args)
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
        *)
            >&2 echo "{{target}}" not a valid container
            exit 99
    esac

# Pushes all release container images.
# Note: deliberately ignores all recipe parameters save version and debug_justfile.
[script]
push:
    {{ _just_debuggable_ }}
    for container in dataplane frr.dataplane; do
        nix-shell --run "just debug_justfile={{debug_justfile}} oci_repo={{oci_repo}} version={{version}} profile=release platform=x86-64-v3 sanitize= instrument=none push-container ${container}"
    done

# Print names of container images to build or push
[script]
print-container-tags:
    echo "{{ oci_image_dataplane }}"

# Run linters
[script]
lint *args:
    {{ _just_debuggable_ }}
    nix-shell --run "cargo clippy --all-targets --all-features {{ args }} -- -D warnings"

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
bump_minor_version yq_flags="":
    CURRENT_VERSION="$(yq -r {{ yq_flags }} '.workspace.package.version' Cargo.toml)"
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

# Enter nix-shell
[script]
shell:
   nix-shell
