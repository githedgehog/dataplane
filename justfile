# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := [x"${SHELL:-bash}", "-euo", "pipefail", "-c"]
set script-interpreter := [x"${SHELL:-bash}", "-euo", "pipefail"]

# enable to debug just recipes

debug_justfile := "false"
[private]
_just_debuggable_ := if debug_justfile == "true" { "set -x" } else { "" }

# List out the available commands
[private]
[default]
@default:
    just --list --justfile {{ justfile() }}

# cargo build profile (debug/release/fuzz)
profile := "debug"

# sanitizer to use (address/thread/"")
sanitize := ""

# instrumentation mode (none/coverage)
instrument := "none"

# target platform (x86-64-v3/bluefield2)
platform := "x86-64-v3"

# comma delimited list of sanitizers to use with bolero
sanitizers := "address,leak"

version_extra := ""
version_platform := if platform == "x86-64-v3" { "" } else { "-" + platform }
version_profile := if profile == "release" { "" } else { "-" + profile }
version := env("VERSION", "") || `git describe --tags --dirty --always` + version_platform + version_profile + version_extra

# Print version that will be used in the build
version:
  @echo "Using version: {{version}}"

# OCI repo to push images to

oci_repo := "127.0.0.1:30000"
oci_insecure := ""
oci_name := "githedgehog/dataplane"
oci_image_full := oci_repo + "/" + oci_name + ":" + version

[private]
_skopeo_dest_insecure := if oci_insecure == "true" { "--dest-tls-verify=false" } else { "" }

# Build a nix derivation with standard build arguments
[script]
build target *args:
    {{ _just_debuggable_ }}
    nix build -f default.nix {{ target }} \
      --argstr profile {{ profile }} \
      --argstr sanitize '{{ sanitize }}' \
      --argstr instrumentation {{ instrument }} \
      --argstr platform {{ platform }} \
      {{ args }}

# Create devroot and sysroot symlinks for local development
[script]
setup-roots *args:
    {{ _just_debuggable_ }}
    nix build -f default.nix devroot \
      --argstr profile {{ profile }} \
      --argstr sanitize '{{ sanitize }}' \
      --argstr instrumentation {{ instrument }} \
      --argstr platform {{ platform }} \
      --out-link devroot \
      {{ args }}
    nix build -f default.nix sysroot \
      --argstr profile {{ profile }} \
      --argstr sanitize '{{ sanitize }}' \
      --argstr instrumentation {{ instrument }} \
      --argstr platform {{ platform }} \
      --out-link sysroot \
      {{ args }}

# Build the dataplane container tar
[script]
build-container *args:
    {{ _just_debuggable_ }}
    mkdir -p results
    nix build -f default.nix dataplane-tar \
      --argstr profile {{ profile }} \
      --argstr sanitize '{{ sanitize }}' \
      --argstr instrumentation {{ instrument }} \
      --argstr platform {{ platform }} \
      --out-link results/dataplane.tar \
      {{ args }}
    docker import ./results/dataplane.tar dataplane:{{version}}

# Build and push the dataplane container
[script]
push: build-container && version
    {{ _just_debuggable_ }}
    skopeo copy \
      {{ _skopeo_dest_insecure }} \
      docker://dataplane:{{version}} \
      docker://{{ oci_image_full }}
    echo "Pushed {{ oci_image_full }}"

# Print names of container images to build or push
[script]
print-container-tags:
    echo "{{ oci_image_full }}"

# Run Clippy
[script]
clippy *args:
    {{ _just_debuggable_ }}
    cargo clippy --all-targets --all-features {{ args }} -- -D warnings

# List available bolero fuzz tests
[script]
list-fuzz-tests *args:
    {{ _just_debuggable_ }}
    cargo bolero list --sanitizer={{ sanitizers }} --build-std --profile=fuzz {{ args }}

# Run the full fuzzer / property-checker on a bolero test. Args are forwarded to bolero
[script]
fuzz test timeout="-T 60sec" *args="--engine=libfuzzer --engine-args=-max_len=65536":
    {{ _just_debuggable_ }}
    cargo bolero test {{ test }} --build-std --profile=fuzz --sanitizer={{ sanitizers }} {{ timeout }} {{ args }}

# Run the full fuzzer / property-checker on a bolero test with the AFL fuzzer
fuzz-afl test: (fuzz test "" "--engine=afl" "--engine-args=-mnone")

# Allocate 2M hugepages (if needed)
[private]
[script]
allocate-2M-hugepages hugepages_2m="1024":
    {{ _just_debuggable_ }}
    pages=$(< /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages)
    if [ "$pages" -gt {{ hugepages_2m }} ]; then
      >&2 echo "INFO: ${pages} 2M hugepages already allocated"
      exit 0
    fi
    printf -- "%s" {{ hugepages_2m }} | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages >/dev/null

# Allocate 1G hugepages (if needed)
[private]
[script]
allocate-1G-hugepages hugepages_1g="8":
    {{ _just_debuggable_ }}
    pages=$(< /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages)
    if [ "$pages" -gt {{ hugepages_1g }} ]; then
      >&2 echo "INFO: ${pages} 1G hugepages already allocated"
      exit 0
    fi
    printf -- "%s" {{ hugepages_1g }} | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages >/dev/null

# umount hugepage mounts created by dataplane
[private]
[script]
umount-hugepages:
    {{ _just_debuggable_ }}
    declare hugemnt2M
    hugemnt2M="/run/user/$(id -u)/hedgehog/dataplane/hugepages/2M"
    declare -r hugemnt2M
    declare hugemnt1G
    hugemnt1G="/run/user/$(id -u)/hedgehog/dataplane/hugepages/1G"
    declare -r hugemnt1G
    if [ "$(findmnt -rno FSTYPE "${hugemnt2M}")" = "hugetlbfs" ]; then
      sudo umount --lazy "${hugemnt2M}"
    fi
    if [ "$(findmnt -rno FSTYPE "${hugemnt1G}")" = "hugetlbfs" ]; then
        sudo umount --lazy "${hugemnt1G}"
    fi
    sync

# mount hugetlbfs
[private]
[script]
mount-hugepages:
    {{ _just_debuggable_ }}
    declare hugemnt2M
    hugemnt2M="/run/user/$(id -u)/hedgehog/dataplane/hugepages/2M"
    declare -r hugemnt2M
    declare hugemnt1G
    hugemnt1G="/run/user/$(id -u)/hedgehog/dataplane/hugepages/1G"
    declare -r hugemnt1G
    [ ! -d "$hugemnt2M" ] && mkdir --parent "$hugemnt2M"
    [ ! -d "$hugemnt1G" ] && mkdir --parent "$hugemnt1G"
    if [ ! "$(findmnt -rno FSTYPE "${hugemnt2M}")" = "hugetlbfs" ]; then
      sudo mount -t hugetlbfs -o pagesize=2M,noatime hugetlbfs "$hugemnt2M"
    fi
    if [ ! "$(findmnt -rno FSTYPE "${hugemnt1G}")" = "hugetlbfs" ]; then
      sudo mount -t hugetlbfs -o pagesize=1G,noatime hugetlbfs "$hugemnt1G"
    fi
    sync

# Set up the environment for testing locally
setup-test-env: allocate-2M-hugepages allocate-1G-hugepages mount-hugepages

# Tear down environment for testing locally
teardown-test-env: umount-hugepages

# Build for each separate commit (for "pull_request") or for the HEAD of the branch (other events)
[script]
build-sweep start="main":
    {{ _just_debuggable_ }}
    set -euo pipefail
    if ! git diff-index --quiet HEAD -- 2>/dev/null || [ -n "$(git ls-files --exclude-standard --others)" ]; then
      >&2 echo "can not build-sweep with dirty branch (would risk data loss)"
      >&2 git status
      exit 1
    fi
    INIT_HEAD=$(git rev-parse --abbrev-ref HEAD)
    # Get all commits since {{ start }}, in chronological order
    while read -r commit; do
      git -c advice.detachedHead=false checkout "${commit}" || exit 1
      { cargo build --locked --profile=dev; } || exit 1
    done < <(git rev-list --reverse "{{ start }}".."$(git rev-parse HEAD)")
    # Return to the initial branch if any (exit "detached HEAD" state)
    git checkout "${INIT_HEAD}"

# Serve rustdoc output locally (using port 8000)
[script]
rustdoc-serve:
    echo "Launching web server, hit Ctrl-C to stop."
    python -m http.server -d "target/doc"

# Run tests with code coverage. Args will be forwarded to nextest
[script]
coverage *args:
    {{ _just_debuggable_ }}
    cargo llvm-cov clean --workspace
    cargo llvm-cov --no-report --branch --remap-path-prefix nextest --cargo-profile=fuzz {{ args }}
    cargo llvm-cov report --html --output-dir=./target/nextest/coverage --profile=fuzz
    cargo llvm-cov report --json --output-path=./target/nextest/coverage/report.json --profile=fuzz
    cargo llvm-cov report --codecov --output-path=./target/nextest/coverage/codecov.json --profile=fuzz

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
    CURRENT_VERSION=$(yq '.workspace.package.version' Cargo.toml)
    echo "Current version: ${CURRENT_VERSION}"
    MAJOR_VNUM=$(echo ${CURRENT_VERSION} | cut -d. -f1)
    MINOR_VNUM=$(echo ${CURRENT_VERSION} | cut -d. -f2)
    NEW_VERSION="${MAJOR_VNUM}.$((MINOR_VNUM + 1)).0"
    echo "New version: ${NEW_VERSION}"
    sed -i "s/^version = \".*\"/version = \"${NEW_VERSION}\"/" Cargo.toml
    cargo update -w

# Enter nix-shell
[script]
shell:
   nix-shell
