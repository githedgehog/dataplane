# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := [x"${SHELL:-bash}", "-euo", "pipefail", "-c"]
set script-interpreter := [x"${SHELL:-bash}", "-euo", "pipefail"]
set dotenv-load := true
set dotenv-required := true
set dotenv-path := "."
set dotenv-filename := "./scripts/rust.env"

# enable to debug just recipes

debug_justfile := "false"
[private]
dpdk_sys_commit := shell("source ./scripts/dpdk-sys.env && echo $DPDK_SYS_COMMIT")
[private]
_just_debuggable_ := if debug_justfile == "true" { "set -x" } else { "" }

# Set to FUZZ to run the full fuzzer in the fuzz recipe
_test_type := "DEFAULT"

# comma delimited list of sanitizers to use with bolero
sanitizers := "address,leak"

# the tripple to compile for
target := "x86_64-unknown-linux-gnu"

# cargo build profile to use
profile := "debug"
[private]
_container_repo := "ghcr.io/githedgehog/dataplane"

# Docker images
[private]
_image_profile := if profile == "debug" { "debug" } else { "release" }
[private]
_dpdk_sys_container_repo := "ghcr.io/githedgehog/dpdk-sys"
[private]
_dpdk_sys_container_tag := dpdk_sys_commit

[private]
_libc_container := _dpdk_sys_container_repo + "/libc-env:" + _dpdk_sys_container_tag + "." + _image_profile

[private]
_debug_env_container := _dpdk_sys_container_repo + "/debug-env:" + _dpdk_sys_container_tag + "." + _image_profile
[private]
_compile_env_image_name := _dpdk_sys_container_repo + "/compile-env"
[private]
_compile_env_container := _compile_env_image_name + ":" + _dpdk_sys_container_tag + "." + _image_profile

# Base container for the dataplane build
[private]
_dataplane_base_container := if _image_profile == "release" { _libc_container } else { _debug_env_container }

# Warn if the compile-env image is deprecated (or missing)

[private]
_compile_env_check := if shell('docker image list --format "{{.Repository}}:{{.Tag}}" | grep -x "' + _compile_env_container + '" || true') == '' { shell('printf "\n/!\\ Latest compile-env not found, try \"just refresh-compile-env\"\n\n" >&2') } else { '' }

# Docker settings

[private]
_network := "host"
[private]
_docker_sock_cmd := replace_regex(_just_debuggable_, ".+", "$0;") + '''
  declare -r DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"
  declare -r without_unix="${DOCKER_HOST##unix://}"
  if [ -S "${without_unix}" ]; then
    printf -- '%s' "${without_unix}"
  elif [ -S "/run/docker/docker.sock" ]; then
    printf -- '%s' "/run/docker/docker.sock"
  elif [ -S /var/run/docker.sock ]; then
    printf -- '%s' "/var/run/docker.sock"
  fi
'''
export DOCKER_HOST := x"${DOCKER_HOST:-unix:///var/run/docker.sock}"
export DOCKER_SOCK := shell(_docker_sock_cmd)

# The git commit hash of the last commit to HEAD
# We allow this command to fail in the sterile environment because git is not available there

[private]
_commit := `git rev-parse HEAD 2>/dev/null || echo "sterile"`

# The git branch we are currnetly on
# We allow this command to fail in the sterile environment because git is not available there

[private]
_branch := `(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "sterile") | tr -c '[:alnum:]\n' '-'`

# The git tree state (clean or dirty)
# We allow this command to fail in the sterile environment because git is not available there

[private]
_clean := ```
  set -euo pipefail
  (
    git diff-index --quiet HEAD -- 2>/dev/null && \
    test -z "$(git ls-files --exclude-standard --others)" && \
    echo clean \
  ) || echo dirty
```

# The slug is the branch name (sanitized) with a marker if the tree is dirty

[private]
_slug := (if _clean == "clean" { "" } else { "dirty." }) + _branch

# Define a function to truncate long lines to the limit for containers tags

[private]
_define_truncate128 := 'truncate128() { printf -- "%s" "${1::128}" ; }'

# The time of the build (in iso8601 utc)

[private]
_build_time := datetime_utc("%+")

# List out the available commands
[private]
@default:
    just --list --justfile {{ justfile() }}

# Run cargo with RUSTFLAGS computed based on profile
[script]
cargo *args:
    # Ideally this would be done via Cargo.toml and .cargo/config.toml,
    # unfortunately passing RUSTFLAGS based on profile (rather than target or cfg)
    # is currently unstable (nightly builds only).
    {{ _just_debuggable_ }}
    export PATH="$(pwd)/compile-env/bin:${PATH}"
    declare -a args=({{ args }})
    declare -a extra_args=()
    for arg in "${args[@]}"; do
      case "$arg" in
        --debug|--profile=debug|--cargo-profile=debug)
          declare -rx RUSTFLAGS="${RUSTFLAGS_DEBUG}"
          declare -rx LIBC_ENV_PROFILE="debug"
          ;;
        --release|--profile=release|--cargo-profile=release)
          declare -rx RUSTFLAGS="${RUSTFLAGS_RELEASE}"
          extra_args+=("$arg")
          ;;
        --profile=fuzz|--cargo-profile=fuzz)
          declare -rx RUSTFLAGS="${RUSTFLAGS_FUZZ}"
          export RUSTC_BOOTSTRAP=1
          extra_args+=("$arg")
          ;;
        *)
          extra_args+=("$arg")
          ;;
      esac
    done
    if [ -z "${RUSTFLAGS:-}" ]; then
      declare -rx RUSTFLAGS="${RUSTFLAGS_DEBUG}"
    fi

    export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} ${RUSTFLAGS} --html-in-header $(pwd)/scripts/doc/custom-header.html"
    ./compile-env/bin/cargo "${extra_args[@]}"

# Run the (very minimal) compile environment
[script]
compile-env *args:
    {{ _just_debuggable_ }}
    mkdir -p dev-env-template/etc
    if [ -z "${UID:-}" ]; then
      >&2 echo "ERROR: environment variable UID not set"
    fi
    declare -rxi UID
    GID="$(id -g)"
    declare -rxi GID
    declare -rx USER="${USER:-runner}"
    declare  DOCKER_GID
    DOCKER_GID="$(getent group docker | cut -d: -f3)"
    declare -rxi DOCKER_GID
    envsubst < dev-env-template/etc.template/group.template > dev-env-template/etc/group
    envsubst < dev-env-template/etc.template/passwd.template > dev-env-template/etc/passwd
    mkdir -p "$(pwd)/sterile"
    declare CARGO_TARGET_DIR
    CARGO_TARGET_DIR="$(pwd)/target"
    mkdir -p "${CARGO_TARGET_DIR}"
    sudo -E docker run \
      --rm \
      --interactive \
      --network="{{ _network }}" \
      --env DOCKER_HOST="${DOCKER_HOST}" \
      --env CARGO_TARGET_DIR="${CARGO_TARGET_DIR}" \
      --env DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}" \
      --env TEST_TYPE="{{ _test_type }}" \
      --tmpfs "/tmp:uid=$(id -u),gid=$(id -g),nodev,noexec,nosuid" \
      --mount "type=tmpfs,destination=/home/${USER:-runner},tmpfs-mode=1777" \
      --mount "type=bind,source=$(pwd),destination=$(pwd),bind-propagation=rprivate" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/passwd,destination=/etc/passwd,readonly" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/group,destination=/etc/group,readonly" \
      --mount "type=bind,source=${CARGO_TARGET_DIR},destination=${CARGO_TARGET_DIR}" \
      --mount "type=bind,source={{ DOCKER_SOCK }},destination={{ DOCKER_SOCK }}" \
      --user "$(id -u):$(id -g)" \
      --device "/dev/kvm" \
      --device "/dev/vhost-net" \
      --device "/dev/vhost-vsock" \
      --cap-drop ALL \
      --cap-add SETUID `# needed for sudo in test-runner` \
      --cap-add SETGID `# needed for sudo in test-runner` \
      --cap-add SETFCAP `# needed by test-runner to grant/limit caps of tests` \
      --read-only \
      --group-add="$(getent group docker | cut -d: -f3)" \
      --workdir "$(pwd)" \
      "{{ _compile_env_container }}" \
      {{ args }}

# Pull the latest versions of the containers
[script]
pull:
    {{ _just_debuggable_ }}
    sudo -E docker pull "{{ _compile_env_container }}"

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

# Dump the compile-env container into a sysroot for use by the build
[script]
create-compile-env:
    {{ _just_debuggable_ }}
    mkdir compile-env
    sudo -E docker create --name dpdk-sys-compile-env-{{ _slug }} "{{ _compile_env_container }}" - fake
    sudo -E docker export dpdk-sys-compile-env-{{ _slug }} \
      | tar --no-same-owner --no-same-permissions -xf - -C compile-env
    sudo -E docker rm dpdk-sys-compile-env-{{ _slug }}

# remove the compile-env directory
[confirm("Remove old compile environment? (yes/no)\n(you can recreate it with `just create-compile-env`)")]
[script]
remove-compile-env:
    {{ _just_debuggable_ }}
    if [ -d compile-env ]; then sudo rm -rf compile-env; fi

# refresh the compile-env (clear and restore)
[script]
refresh-compile-env: pull remove-compile-env create-compile-env

# clean up (delete) old compile-env images from system
[script]
prune-old-compile-env:
    {{ _just_debuggable_ }}
    docker image list "{{ _compile_env_image_name }}" --format "{{{{.Repository}}:{{{{.Tag}}" | \
        grep -v "{{ _dpdk_sys_container_tag }}" | \
        xargs -r docker image rm

# Install "fake-nix" (required for local builds to function)
[confirm("Fake a nix install (yes/no)")]
[script]
fake-nix refake="":
    {{ _just_debuggable_ }}
    if [ -h /nix ]; then
      if [ "$(readlink -e /nix)" = "$(readlink -e "$(pwd)/compile-env/nix")" ]; then
        >&2 echo "Nix already faked!"
        exit 0
      else
        if [ "{{ refake }}" = "refake" ]; then
          sudo rm /nix
        else
          >&2 echo "Nix already faked elsewhere!"
          >&2 echo "Run \`just fake-nix refake\` to re-fake to this location"
          exit 1
        fi
      fi
    elif [ -d /nix ]; then
      >&2 echo "Nix already installed, can't fake it!"
      exit 1
    fi
    if [ ! -d ./compile-env/nix ]; then
      just refresh-compile-env
    fi
    if [ ! -d ./compile-env/nix ]; then
      >&2 echo "Failed to create nix environment"
      exit 1
    fi
    sudo ln -rs ./compile-env/nix /nix

# Run a "sterile" command
sterile *args: \
  (cargo "clean") \
  (compile-env "just" \
    ("debug_justfile=" + debug_justfile) \
    ("target=" + target) \
    ("profile=" + profile) \
    ("_test_type=" + _test_type) \
    ("sanitizers=" + sanitizers) \
    args \
  )

# Run the full fuzzer / property-checker on a bolero test. Args are forwarded to bolero
[script]
list-fuzz-tests *args: (cargo "bolero" "list" ("--sanitizer=" + sanitizers) "--build-std" "--profile=fuzz" args)

# Run the full fuzzer / property-checker on a bolero test. Args are forwarded to bolero
fuzz test timeout="-T 60sec" *args="--engine=libfuzzer --engine-args=-max_len=65536": ( \
  compile-env \
    "just" \
    "_test_type=FUZZ" \
    "cargo" \
    "bolero" \
    "test" \
    test \
    "--build-std" \
    "--profile=fuzz" \
    ("--sanitizer=" + sanitizers) \
    timeout \
    args \
  )

# Run the full fuzzer / property-checker on a bolero test with the AFL fuzzer
[script]
fuzz-afl test: (fuzz test "" "--engine=afl" "--engine-args=-mnone")

[script]
sh *args:
    /bin/sh -i -c "{{ args }}"

# Build containers in a sterile environment
[script]
build-container: (sterile "_network=none" "cargo" "--locked" "build" ("--profile=" + profile) ("--target=" + target) "--package=dataplane" "--package=dataplane-cli")
    {{ _just_debuggable_ }}
    {{ _define_truncate128 }}
    mkdir -p "artifact/{{ target }}/{{ profile }}"
    cp -r "${CARGO_TARGET_DIR:-target}/{{ target }}/{{ profile }}/dataplane" "artifact/{{ target }}/{{ profile }}/dataplane"
    cp -r "${CARGO_TARGET_DIR:-target}/{{ target }}/{{ profile }}/cli" "artifact/{{ target }}/{{ profile }}/dataplane-cli"
    declare build_date
    build_date="$(date --utc --iso-8601=date --date="{{ _build_time }}")"
    declare -r build_date
    declare build_time_epoch
    build_time_epoch="$(date --utc '+%s' --date="{{ _build_time }}")"
    declare -r build_time_epoch
    declare -r TAG="{{ _container_repo }}:$(truncate128 "${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")"
    sudo -E docker build \
      --label "git.commit={{ _commit }}" \
      --label "git.branch={{ _branch }}" \
      --label "git.tree-state={{ _clean }}" \
      --label "build.date=${build_date}" \
      --label "build.timestamp={{ _build_time }}" \
      --label "build.time_epoch=${build_time_epoch}" \
      --tag "${TAG}" \
      --build-arg ARTIFACT="artifact/{{ target }}/{{ profile }}/dataplane" \
      --build-arg ARTIFACT_CLI="artifact/{{ target }}/{{ profile }}/dataplane-cli" \
      --build-arg BASE="{{ _dataplane_base_container }}" \
      .

    sudo -E docker tag \
      "${TAG}" \
      "{{ _container_repo }}:$(truncate128 "{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")"
    sudo -E docker tag \
      "${TAG}" \
      "{{ _container_repo }}:$(truncate128 "{{ _slug }}.{{ target }}.{{ profile }}")"
    if [ "{{ target }}" = "x86_64-unknown-linux-gnu" ]; then
      sudo -E docker tag \
        "${TAG}" \
        "{{ _container_repo }}:$(truncate128 "{{ _slug }}.{{ profile }}")"
    fi
    if [ "{{ target }}" = "x86_64-unknown-linux-gnu" ] && [ "{{ profile }}" = "release" ]; then
      sudo -E docker tag \
        "${TAG}" \
        "{{ _container_repo }}:$(truncate128 "{{ _slug }}")"
    fi

# Build a container for local testing, without cache and extended base
[script]
build-container-quick: (compile-env "cargo" "--locked" "build" ("--target=" + target) "--package=dataplane" "--package=dataplane-cli")
    {{ _just_debuggable_ }}
    {{ _define_truncate128 }}
    mkdir -p "artifact/{{ target }}/{{ profile }}"
    cp -r "${CARGO_TARGET_DIR:-target}/{{ target }}/{{ profile }}/dataplane" "artifact/{{ target }}/{{ profile }}/dataplane"
    cp -r "${CARGO_TARGET_DIR:-target}/{{ target }}/{{ profile }}/cli" "artifact/{{ target }}/{{ profile }}/dataplane-cli"
    declare build_date
    build_date="$(date --utc --iso-8601=date --date="{{ _build_time }}")"
    declare -r build_date
    declare -r TAG="{{ _container_repo }}:$(truncate128 "${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")"
    sudo -E docker build \
      --label "git.commit={{ _commit }}" \
      --label "git.branch={{ _branch }}" \
      --label "git.tree-state={{ _clean }}" \
      --label "build.date=${build_date}" \
      --label "build.timestamp={{ _build_time }}" \
      --tag "${TAG}" \
      --build-arg ARTIFACT="artifact/{{ target }}/{{ profile }}/dataplane" \
      --build-arg ARTIFACT_CLI="artifact/{{ target }}/{{ profile }}/dataplane-cli" \
      --build-arg BASE="{{ _debug_env_container }}" \
      .

    sudo -E docker tag "${TAG}" "dataplane:local-testing-latest"

# Build and push containers
[script]
push-container: build-container
    {{ _define_truncate128 }}
    declare build_date
    build_date="$(date --utc --iso-8601=date --date="{{ _build_time }}")"
    declare -r build_date
    sudo -E docker push "{{ _container_repo }}:$(truncate128 "${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")"
    sudo -E docker push "{{ _container_repo }}:$(truncate128 "{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")"
    if [ "{{ target }}" = "x86_64-unknown-linux-gnu" ]; then
      sudo -E docker push "{{ _container_repo }}:$(truncate128 "{{ _slug }}.{{ profile }}")"
    fi
    if [ "{{ target }}" = "x86_64-unknown-linux-gnu" ] && [ "{{ profile }}" = "release" ]; then
      sudo -E docker push "{{ _container_repo }}:$(truncate128 "{{ _slug }}")"
    fi

# Run Clippy like you're in CI
[script]
clippy *args: (cargo "clippy" "--all-targets" "--all-features" args "--" "-D" "warnings")

# Serve rustdoc output locally (using port 8000)
[script]
rustdoc-serve:
    echo "Launching web server, hit Ctrl-C to stop."
    python -m http.server -d "target/{{ target }}/doc"

# Build for each separate commit (for "pull_request") or for the HEAD of the branch (other events)
[script]
build-sweep start="main":
    {{ _just_debuggable_ }}
    set -euo pipefail
    if [ {{ _clean }} != "clean" ]; then
      >&2 echo "can not build-sweep with dirty branch (would risk data loss)"
      >&2 git status
      exit 1
    fi
    INIT_HEAD=$(git rev-parse --abbrev-ref HEAD)
    # Get all commits since {{ start }}, in chronological order
    while read -r commit; do
      git -c advice.detachedHead=false checkout "${commit}" || exit 1
      { just debug_justfile={{ debug_justfile }} cargo build --locked --profile=dev --target=x86_64-unknown-linux-gnu; } || exit 1
    done < <(git rev-list --reverse "{{ start }}".."$(git rev-parse HEAD)")
    # Return to the initial branch if any (exit "detached HEAD" state)
    git checkout "${INIT_HEAD}"

# Run tests with code coverage.  Args will be forwarded to nextest
[script]
coverage *args: \
  (cargo "llvm-cov" "clean" "--workspace") \
  (cargo "llvm-cov" "--no-report" "--branch" "--remap-path-prefix" "nextest" "--cargo-profile=fuzz" args) \
  (cargo "llvm-cov" "report" "--html" "--output-dir=./target/nextest/coverage" "--profile=fuzz") \
  (cargo "llvm-cov" "report" "--json" "--output-path=./target/nextest/coverage/report.json" "--profile=fuzz") \
  (cargo "llvm-cov" "report" "--codecov" "--output-path=./target/nextest/coverage/codecov.json" "--profile=fuzz")


# regenerate the dependency graph for the project
[script]
depgraph:
  just cargo depgraph --exclude dataplane-test-utils,dataplane-dpdk-sysroot-helper  --workspace-only \
    | sed 's/dataplane-//g' \
    | dot -Grankdir=TD -Gsplines=polyline -Granksep=1.5 -Tsvg > workspace-deps.svg
