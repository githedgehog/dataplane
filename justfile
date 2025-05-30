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

# the tripple to compile for

target := "x86_64-unknown-linux-gnu"

# cargo build profile to use

profile := "debug"
[private]
_container_repo := "ghcr.io/githedgehog/dataplane"

# the rust channel to use (choose stable, beta, or nightly)

rust := "stable"

# Docker images

[private]
_dpdk_sys_container_repo := "ghcr.io/githedgehog/dpdk-sys"
[private]
_dpdk_sys_container_tag := dpdk_sys_commit
[private]
_doc_env_container := _dpdk_sys_container_repo + "/doc-env:" + _dpdk_sys_container_tag
[private]
_compile_env_image_name := _dpdk_sys_container_repo + "/compile-env"
[private]
_compile_env_container := _compile_env_image_name + ":" + _dpdk_sys_container_tag

# Warn if the compile-env image is deprecated (or missing)

[private]
_compile_env_check := if shell('docker image list --format "{{.Repository}}:{{.Tag}}" | grep -x "' + _compile_env_image_name + ':' + _dpdk_sys_container_tag + '" || true') == '' { shell('printf "\n/!\\ Latest compile-env not found, try \"just refresh-compile-env\"\n\n" >&2') } else { '' }

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
    declare -a args=({{ args }})
    PROFILE="{{ profile }}"
    declare -a extra_args=()
    for arg in "${args[@]}"; do
      case "$arg" in
        --debug|--profile=debug)
          [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_DEBUG}"
          ;;
        --release|--profile=release|--profile=bench)
          [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_RELEASE}"
          extra_args+=("$arg")
          ;;
        --profile=fuzz)
          [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_FUZZ}"
          extra_args+=("$arg")
          ;;
        *)
          extra_args+=("$arg")
          ;;
      esac
    done
    [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_DEBUG}"
    cargo "${extra_args[@]}"

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
    declare tmp_link
    tmp_link="$(mktemp -p "$(pwd)/sterile" -d --suffix=.compile-env.link)"
    declare -r tmp_link
    cleanup() {
      rm -fr "${tmp_link}"
    }
    trap cleanup EXIT
    declare CARGO_TARGET_DIR
    CARGO_TARGET_DIR="$(pwd)/target"
    declare -r CARGO_TARGET_DIR
    rm -fr "${CARGO_TARGET_DIR}"
    mkdir -p "${CARGO_TARGET_DIR}"
    TMPDIR="${tmp_link}/tmp"
    mkdir "${TMPDIR}"
    ln -s /bin "${tmp_link}/bin"
    ln -s /lib "${tmp_link}/lib"
    ln -s /sysroot "${tmp_link}/sysroot"
    ln -s /nix "${tmp_link}/nix"
    sudo -E docker run \
      --rm \
      --name dataplane-compile-env \
      --network="{{ _network }}" \
      --env DOCKER_HOST="${DOCKER_HOST}" \
      --env CARGO_TARGET_DIR="${CARGO_TARGET_DIR}" \
      --env DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}" \
      --env TMPDIR="${TMPDIR}" \
      --tmpfs "/tmp:uid=$(id -u),gid=$(id -g),nodev,noexec,nosuid" \
      --mount "type=tmpfs,destination=/home/${USER:-runner},tmpfs-mode=1777" \
      --mount "type=bind,source=$(pwd),destination=$(pwd),bind-propagation=rprivate" \
      --mount "type=bind,source=${tmp_link},destination=$(pwd)/compile-env,bind-propagation=rprivate" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/passwd,destination=/etc/passwd,readonly" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/group,destination=/etc/group,readonly" \
      --mount "type=bind,source=${CARGO_TARGET_DIR},destination=${CARGO_TARGET_DIR}" \
      --mount "type=bind,source={{ DOCKER_SOCK }},destination={{ DOCKER_SOCK }}" \
      --user "$(id -u):$(id -g)" \
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
        grep -v "{{ _dpdk_sys_container_tag }}" || true | \
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
sterile *args: (compile-env "just" ("debug_justfile=" + debug_justfile) ("rust=" + rust) ("target=" + target) ("profile=" + profile) args)

[script]
sh *args:
    /bin/sh -i -c "{{ args }}"

# Build containers in a sterile environment
[script]
build-container: (sterile "_network=none" "cargo" "--locked" "build" ("--profile=" + profile) ("--target=" + target) "--package=dataplane")
    {{ _just_debuggable_ }}
    {{ _define_truncate128 }}
    mkdir -p "artifact/{{ target }}/{{ profile }}"
    cp -r "${CARGO_TARGET_DIR:-target}/{{ target }}/{{ profile }}/dataplane" "artifact/{{ target }}/{{ profile }}/dataplane"
    declare build_date
    build_date="$(date --utc --iso-8601=date --date="{{ _build_time }}")"
    declare -r build_date
    declare build_time_epoch
    build_time_epoch="$(date --utc '+%s' --date="{{ _build_time }}")"
    declare -r build_time_epoch
    sudo -E docker build \
      --label "git.commit={{ _commit }}" \
      --label "git.branch={{ _branch }}" \
      --label "git.tree-state={{ _clean }}" \
      --label "version.rust={{ rust }}" \
      --label "build.date=${build_date}" \
      --label "build.timestamp={{ _build_time }}" \
      --label "build.time_epoch=${build_time_epoch}" \
      --tag "{{ _container_repo }}:$(truncate128 "${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")" \
      --build-arg ARTIFACT="artifact/{{ target }}/{{ profile }}/dataplane" \
      .

    sudo -E docker tag \
      "{{ _container_repo }}:$(truncate128 "${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")" \
      "{{ _container_repo }}:$(truncate128 "{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")"
    sudo -E docker tag \
      "{{ _container_repo }}:$(truncate128 "${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")" \
      "{{ _container_repo }}:$(truncate128 "{{ _slug }}.{{ target }}.{{ profile }}")"
    if [ "{{ target }}" = "x86_64-unknown-linux-gnu" ]; then
      sudo -E docker tag \
        "{{ _container_repo }}:$(truncate128 "${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")" \
        "{{ _container_repo }}:$(truncate128 "{{ _slug }}.{{ profile }}")"
    fi
    if [ "{{ target }}" = "x86_64-unknown-linux-gnu" ] && [ "{{ profile }}" = "release" ]; then
      sudo -E docker tag \
        "{{ _container_repo }}:$(truncate128 "${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}")" \
        "{{ _container_repo }}:$(truncate128 "{{ _slug }}")"
    fi

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
build-sweep start="main" command="{ git log --oneline --no-decorate -n 1 && just cargo build; }":
    {{ _just_debuggable_ }}
    # Check for uncommitted changes
    if [ -n "$(git status --porcelain)" ]; then
        echo "Error: Uncommitted changes detected. Please commit or stash your changes before running this script."
        exit 1
    fi
    git rebase --keep-base "{{ start }}" --no-autosquash --exec "{{ command }}"
