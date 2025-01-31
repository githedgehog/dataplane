# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true

run_id := uuid()
SHELL := shell("""
  if ! set -e; then
    >&2 echo "ERROR: failed to configure shell (set -e not supported by shell $SHELL)"
    exit 1
  fi
  if ! set -u; then
    >&2 echo "ERROR: failed to configure shell (set -u not supported by shell $SHELL)"
    exit 1
  fi
  if ! set -o pipefail; then
    >&2 echo "ERROR: failed to configure shell (set -o pipefail not supported by shell $SHELL)"
    exit 1
  fi
  if ! (set -x); then
    >&2 echo "WARNING: shell does not support set -x: debug mode unavailable (shell $SHELL)"
  fi
  echo ${SHELL:-sh}
""")

set shell := [x"${SHELL:-bash}", "-euo", "pipefail", "-c"]
set script-interpreter := [x"${SHELL:-bash}", "-euo", "pipefail"]
set dotenv-load := true
set dotenv-required := true
set dotenv-path := "."
set dotenv-filename := "./scripts/rust.env"

export NEXTEST_EXPERIMENTAL_LIBTEST_JSON := "1"
debug := "false"
dpdk_sys_commit := shell("source ./scripts/dpdk-sys.env && echo $DPDK_SYS_COMMIT")
hugepages_1g := "8"
hugepages_2m := "1024"
_just_debuggable_ := if debug == "true" { "set -x" } else { "" }
target := "x86_64-unknown-linux-gnu"
profile := "dev"
_container_repo := "ghcr.io/githedgehog/dataplane"
rust := "stable"
_dpdk_sys_container_repo := "ghcr.io/githedgehog/dpdk-sys"
_dpdk_sys_container_tag := dpdk_sys_commit + ".rust-" + rust
_doc_env_container := _dpdk_sys_container_repo + "/doc-env:" + _dpdk_sys_container_tag
_compile_env_container := _dpdk_sys_container_repo + "/compile-env:" + _dpdk_sys_container_tag
_network := "host"
_docker_sock_cmd := replace_regex(_just_debuggable_, ".+", "$0;") + '''
  declare -r DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"
  declare -r without_unix="${DOCKER_HOST##unix://}"
  if [ -S "${without_unix}" ]; then
    printf -- '%s' "${without_unix}"
  elif [ -S /var/run/docker.sock ]; then
    printf -- '%s' "/var/run/docker.sock"
  fi
'''
export DOCKER_HOST := x"${DOCKER_HOST:-unix:///var/run/docker.sock}"
export DOCKER_SOCK := shell(_docker_sock_cmd)

# The git commit hash of the last commit to HEAD
# We allow this command to fail in the sterile environment because git is not available there

_commit := `git rev-parse HEAD 2>/dev/null || echo "sterile"`

# The git branch we are currnetly on
# We allow this command to fail in the sterile environment because git is not available there

_branch := `(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "sterile") | tr -c '[:alnum:]\n' '-'`

# The git tree state (clean or dirty)
# We allow this command to fail in the sterile environment because git is not available there

_clean := ```
  set -euo pipefail
  (
    git diff-index --quiet HEAD -- 2>/dev/null && \
    test -z "$(git ls-files --exclude-standard --others)" && \
    echo clean \
  ) || echo dirty
```

# The slug is the branch name (sanitized) with a marker if the tree is dirty

_slug := (if _clean == "clean" { "" } else { "dirty-_-" }) + _branch

# Define a function to truncate long lines to the limit for containers tags
_define_truncate128 := 'truncate128() { printf -- "%s" "${1::128}" ; }'

# The time of the build (in iso8601 utc)

_build_time := datetime_utc("%+")

# List out the available commands
[private]
@default:
    just --list --justfile {{ justfile() }}

# Run cargo with RUSTFLAGS computed based on profile.
[group('rust')]
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
compile-env *args: fill-out-dev-env-template
    {{ _just_debuggable_ }}
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
    ln -s /bin "${tmp_link}/bin"
    ln -s /lib "${tmp_link}/lib"
    ln -s /sysroot "${tmp_link}/sysroot"
    ln -s /nix "${tmp_link}/nix"
    sudo -E docker run \
      --rm \
      --name dataplane-compile-env \
      --network="{{ _network }}" \
      --env DOCKER_HOST \
      --env CARGO_TARGET_DIR \
      --tmpfs "/tmp:uid=$(id -u),gid=$(id -g),nodev,noexec,nosuid" \
      --mount "type=tmpfs,destination=/home/${USER:-runner},tmpfs-mode=1777" \
      --mount "type=bind,source=$(pwd),destination=$(pwd),bind-propagation=rprivate" \
      --mount "type=bind,source=${tmp_link},destination=$(pwd)/compile-env,bind-propagation=rprivate" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/passwd,destination=/etc/passwd,readonly" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/group,destination=/etc/group,readonly" \
      --mount "type=bind,source=${CARGO_TARGET_DIR},destination=${CARGO_TARGET_DIR},bind-propagation=rprivate" \
      --mount "type=bind,source={{ DOCKER_SOCK }},destination=/var/run/docker.sock" \
      --user "$(id -u):$(id -g)" \
      --workdir "$(pwd)" \
      "{{ _compile_env_container }}" \
      {{ args }}

# Pull the latest versions of the compile-env container
[script]
pull-compile-env:
    {{ _just_debuggable_ }}
    sudo -E docker pull "{{ _compile_env_container }}" || true

# Pull the latest versions of the containers
[script]
pull: pull-compile-env

# Allocate 2M hugepages (if needed)
[private]
[script]
allocate-2M-hugepages:
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
allocate-1G-hugepages:
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
[group('env')]
setup-test-env: allocate-2M-hugepages allocate-1G-hugepages mount-hugepages

# Tear down environment for testing locally
[group('env')]
teardown-test-env: umount-hugepages

# Dump the compile-env container into a sysroot for use by the build.
[group('env')]
[script]
create-compile-env:
    {{ _just_debuggable_ }}
    mkdir compile-env
    sudo -E docker create --name dpdk-sys-compile-env-{{ run_id }} "{{ _compile_env_container }}" - fake
    sudo -E docker export dpdk-sys-compile-env-{{ run_id }} \
      | tar --no-same-owner --no-same-permissions -xf - -C compile-env
    sudo -E docker rm dpdk-sys-compile-env-{{ run_id }}

# remove the compile-env directory
[confirm("Remove old compile environment? (yes/no)\n(you can recreate it with `just create-compile-env`)")]
[group('env')]
[script]
remove-compile-env:
    {{ _just_debuggable_ }}
    if [ -d compile-env ]; then sudo rm -rf compile-env; fi

# refresh the compile-env (clear and restore)
[group('env')]
[script]
refresh-compile-env: remove-compile-env pull-compile-env create-compile-env

# Install "fake-nix" (required for local builds to function)
[confirm("Fake a nix install (yes/no)")]
[group('env')]
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

# Fill out template file for the dev-env (needed to preserve user in dev-env container)
[group('env')]
[private]
[script]
fill-out-dev-env-template:
    {{ _just_debuggable_ }}
    mkdir -p dev-env-template/etc
    if [ -z "${UID:-}" ]; then
      >&2 echo "ERROR: environment variable UID not set"
    fi
    declare -rxi UID
    GID="$(id -g)"
    declare -rxi GID
    declare -rx USER="${USER:-runner}"
    envsubst < dev-env-template/etc.template/group.template > dev-env-template/etc/group
    envsubst < dev-env-template/etc.template/passwd.template > dev-env-template/etc/passwd

# Run a "sterile" command
[group('env')]
sterile *args: (compile-env "just" ("debug=" + debug) ("rust=" + rust) ("target=" + target) ("profile=" + profile) args)

# Run a "sterile" build
[private]
sterile-build: (sterile "_network=none" "cargo" "--locked" "build" ("--profile=" + profile) ("--target=" + target) "--package=dataplane")
    mkdir -p "artifact/{{ target }}/{{ profile }}"
    cp -r "${CARGO_TARGET_DIR:-target}/{{ target }}/{{ profile }}/dataplane" "artifact/{{ target }}/{{ profile }}/dataplane"

# Build containers in a sterile environment
[script]
build-container: sterile-build
    {{ _just_debuggable_ }}
    {{ _define_truncate128 }}
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

# Run the tests (with nextest)
[group("ci")]
[script]
test:
    declare -r  report_dir="${CARGO_TARGET_DIR:-target}/nextest/{{ profile }}"
    mkdir -p "${report_dir}"
    {{ _just_debuggable_ }}
    PROFILE="{{ profile }}"
    case "{{ profile }}" in
      dev|test)
        [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_DEBUG}"
        ;;
      bench|release)
        [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_RELEASE}"
        ;;
      fuzz)
        [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_FUZZ}"
        ;;
    esac
    [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_DEBUG}"
    # >&2 echo "With RUSTFLAGS=\"${RUSTFLAGS:-}\""
    cargo $(if rustup -V &>/dev/null; then echo +{{ rust }}; fi) nextest --profile={{ profile }} run \
          --message-format libtest-json-plus \
          --locked \
          --cargo-profile={{ profile }} \
          --target={{ target }} \
        > >(tee "$report_dir/report.json") \
        2> >(tee "$report_dir/report.log")

# Generate a test report (does not run the tests first)
[group("ci")]
[script]
report:
    {{ _just_debuggable_ }}
    declare -r report_dir="${CARGO_TARGET_DIR:-target}/nextest/{{ profile }}"
    markdown-test-report "$report_dir/report.json" -o "$report_dir/report.md"
    cat <<'EOF' >> "${report_dir}/report.md"
    ## Test Report

    > [!NOTE]
    > Rust: {{ rust }}
    > Profile: {{ profile }}
    > Target: {{ target }}

    EOF
    declare -rx log="$(ansi2txt < $report_dir/report.log)"
    cat >> "${report_dir}/report.md" <<EOF
    <details>
    <summary>

    ## Test log

    </summary>

    \`\`\`log
    $log
    \`\`\`
    </details>

    EOF

    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      cat $report_dir/report.md >> $GITHUB_STEP_SUMMARY
    fi

# run commands in a minimal mdbook container
[script]
mdbook *args="build":
    {{ _just_debuggable_ }}
    mkdir -p /tmp/doc-env
    cd ./design-docs/src/mdbook
    docker pull {{ _doc_env_container }}
    docker run \
      --rm \
      --init \
      --volume "$(pwd):$(pwd)" \
      --env HOME=/tmp \
      --user "$(id -u):$(id -g)" \
      --mount type=bind,source=/tmp/doc-env,target=/tmp \
      --workdir "$(pwd)" \
      --network=host \
      --name design-docs \
      --entrypoint /bin/mdbook \
      {{ _doc_env_container }} \
      {{ args }}
