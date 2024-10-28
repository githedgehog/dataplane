set unstable := true

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

debug := "false"
DPDK_SYS_COMMIT := shell("source ./scripts/dpdk-sys.env && echo $DPDK_SYS_COMMIT")
hugepages_1g := "8"
hugepages_2m := "1024"
_just_debuggable_ := if debug == "true" { "set -x" } else { "" }
target := "x86_64-unknown-linux-gnu"
profile := "debug"
sterile_target_dir := `printf -- %s "/run/user/$(id -u)/hedgehog/dataplane/sterile"`
container_repo := "ghcr.io/githedgehog/dataplane"
rust := "stable"
_dpdk_sys_container_repo := "ghcr.io/githedgehog/dpdk-sys"
_env_branch := "main"
_dev_env_container := _dpdk_sys_container_repo + "/dev-env:" + _env_branch + "-rust-" + rust + "-" + DPDK_SYS_COMMIT
_compile_env_container := _dpdk_sys_container_repo + "/compile-env:" + _env_branch + "-rust-" + rust + "-" + DPDK_SYS_COMMIT
_network := "host"

# The git commit hash of the last commit to HEAD

_commit := `git rev-parse HEAD 2>/dev/null || echo "sterile"`

# The git branch we are currnetly on

_branch := `git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "sterile"`

# The git tree state (clean or dirty)

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

# NOTE: if USE_WORLDTIME is set to true then
# we parse the returned date from the worldtimeapi.org API to ensure that
# we actually got a valid iso-8601 date (and nobody is messing with clocks)
#
# We also diff the official worldtimeapi.org time with the system time to see if we are off by more than 5 seconds
# If we are, then we should fail the build as either
# 1. the system is incorrectly configured
# 2. someone is messing with the system clock (which makes me think CA cert issues are afoot)
# 3. the worldtimeapi.org API is down or inacurate (very unlikely)

_build_time := ```
  set -euo pipefail
  declare official_unparsed
  if [ "${USE_WORLDTIME:-}" = "true" ]; then
    official_unparsed="$(curl "http://worldtimeapi.org/api/timezone/utc" | jq --raw-output '.utc_datetime')"
  else
    official_unparsed="$(date --iso-8601=seconds --utc)"
  fi
  declare -r official_unparsed
  declare official
  official="$(date --iso-8601=seconds --utc --date="${official_unparsed}")"
  declare -r official
  declare system_epoch
  system_epoch="$(date --utc +%s)"
  declare -ri system_epoch
  declare official_epoch
  official_epoch="$(date --utc --date="${official}" +%s)"
  declare -ri official_epoch
  declare -ri clock_skew=$((system_epoch - official_epoch))
  if [ "${clock_skew}" -gt 5 ] || [ "${clock_skew}" -lt -5 ]; then
    >&2 echo "Clock skew detected: system time: ${system_epoch} official time: ${official_epoch}"
    exit 1
  fi
  printf -- "%s" "${official}"
```

[private]
@default:
  just --list --justfile {{justfile()}}

[group('ci')]
[private]
[script]
_ci-compile-env-hack:
    {{ _just_debuggable_ }}
    ln -s / ./compile-env

[private]
[script]
_cargo-with-rust-flags *args:
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
        *)
          extra_args+=("$arg")
          ;;
      esac
    done
    [ -z "${RUSTFLAGS:-}" ] && declare -rx RUSTFLAGS="${RUSTFLAGS_DEBUG}"
    # >&2 echo "With RUSTFLAGS=\"${RUSTFLAGS:-}\""
    cargo "${extra_args[@]}"

[group('rust')]
[script]
cargo *args: (_cargo-with-rust-flags args)

[group('env')]
[script]
dev-env *args="": allocate-2M-hugepages allocate-1G-hugepages mount-hugepages fill-out-dev-env-template && umount-hugepages
    {{ _just_debuggable_ }}
    declare hugemnt2M
    hugemnt2M="/run/user/$(id -u)/hedgehog/dataplane/hugepages/2M"
    declare -r hugemnt2M
    declare hugemnt1G
    hugemnt1G="/run/user/$(id -u)/hedgehog/dataplane/hugepages/1G"
    declare -r hugemnt1G
    sudo docker run \
      --rm \
      --interactive \
      --tty \
      --name dataplane-dev-env \
      --privileged \
      --network="{{_network}}" \
      --security-opt seccomp=unconfined \
      --mount "type=tmpfs,destination=/home/${USER:-runner},tmpfs-mode=0777" \
      --mount "type=bind,source=${hugemnt2M},destination=/mnt/hugepages/2M,bind-propagation=rprivate" \
      --mount "type=bind,source=${hugemnt1G},destination=/mnt/hugepages/1G,bind-propagation=rprivate" \
      --mount "type=bind,source=$(pwd),destination=$(pwd),bind-propagation=rprivate" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/passwd,destination=/etc/passwd,readonly" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/group,destination=/etc/group,readonly" \
      --mount "type=bind,source=/var/run/docker.sock,destination=/var/run/docker.sock,bind-propagation=rprivate" \
      --user "$(id -u):$(id -g)" \
      --workdir "$(pwd)" \
      "{{ _dev_env_container }}" \
      {{ args }}

[script]
compile-env *args: fill-out-dev-env-template
    {{ _just_debuggable_ }}
    mkdir -p "$(pwd)/sterile"
    declare tmp_link
    tmp_link="$(mktemp -p "$(pwd)/sterile" -d --suffix=.compile-env.link)"
    declare -r tmp_link
    cleanup() {
      rm -r "${tmp_link}"
    }
    trap cleanup EXIT
    declare tmp_targetdir
    tmp_targetdir="$(pwd)/sterile/target"
    declare -r tmp_targetdir
    rm -fr "${tmp_targetdir}"
    mkdir -p "${tmp_targetdir}"
    ln -s /bin "${tmp_link}/bin"
    ln -s /lib "${tmp_link}/lib"
    ln -s /sysroot "${tmp_link}/sysroot"
    ln -s /nix "${tmp_link}/nix"
    sudo docker run \
      --rm \
      --name dataplane-compile-env \
      --network="{{_network}}" \
      --tmpfs "/tmp:uid=$(id -u),gid=$(id -g),nodev,noexec,nosuid" \
      --mount "type=tmpfs,destination=/home/${USER:-runner},tmpfs-mode=1777" \
      --mount "type=bind,source=$(pwd),destination=$(pwd),bind-propagation=rprivate" \
      --mount "type=bind,source=${tmp_link},destination=$(pwd)/compile-env,bind-propagation=rprivate" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/passwd,destination=/etc/passwd,readonly" \
      --mount "type=bind,source=$(pwd)/dev-env-template/etc/group,destination=/etc/group,readonly" \
      --mount "type=bind,source=${tmp_targetdir},destination=$(pwd)/target,bind-propagation=rprivate" \
      --user "$(id -u):$(id -g)" \
      --workdir "$(pwd)" \
      "{{ _compile_env_container }}" \
      {{ args }}

[script]
pull-compile-env:
    {{ _just_debuggable_ }}
    sudo docker pull "{{ _compile_env_container }}" || true

[script]
pull-dev-env:
    {{ _just_debuggable_ }}
    sudo docker pull "{{ _dev_env_container }}"

[script]
pull: pull-compile-env pull-dev-env

[script]
create-dev-env:
    {{ _just_debuggable_ }}
    mkdir dev-env
    sudo docker create --name dpdk-sys-dev-env {{ _dev_env_container }} - fake
    sudo docker export dpdk-sys-dev-env | tar --no-same-owner --no-same-permissions -xf - -C dev-env
    sudo docker rm dpdk-sys-dev-env

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

[group('env')]
[script]
create-compile-env:
    {{ _just_debuggable_ }}
    mkdir compile-env
    sudo docker create --name dpdk-sys-compile-env "{{ _compile_env_container }}" - fake
    sudo docker export dpdk-sys-compile-env \
      | tar --no-same-owner --no-same-permissions -xf - -C compile-env
    sudo docker rm dpdk-sys-compile-env

[confirm("Remove the compile environment? (yes/no)\n(you can recreate it with `just create-compile-env`)")]
[group('env')]
[script]
remove-compile-env:
    {{ _just_debuggable_ }}
    if [ -d compile-env ]; then sudo rm -rf compile-env; fi

[group('env')]
[script]
refresh-compile-env: remove-compile-env pull-compile-env && create-compile-env

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

[group('env')]
sterile *args: (compile-env "just" "debug={{debug}}" "rust={{rust}}" "target={{target}}" "profile={{profile}}" args)

[script]
compress *args:
    {{ _just_debuggable_ }}
    zstd -T0 -19 -c "{{ args }}" > "{{ args }}.tar.zst"

[private]
sterile-build: (sterile "_network=none" "cargo" "--locked" "build" ("--profile=" + profile) ("--target=" + target))
    mkdir -p "artifact/{{ target }}/{{ profile }}"
    cp -r "sterile/target/{{ target }}/{{ profile }}/scratch" "artifact/{{ target }}/{{ profile }}/scratch"

[script]
build-container: sterile-build
    {{ _just_debuggable_ }}
    declare build_date
    build_date="$(date --utc --iso-8601=date --date="{{ _build_time }}")"
    declare -r build_date
    declare build_time_epoch
    build_time_epoch="$(date --utc '+%s' --date="{{ _build_time }}")"
    declare -r build_time_epoch
    sudo docker build \
      --label "git.commit={{ _commit }}" \
      --label "git.branch={{ _branch }}" \
      --label "git.tree-state={{ _clean }}" \
      --label "version.rust={{ rust }}" \
      --label "build.date=${build_date}" \
      --label "build.timestamp={{ _build_time }}" \
      --label "build.time_epoch=${build_time_epoch}" \
      --tag "{{ container_repo }}:${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}" \
      --build-arg ARTIFACT="artifact/{{ target }}/{{ profile }}/scratch" \
      .

    sudo docker tag \
      "{{ container_repo }}:${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}" \
      "{{ container_repo }}:{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}"
    sudo docker tag \
      "{{ container_repo }}:${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}" \
      "{{ container_repo }}:{{ _slug }}.{{ target }}.{{ profile }}"
    if [ "{{ target }}" = "x86_64-unknown-linux-gnu" ]; then
      sudo docker tag \
        "{{ container_repo }}:${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}" \
        "{{ container_repo }}:{{ _slug }}.{{ profile }}"
    fi
    if [ "{{ target }}" = "x86_64-unknown-linux-gnu" ] && [ "{{ profile }}" = "release" ]; then
      sudo docker tag \
        "{{ container_repo }}:${build_date}.{{ _slug }}.{{ target }}.{{ profile }}.{{ _commit }}" \
        "{{ container_repo }}:{{ _slug }}"
    fi

[script]
build-docs:
    cd design-docs/src/mdbook
    mdbook build

[script]
serve-docs:
    cd design-docs/src/mdbook
    mdbook serve
