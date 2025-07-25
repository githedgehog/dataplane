#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Cargo automatically runs this script for every unit test (this applies to nextest as well).
# The script has two main responsibilities:
#
# 1. It runs `setcap` on the _test binary_ to elevate the test's _permitted_ capabilities.
#    This action _does not_ cause the tests to run with these capabilities active by default.
#    That would involve setting the _effective_ capabilities for the test binary (which we don't do).
#    Instead, assigning the _permitted_ capabilities allows the use of the `caps` crate to allow us to request elevated
#    permissions for specific sections of test code.
#
#    The purpose of these elevated privileges is to allow the tests to create and destroy virtual network interfaces and
#    network namespaces (as is required for integration testing).
#
# 2. It bind mounts the (setcap modified) test binary, the project directory, and a few other files into a (read-only)
#    docker container (which executes the test).  This docker container contains _only_ libc and libgcc_s (to better
#    simulate our deployment environment and discourage faulty assumptions about what will be available at runtime).
#
#    The purpose of this container is to
#    * minimize the damage a faulty test might do
#    * make sure that we aren't relying on resources only available on the developer's machine in the tests (test like
#      we are in prod).
#
# Hopefully, this process also requires us to carefully think about what parts of our code require which privileges (and
# to document these requirements carefully).  I'm lookin' at you, future me :)

set -euo pipefail


get_docker_sock() {
  declare -r DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"
  declare -r without_unix="${DOCKER_HOST##unix://}"
  if [ -S "${without_unix}" ]; then
    printf -- '%s' "${without_unix}"
  elif [ -S /run/docker/docker.sock ]; then
    printf -- '%s' "/run/docker/docker.sock"
  elif [ -S /var/run/docker.sock ]; then
    printf -- '%s' "/var/run/docker.sock"
  fi
}

# compute the location of the directory which contains this file.
declare script_dir
script_dir="$(readlink -e "$(dirname "${0}")")"
declare -r script_dir

# compute the location of the directory which contains this project.
declare project_dir
project_dir="$(readlink -e "${script_dir}/..")"
declare -r project_dir

# NOTE: Cargo dispatches this script.
# Therefore, the PATH variable is set in config.toml to point to our compile-env; not the systems normal PATH.
# We can't meaningfully ship sudo in the compile-env (for a lot of reasons).
# It is there, but it won't have the 0 uid owner or its setuid bit set, so it can't work.
# Even if we fixed that, /etc/sudoers et al. wouldn't be reliably configured.
# Thus, we need to look it up on the "normal" PATH.  We don't have the official "normal" PATH available, so we check
# the usual suspects to find sudo.
declare SUDO
SUDO="$(PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:${PATH}" which sudo)"
declare -r SUDO

# Start with a basic check: we have no reason to assign caps to files we don't own or can't execute.
check_if_reasonable() {
  declare -r prog="${1}"

  if [ ! -x "${prog}" ]; then
    >&2 echo "ERROR: ${prog} is not executable"
    return 1
  fi

  if [ ! -O "${prog}" ]; then
    >&2 echo "ERROR: ${prog} is not owned by $(whoami), refusing to edit capabilities"
    return 1
  fi

  if [ ! -G "${prog}" ]; then
    >&2 echo "ERROR: ${prog} is not owned by $(whoami) effective user group, refusing to edit capabilities"
    return 1
  fi
}


# some IDEs (e.g., rust-rover) use a helper to run tests / debug sessions.
# in such cases, the test exe is actually $2 ($1 shouldn't have any special privileges in that case)
declare test_exe
if [ -x "${2:-}" ]; then
  test_exe="${2}"
else
  test_exe="${1}"
fi
declare -r test_exe
check_if_reasonable "${test_exe}"

# Pull the current version of the sysroot from the env.
# This lets us pick the correct libc container.
source "${script_dir}/dpdk-sys.env"

declare -ra WRAPPED_TEST_SUITES=(
  "dataplane"
  "dataplane-interface-manager"
  "dataplane-mgmt"
  "integration-fixtures"
)

declare -i SHOULD_WRAP=0
declare test_suite
for test_suite in "${WRAPPED_TEST_SUITES[@]}"; do
  if [ "${CARGO_PKG_NAME-CARGO_PKG_NAME_NOT_SET}" == "${test_suite}" ]; then
    SHOULD_WRAP=1
    break
  fi
done
declare -ri SHOULD_WRAP

# This is the list of capabilities to add to the test binary.
# Note: do not add =e or =i to this setcap command!  We don't want privileged execution by default.
# Note: if you adjust this list, then you also need to adjust the symmetric list given to the docker run command.
declare -r CAPS='cap_net_raw,cap_sys_admin,cap_net_admin,cap_sys_rawio=p'

if [ "${TEST_TYPE:-""}" = "FUZZ" ]; then
  # In this branch we are running full fuzz tests.
  # These tests are only run from a just command which has already wrapped this script in a docker container.

  # In the case of the full fuzz tests, libstdc++.so.6 will be linked into the test binary because libfuzzer is an LLVM
  # project (LLVM is a C++ codebase).
  # Unfortunately, the combination of bolero's RUSTFLAGS and the nix fenix rust overlay _do not_ set the rpath for
  # libstdc++.so.6.
  # As a result, a naive attempt to execute the test binary in the compile-env will result in a file not found error
  # when the dynamic linker is unable to find libstdc++.so.6.
  # Fortunately, this is relatively easy to fix; we need to patch the test binary to make sure it resolves to the
  # exact libstdc++.so.6 file which it was liked against.
  # If the compile-env is correct, then `/lib/libstdc++.so.6` will always be a symlink to the `/nix` store which
  # contains the correct dynamic library.
  patchelf --replace-needed libstdc++.so.6 "$(readlink -e /lib/libstdc++.so.6)" "${test_exe}"
  # note: we don't need ${SUDO} here (i.e., we can resolve sudo via the $PATH) because this branch only ever happens
  # when this script is being executed in the compile-env; the compile-env is the only place environment able to execute
  # the full fuzz tests.
  sudo setcap "${CAPS}" "${test_exe}"
  exec "${@}"
elif [ "${SHOULD_WRAP}" -eq 0 ]; then
  # In this branch
  # 1. we are not doing a full fuzz test run,
  # 2. and we are not running a test which requires a container wrapper.
  # As a consequence, we should never need to call setcap on the test binary.
  # We can just run it directly and be done.
  exec "${@}"
fi


# If we reached this point then we aren't using the full fuzz test setup.
# Instead, we are trying to run semi-privileged tests in a libc-container.
# We still need to add capabilities to the test binary, but in this case we need to make sure we are using the
# host system's sudo binary.
"${SUDO}" setcap "${CAPS}" "${test_exe}"

# Now we can run the docker container
#
# Notes about this command:
# * Note that we mount everything we can as read-only
# * --ipc=host and --pid=host are to allow debuggers to connect to the tests more easily.
# * We mount $1 in case it is an IDE's helper runner.
#   If not, then no harm has been done as $1 will be mounted by the project_dir mount anyway.
# * We drop all caps and then add back just the caps we know we need.
#   This allows those capabilities into our ambient+inheritable set, letting us elevate to them as needed.
#   Critically, it _does not_ give us these capabilities by default (i.e., they aren't in our effective set) because
#   the above setcap command has enumerated exactly what our defaults should be.
# * If you adjust the list of --cap-add arguments, then you need to adjust the CAPS env var as well.
"${SUDO}" --preserve-env docker run \
  --rm \
  --interactive \
  --mount "type=bind,source=$(readlink -e "${1}"),target=$(readlink -e "${1}"),readonly=true,bind-propagation=rprivate" \
  --mount "type=bind,source=${project_dir},target=${project_dir},readonly=true,bind-propagation=rprivate" \
  --mount "type=bind,source=${project_dir}/target,target=${project_dir}/target,readonly=false,bind-propagation=rprivate" \
  --mount "type=bind,source=$(get_docker_sock),target=$(get_docker_sock),readonly=false,bind-propagation=rprivate" \
  --tmpfs "/run/netns:noexec,nosuid,uid=$(id -u),gid=$(id -g)" \
  --tmpfs "/var/run/netns:noexec,nosuid,uid=$(id -u),gid=$(id -g)" \
  --tmpfs "/tmp:nodev,noexec,nosuid,uid=$(id -u),gid=$(id -g)" \
  --user="$(id -u):$(id -g)" \
  --group-add="$(getent group docker | cut -d: -f3)" \
  --env LLVM_PROFILE_FILE="${LLVM_PROFILE_FILE:-""}" \
  --env CARGO_LLVM_COV="${CARGO_LLVM_COV:-0}" \
  --env CARGO_LLVM_COV_TARGET_DIR="${project_dir}/target" \
  --workdir="${project_dir}" \
  --env DOCKER_HOST="unix://$(get_docker_sock)" \
  --net=none \
  --ipc=host \
  --pid=host \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --cap-add SYS_ADMIN \
  --cap-add SYS_RAWIO \
  --read-only \
  "ghcr.io/githedgehog/dpdk-sys/libc-env:${DPDK_SYS_COMMIT}.${LIBC_ENV_PROFILE:-release}" \
  "${@}"
