# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# The linker rustc runs (`-Clinker`), in front of the real one, `LINK_CC`.
#
# Every ThinLTO link runs an ld.lld that optimizes the whole program, Rust and the C dependencies
# together, and holds gigabytes while it does. Cargo cannot see that: `-j` caps how many rustc
# processes run, and any of them may be linking, so how many links overlap is left to chance -- and
# an unlucky overlap is what runs a build out of memory. With `LINK_SLOTS` set, a link first takes
# one of that many slots and keeps it until the linker exits; the others wait their turn.
#
# `LINK_THINLTO_JOBS` sets each link's ThinLTO backend threads: with the links bounded, the ones
# that run can use more.
#
# Unset (or `LINK_SLOTS=0`), this is transparent. Both are environment rather than flags so that
# they stay out of cargo's fingerprint: builds with and without them share dependency artifacts.

extra=()
if [ -n "${LINK_THINLTO_JOBS:-}" ]; then
  # lld takes the last `--thinlto-jobs`, so this overrides the profile's.
  extra+=("-Wl,--thinlto-jobs=${LINK_THINLTO_JOBS}")
fi

if [ "${LINK_SLOTS:-0}" -gt 0 ]; then
  # One directory per build: the nix sandbox gives each its own `NIX_BUILD_TOP`.
  dir="${NIX_BUILD_TOP:-${TMPDIR:-/tmp}}/link-slots"
  mkdir -p "${dir}"
  while true; do
    for ((slot = 1; slot <= LINK_SLOTS; slot++)); do
      exec {fd}> "${dir}/${slot}"
      if flock --nonblock "${fd}"; then
        # The lock is held by the open descriptor, which the linker inherits through `exec`, so
        # the slot is released when the linker exits, however it exits.
        exec "${LINK_CC}" "$@" "${extra[@]}"
      fi
      exec {fd}>&-
    done
    sleep 0.2
  done
fi

exec "${LINK_CC}" "$@" "${extra[@]}"
