# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := ["/usr/bin/env", "bash", "-euo", "pipefail", "-c"]
set script-interpreter := ["/usr/bin/env", "bash", "-euo", "pipefail"]

mod ci
mod miri

# enable to debug just recipes
debug_justfile := "false"

[private]
_just_debuggable_ := if debug_justfile == "true" { "set -x" } else { "" }

# number of nix derivations to build concurrently
jobs := "8"

# threads each nix derivation may use ("0" means every core on the machine).
#
# nix hands this to the builder as NIX_BUILD_CORES, which crane turns into
# CARGO_BUILD_JOBS and nixpkgs' enableParallelBuilding turns into make -j, so
# it is the cap on concurrent compile/link jobs *within* one derivation. The
# cap on the whole build is therefore `jobs` x `cores`; a runner with fewer
# cores than that will oversubscribe itself.
cores := "0"

# libc
libc := if platform == "wasm32-wasip1" { "none" } else { "gnu" }

# kernel (linux or wasip1)
kernel := if platform == "wasm32-wasip1" { "wasip1" } else { "linux" }

# List out the available commands
[private]
[default]
@default:
    just --list --justfile {{ justfile() }}

# cargo build profile (debug/release/fuzz)
profile := "debug"

export callgrind_package := "dataplane-routing"
export callgrind_bench := "fib_lookup_callgrind"

# sanitizer to use (address/thread/safe-stack/cfi/"")
sanitize := ""

bolero_coverage_test_time_ms := env("BOLERO_COVERAGE_TEST_TIME_MS", "15000")

# comma-separated list of cargo features to enable (e.g. "shuttle")
features := ""

fuzz_max_input_length := env("FUZZ_MAX_INPUT_LENGTH", "65536")

fuzz_corpus_root := env("FUZZ_CORPUS_ROOT", justfile_directory() / ".fuzz-corpus")

fuzz_jobs := env("FUZZ_JOBS", `echo $(( ($(nproc) + 1) / 2 ))`)

fuzz_len_control := env("FUZZ_LEN_CONTROL", "0")

# whether to include default cargo features for this workspace (set to "false" to disable)
default_features := "true"

# pyroscope server the dataplane image should push profiles to (empty = profiling off)
pyroscope_url := ""

# HTTP proxy baked into the dataplane image. Gateway nodes have no route off the fabric, so
# anything the dataplane pushes outward -- profiles today -- has to go through the control proxy.
# Alloy gets the equivalent injected into its config by fabricator; the dataplane has no such
# machinery, and without this its pushes simply time out.
dataplane_proxy_url := ""

# Private computed cargo flag groups for consistent invocations.
# Recipes should compose these as needed (not all cargo subcommands accept all flags).
[private]
_cargo_feature_flags := \
    (if default_features == "false" { "--no-default-features " } else { "" }) \
    + (if features != "" { "--features " + features } else { "" })

[private]
_cargo_profile_flag := if profile == "debug" { "" } else { "--profile " + profile }

# filters for nextest
#
# Under `shuttle`, the legacy `dataplane-quiescent` test layout had a
# `shuttle` binary that hosted the bolero x shuttle suite, and we used
# `--package=shuttle` (now an `-E 'package(shuttle)'`-style filter
# embedded in nextest's argv) to isolate it.  Today that suite lives in
# `concurrency/tests/quiescent_shuttle.rs`, and the test binary is
# `quiescent_shuttle`; matching the substring `shuttle` is good enough.
#
# Under `loom`, the legacy filter `-E 'binary(loom)'` matched
# `quiescent_loom`, the single integration-test binary that opted into
# `loom::model`.  After the concurrency rework, loom-compatible tests
# are spread across multiple binaries (`quiescent_model`,
# `thread_scope`, `arc_weak`, `stress_dispatch`); the rest are gated
# with `#![cfg(not(any(feature = "loom", ...)))]` and compile down to
# zero tests under the loom feature.  An empty filter is therefore the
# right answer: nextest walks every archived binary, the cfg-gated
# ones contain no tests, and the loom-compatible ones run under their
# `#[concurrency::test]`-routed `loom::model` body.
# Match all shuttle variants (`shuttle`, plus the additive
# `shuttle_dfs` opt-in).
# Under any shuttle backend, `concurrency::sync` types ARE shuttle
# primitives, and touching them outside a `shuttle::check_*`-wrapped
# body panics with `ExecutionState NotSet`. Tests that are designed
# to run under shuttle either go through `#[concurrency::test]` (which
# emits a `concurrency_model::<backend>` leaf -- the substring matches)
# or live in a `*_shuttle` module / `*shuttle*` binary by convention.
# Other workspace tests would fail spuriously without this filter.
filter := if features =~ "^shuttle" { "shuttle" } else if features =~ "^loom" { "::concurrency_model::loom" } else { "" }

# instrumentation mode (none/coverage)
instrument := "none"

# target platform (x86-64-v3/bluefield2)
platform := "x86-64-v3"

version_extra := ""
version_platform := if platform == "x86-64-v3" { "" } else { "-" + platform }
version_profile := if profile == "release" { "" } else { "-" + profile }
version_san := if sanitize == "" { "" } else { "-san." + replace(sanitize, ",", ".") }
version_feat := if features == "" { "" } else { "-feat." + replace(features, ",", ".") }
version := env("VERSION", `git describe --tags --dirty --always` + version_platform + version_profile + version_san + version_feat + version_extra)

# Print version that will be used in the build
version:
  @echo "Using version: {{version}}"

# OCI repo to push images to

oci_repo := "127.0.0.1:30000"
oci_insecure := ""
oci_name := "githedgehog/dataplane"
oci_frr_prefix := "githedgehog/dataplane/frr"
oci_image_dataplane := oci_repo + "/" + oci_name + ":" + version
oci_image_dataplane_debugger := oci_repo + "/" + oci_name + "/debugger:" + version
oci_image_dataplane_validator := oci_repo + "/" + oci_name + "/validator:" + version
oci_image_frr_dataplane := oci_repo + "/" + oci_frr_prefix + ":" + version
oci_image_frr_host := oci_repo + "/" + oci_frr_prefix + "-host:" + version

[private]
_skopeo_dest_insecure := if oci_insecure == "true" { "--dest-tls-verify=false" } else { "" }
[private]
_oras_insecure := if oci_insecure == "true" { "--insecure" } else { "" }

[private]
nightly := "false"

[private]
docker_sock := "/var/run/docker.sock"

# Directory the Docker daemon can see, when it cannot see this checkout's
# /nix/store. Empty -- the ordinary case -- means the daemon runs on this host
# and resolves store paths itself.
#
# n-vm's container tier hands the daemon bind-mount *sources*, and the daemon
# resolves them in its own mount namespace. On a CI runner that is itself a
# container talking to the host's daemon, /nix belongs to the runner image and
# the bare metal has nothing at those paths. Because every mount asks Docker to
# create a missing mount point, the daemon answers by creating an *empty*
# directory rather than failing, so the guest root comes up empty and the first
# mount beneath it dies on a read-only filesystem.
#
# Set this to a directory on a filesystem both sides share -- under this
# workspace, which is the one path a containerised runner and its host agree on
# -- and `setup-roots` will export the roots' closure into it. `n-vm` reads the
# same variable and rewrites the mount sources; the targets stay `/nix/store`,
# so rpaths in the guest are unaffected.
n_vm_host_share := env("N_VM_HOST_SHARE_DIR", "")

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
      --argstr nightly '{{nightly}}' \
      --print-build-logs \
      --show-trace \
      --out-link "results/${target}" \
      --max-jobs "{{jobs}}" \
      --cores "{{cores}}" \
      --keep-failed \
      {{ args }}

# run formatters for the code used in this project
[script]
fmt *args:
    {{ _just_debuggable_ }}
    cargo fmt {{args}}

# run a series of pre-flight checks to catch most problems you might find in CI early
[script]
pre-flight: (check-dependencies) (fmt "--check") (test) (lint) (doctest)
    {{ _just_debuggable_ }}
    echo "pre flight checks pass"

[script]
test package="tests.all" *args: (setup-roots) (build (if package == "tests.all" { "tests.all" } else { "tests.pkg." + package }) args)
    {{ _just_debuggable_ }}
    declare -r target="{{ if package == "tests.all" { "tests.all" } else { "tests.pkg." + package } }}"
    # Export the scratch-container roots `setup-roots` just built, so that
    # `#[n_vm::test]` tests find them. The guard is for a tree where
    # `setup-roots` was skipped; the tests fail loudly rather than skip, so
    # this is a clearer error, not a fallback.
    if [[ -e testroot && -e vmroot ]]; then
        export N_VM_TEST_ROOT="$(pwd)/testroot"
        export N_VM_VM_ROOT="$(pwd)/vmroot"
    fi
    # `trybuild` (n-vm-macros' compile-fail suite) shells out to
    # `cargo --offline` for a scratch project under `target/tests/trybuild`,
    # which resolves against the local registry cache rather than the nix
    # vendor directory the workspace was built from. CI builds through nix and
    # never populates that cache, so the suite fails there with "no matching
    # package named `proc-macro2`" while passing on any developer machine.
    # `--locked` means every download is checksum-checked against Cargo.lock,
    # and a warm cache makes this a no-op.
    cargo fetch --locked
    # `--no-tests pass`: a single-package archive whose only test(s) are
    # `#[cfg_attr(emulated, ignore)]` (e.g. n-vm-macros' trybuild test under
    # cross) runs zero tests; treat that as success, matching `test-each`.
    cargo nextest run --archive-file results/${target}/*.tar.zst --workspace-remap $(pwd) --no-tests pass {{ filter }}

# List the bolero targets `just fuzz` can run. Args go to `cargo bolero list`
[script]
fuzz-list *args="":
    {{ _just_debuggable_ }}
    cargo bolero list {{ _cargo_feature_flags }} {{ args }}

# Fuzz one bolero target under libfuzzer. See development/code/running-tests.md
[script]
fuzz target time="60s" *args="":
    {{ _just_debuggable_ }}
    # libfuzzer wants a nightly compiler for its sanitizer coverage flags, while the
    # pinned toolchain is stable; --rustc-bootstrap bridges that. cargo-bolero already
    # builds with the fuzz profile and links AddressSanitizer unless told otherwise, so
    # a plain `just fuzz` is already an asan run. Findings land in a gitignored
    # `__fuzz__` directory beside the test.
    #
    # `sanitize=thread` additionally rebuilds std: thread instrumentation changes the
    # ABI, so a std left uninstrumented fails the build on a mismatch against `core`.
    # asan does not need that, and skipping the std rebuild keeps it far quicker.
    # `sanitize=NONE` drops instrumentation altogether, which buys roughly four times
    # the executions per second in exchange for only catching what the test asserts.
    case "{{ sanitize }}" in
      "") want=address ;;
      NONE) want=none ;;
      *) want="{{ sanitize }}" ;;
    esac
    sysroot="${DATAPLANE_SYSROOT:-}"
    if [ -n "${sysroot}" ] && [ -r "${sysroot}/.sanitize" ]; then
      built_with="$(cat "${sysroot}/.sanitize")"
      built_with="${built_with:-none}"
      if [ "${want}" != "${built_with}" ] && [ -z "{{ sanitize }}" ]; then
        printf 'warning: rust is built with %s and this sysroot with %s, so the C dependencies -- dpdk above all -- are not instrumented.\n' \
          "${want}" "${built_with}" >&2
        printf '         `just sanitize=NONE fuzz ...` instruments neither and runs about four times quicker.\n' >&2
      elif [ "${want}" != "${built_with}" ]; then
        printf 'refusing to fuzz: sanitize=%s was asked for, but this sysroot was built with sanitize=%s.\n' \
          "{{ sanitize }}" "${built_with:-<none>}" >&2
        printf 'the C dependencies would not be instrumented. Re-enter the shell with:\n' >&2
        printf '  just sanitize=%s setup-roots && nix-shell --argstr sanitize %s\n' \
          "{{ sanitize }}" "{{ sanitize }}" >&2
        exit 1
      fi
    fi
    inherited="$(cargo config get -Zunstable-options --format json-value build.rustflags 2>/dev/null | jq -r 'join(" ")')"
    export RUSTFLAGS="${inherited} ${RUSTFLAGS:-}"

    sancov_rt="$(clang -print-file-name=libclang_rt.fuzzer_no_main-$(uname -m).a 2>/dev/null || true)"
    if [ -f "${sancov_rt}" ]; then
      export RUSTFLAGS="${RUSTFLAGS} -Clink-arg=${sancov_rt} -Clink-arg=-lstdc++"
    else
      printf 'warning: no libFuzzer runtime beside clang; packages with a non-bolero test binary will not link.\n' >&2
    fi

    corpus_dir="{{ fuzz_corpus_root }}/$(printf '%s' '{{ target }}' | tr -c 'A-Za-z0-9_.-' '_')"
    mkdir -p "${corpus_dir}"
    cargo bolero test '{{ target }}' --rustc-bootstrap -T '{{ time }}' \
        --profile checked \
        --corpus-dir "${corpus_dir}" \
        -l '{{ fuzz_max_input_length }}' \
        -E='-len_control={{ fuzz_len_control }}' \
        -j '{{ fuzz_jobs }}' \
        {{ if sanitize != "" { "--sanitizer " + sanitize } else { "" } }} \
        {{ if sanitize == "thread" { "--build-std" } else { "" } }} \
        {{ _cargo_feature_flags }} {{ args }}

[private]
[script]
_bench-release-only:
    {{ _just_debuggable_ }}
    if [ '{{ profile }}' != "release" ]; then
      echo "error: benchmarks want profile=release, not '{{ profile }}'" >&2
      echo "       run: just profile=release bench" >&2
      exit 1
    fi

[doc("Wall-clock time, via criterion")]
[script]
bench *args: _bench-release-only (build "benches")
    {{ _just_debuggable_ }}
    shopt -s nullglob
    for bench in ./results/benches/bin/*; do
      case "${bench}" in
        *_callgrind) continue ;;
      esac
      "${bench}" --bench {{ args }}
    done
    if [ -f target/criterion/report/index.html ]; then
      echo
      echo "html report: target/criterion/report/index.html"
    fi

[doc("Instructions and cache traffic, via iai-callgrind")]
[script]
bench-callgrind *args:
    {{ _just_debuggable_ }}
    cargo bench -p "${callgrind_package}" --bench "${callgrind_bench}" {{ args }}

[doc("Compare against a baseline and print a markdown report")]
[script]
bench-compare baseline="base" *args:
    {{ _just_debuggable_ }}
    mkdir -p results/bench
    # Decide save-or-compare *before* running, and scope the question to this suite's own
    # output directory. Two things went wrong when this was one condition. A file anywhere
    # under `target/iai` -- another package, another benchmark -- answered "a baseline
    # exists", and the run then found none for any benchmark here, succeeded, and reported a
    # new baseline it had not written; every repeat did the same. And with the comparison run
    # inside the `if`, any non-zero exit (a compile error, a panicking benchmark, a runner
    # version mismatch) fell through to the `else` and overwrote the baseline being compared
    # against -- with stderr discarded, so nothing said why.
    # iai-callgrind writes to `target/iai[/<triple>]/<CARGO_PKG_NAME>/<module path>/<bench>`,
    # so match on the two components that identify this suite and stay agnostic about the
    # optional target triple above them and the group nesting below.
    scope="*/${callgrind_package}/${callgrind_bench}/*"
    if find target/iai -type f -path "${scope}" -name '*base@{{ baseline }}*' -print -quit 2>/dev/null | grep -q .; then
      cargo bench -p "${callgrind_package}" --bench "${callgrind_bench}" -- \
        --baseline='{{ baseline }}' --output-format=json > results/bench/run.jsonl
    else
      echo "no baseline '{{ baseline }}' for ${callgrind_package}/${callgrind_bench}; recording one" >&2
      cargo bench -p "${callgrind_package}" --bench "${callgrind_bench}" -- \
        --save-baseline='{{ baseline }}' --output-format=json > results/bench/run.jsonl
    fi
    ./scripts/bench-report.ts results/bench/run.jsonl {{ args }}

[doc("Record a baseline for `bench-compare`, without reporting")]
[script]
bench-baseline name="base":
    {{ _just_debuggable_ }}
    cargo bench -p "${callgrind_package}" --bench "${callgrind_bench}" -- \
      --save-baseline='{{ name }}' > /dev/null
    echo "recorded baseline '{{ name }}'"

[doc("Serve the criterion html report over http")]
[script]
bench-serve port="8080":
    {{ _just_debuggable_ }}
    just serve ./target/criterion '{{ port }}' report/index.html

[script]
build-each *args: (build "workspace" args)
    {{ _just_debuggable_ }}

[script]
check package="" *args: (build (if package == "" { "check" } else { "check." + package }) args)
    {{ _just_debuggable_ }}

[script]
check-each *args: (build "check" args)
    {{ _just_debuggable_ }}

[script]
test-each *args: (setup-roots) (build "tests.pkg" args)
    {{ _just_debuggable_ }}
    # Same two requirements as `test`: the per-package archives include
    # `dataplane-n-vm`'s guest-booting suite, and n-vm-macros' trybuild suite
    # resolves against the local registry cache.
    if [[ -e testroot && -e vmroot ]]; then
        export N_VM_TEST_ROOT="$(pwd)/testroot"
        export N_VM_VM_ROOT="$(pwd)/vmroot"
    fi
    cargo fetch --locked
    declare -a fail=()
    for test_archive in results/tests.pkg*/*.tar.zst; do
        if ! cargo nextest run --archive-file "${test_archive}" --workspace-remap "$(pwd)" --no-tests pass; then
            fail+=("${test_archive} failed")
        fi
    done
    if [ "${#fail[@]}" -gt 0 ]; then
        >&2 printf '%s\n' "${fail[@]}"
        exit 1
    fi

[script]
docs package="" *args: (build (if package == "" { "docs.all" } else { "docs.pkg." + package }) args)
    {{ _just_debuggable_ }}

# Remove test containers n-vm left behind. Args go to n-vm-reap (--force, --list, --all)
[script]
reap *args:
    {{ _just_debuggable_ }}
    # The host tier cleans up after itself on every route it can reach,
    # including SIGTERM and SIGINT, so this is only needed after a SIGKILL, an
    # OOM kill, or a reboot -- none of which give a process the chance to tidy
    # up. Containers whose creating process is still alive are left alone
    # unless `--all` is passed, so this is safe to run while other tests are
    # going. Without a tty it refuses to remove anything; CI should pass
    # `--force`.
    cargo run --quiet -p dataplane-n-vm --features reap --bin n-vm-reap -- {{ args }}

# Create devroot, sysroot, testroot, and vmroot symlinks for local development
[script]
setup-roots *args:
    {{ _just_debuggable_ }}
    for root in devroot sysroot testroot vmroot; do
      nix build -f default.nix "${root}" \
        --argstr default-features '{{ default_features }}' \
        --argstr features '{{ features }}' \
        --argstr instrumentation '{{ instrument }}' \
        --argstr kernel '{{ kernel }}' \
        --argstr libc '{{ libc }}' \
        --argstr nightly '{{nightly}}' \
        --argstr platform '{{ platform }}' \
        --argstr profile '{{ profile }}' \
        --argstr sanitize '{{ sanitize }}' \
        --argstr tag '{{version}}' \
        --out-link "${root}" \
        {{ args }}
    done

    if [ -n "{{ n_vm_host_share }}" ]; then
      just n_vm_host_share="{{ n_vm_host_share }}" export-scratch-roots
    fi

# Copy the scratch roots' nix closure somewhere the Docker daemon can read it.
# See `n_vm_host_share`; a no-op unless that is set.
[script]
export-scratch-roots:
    {{ _just_debuggable_ }}
    declare -r share="{{ n_vm_host_share }}"
    if [ -z "${share}" ]; then
      echo "n_vm_host_share is unset; nothing to export"
      exit 0
    fi
    declare -r store="${share}/nix/store"
    # `tmp` is the other half: the forwarded-environment directory is a bind
    # source too, and a container-local /tmp is no more visible than /nix.
    mkdir -p "${store}" "${share}/tmp"

    # The closure, not the whole store. `/nix/store` is mounted into the
    # container whole, so the export has to cover everything the container
    # resolves through it, which is two things:
    #
    #   testroot/vmroot  the host tier's qemu, cloud-hypervisor and virtiofsd,
    #                    the guest kernel, and n-it inside the guest root
    #   sysroot          what the *test binary* is linked against. Missing this
    #                    is not a missing-file error: the binary is there and
    #                    execs, and the kernel reports ENOENT for its absent
    #                    ELF interpreter, so the container exits 127 with
    #                    "No such file or directory" naming a path that plainly
    #                    exists.
    #
    # devroot is deliberately not here. It is the toolchain -- 4.6 GiB against
    # sysroot's 2.0 -- and nothing inside the container compiles.
    declare -a roots=( testroot vmroot sysroot )
    declare -a resolved=()
    for root in "${roots[@]}"; do
      if [ ! -e "${root}" ]; then
        >&2 echo "::error::${root} is missing; run setup-roots first"
        exit 1
      fi
      resolved+=( "$(readlink -f "${root}")" )
    done
    declare -a paths
    mapfile -t paths < <(nix-store --query --requisites "${resolved[@]}")

    declare -i copied=0 kept=0
    for path in "${paths[@]}"; do
      declare dest="${store}/$(basename "${path}")"
      # A store path is immutable, so an entry that is already here is already
      # right. This is what makes the second job on a runner cheap.
      if [ -e "${dest}" ]; then
        kept+=1
        continue
      fi
      # Copy to a private name and rename, so a concurrent job never observes
      # a half-copied path under a name that promises a whole one.
      declare staging="${store}/.staging-$$-$(basename "${path}")"
      rm -rf -- "${staging}"
      cp -a --no-preserve=ownership -- "${path}" "${staging}"
      # A store path's directories are r-xr-xr-x, which nix relies on to keep
      # them immutable. A copy has no such contract, and inheriting the mode
      # makes the export undeletable: `rm -rf` cannot unlink a child of a
      # directory it cannot write. Whoever cleans this runner should not have
      # to know that.
      chmod -R u+w -- "${staging}"
      if ! mv -T -- "${staging}" "${dest}" 2>/dev/null; then
        # Lost the race; the winner's copy is as good as ours.
        chmod -R u+w -- "${staging}" 2>/dev/null || true
        rm -rf -- "${staging}"
      fi
      copied+=1
    done
    # Reported from nix rather than `du`: on a copy-on-write filesystem `du`
    # run straight after the copy reports blocks that are still dirty, which
    # made a 1.8 GiB export read as 26 MiB.
    printf 'exported %d store paths to %s (%d already present, %s closure)\n' \
        "${copied}" "${store}" "${kept}" \
        "$(nix path-info -S "${resolved[@]}" 2>/dev/null | awk '{t+=$2} END {printf "%.1f GiB", t/1024/1024/1024}')"

[private]
[script]
_refuse-instrumented-artifact:
    if [ -n '{{ instrument }}' ] && [ '{{ instrument }}' != "none" ]; then
      printf 'refusing to build a container at instrument=%s: an instrumented build is a diagnostic,\n' '{{ instrument }}' >&2
      printf 'not an artifact, and instrumentation is not part of the version -- so this image would\n' >&2
      printf 'take a clean image tag and replace it.\n' >&2
      exit 1
    fi

# Build the dataplane container image
[script]
build-container target="dataplane" *args: _refuse-instrumented-artifact (build (if target == "dataplane" { "dataplane.tar" } else if target == "validator" { "workspace.validator" } else { "containers." + target }) args)
    {{ _just_debuggable_ }}
    declare -xr DOCKER_HOST="${DOCKER_HOST:-unix://{{docker_sock}}}"
    case "{{target}}" in
        "dataplane")
            declare docker_platform
            case "{{platform}}" in
                aarch64|bluefield2|bluefield3) docker_platform="linux/arm64" ;;
                x86-64-v3|x86-64-v4|zen3|zen4|zen5) docker_platform="linux/amd64" ;;
                *)
                    >&2 echo "build-container: no docker platform mapping for {{platform}}"
                    exit 1
                    ;;
            esac
            declare -r docker_platform
            declare img
            # The rootfs tarball carries no image config; everything the runtime sees is set
            # here. A controller owns the dataplane's argv in a fabric, so an environment
            # variable baked in at import is the only way to reach an option like the pyroscope
            # endpoint.
            declare -a import_changes=(--change 'ENTRYPOINT ["/bin/dataplane"]')
            if [ -n "{{ pyroscope_url }}" ]; then
                import_changes+=(--change 'ENV DATAPLANE_PYROSCOPE_URL={{ pyroscope_url }}')
            fi
            if [ -n "{{ dataplane_proxy_url }}" ]; then
                # Both spellings: reqwest reads the lowercase one, most other clients the upper.
                import_changes+=(--change 'ENV HTTP_PROXY={{ dataplane_proxy_url }}')
                import_changes+=(--change 'ENV http_proxy={{ dataplane_proxy_url }}')
            fi
            img="$(docker import --platform "${docker_platform}" "${import_changes[@]}" ./results/dataplane.tar)"
            declare -r img
            docker tag "${img}" "{{oci_image_dataplane}}"
            echo "imported {{ oci_image_dataplane }} (${docker_platform})"
            ;;
        "dataplane-debugger")
            docker load < ./results/containers.dataplane-debugger
            docker tag "ghcr.io/githedgehog/dataplane/debugger:{{version}}" "{{oci_image_dataplane_debugger}}"
            echo "imported {{ oci_image_dataplane_debugger }}"
            ;;
        "debug-tools")
            # Uses nix only to produce a base image with the runtime closure (glibc, bash, etc.)
            # then layers locally-compiled cargo binaries on top via Dockerfile.
            # See the `build-container-quick` recipe.
            docker load < ./results/containers.debug-tools
            echo "imported debug-tools:dev"
            ;;
        "frr.dataplane")
            docker load < ./results/containers.frr.dataplane
            docker tag "ghcr.io/githedgehog/dataplane/frr:{{version}}" "{{oci_image_frr_dataplane}}"
            echo "imported {{oci_image_frr_dataplane}}"
            ;;
        "frr.host")
            docker load < ./results/containers.frr.host
            docker tag "ghcr.io/githedgehog/dataplane/frr-host:{{version}}" "{{oci_image_frr_host}}"
            echo "imported {{oci_image_frr_host}}"
            ;;
        "validator")
            echo "NOTE: validator image is wasm and not containerized"
            ;;
        *)
            >&2 echo "{{target}} is not a valid container"
            exit 99
    esac

# WARNING: The resulting image must NEVER be pushed to a shared registry.
# NOTE: this recipe intentionally does not depend on build-container "debug-tools" to make the call fast.
# Quick (non-sterile) container build using local cargo artifacts
[script]
build-container-quick:
    {{ _just_debuggable_ }}
    docker build \
        --file ./Dockerfile \
        --build-arg PROFILE="{{profile}}" \
        --label sterile="false" \
        --annotation sterile="false" \
        --tag "dataplane:dev" \
        .
    echo "imported dataplane:dev"

# Build and push the dataplane container
[script]
push-container target="dataplane" *args: (build-container target args) && version
    {{ _just_debuggable_ }}
    declare -xr DOCKER_HOST="${DOCKER_HOST:-unix://{{docker_sock}}}"

    # Preserve completed builds across transient registry failures. Skopeo
    # retries blobs; this outer loop retries known-safe, idempotent whole pushes
    # and announces them so registry degradation remains visible.
    retry() {
        declare -r what="$1"
        shift
        declare -ri attempts=4
        declare -i attempt=1
        declare -i delay
        declare log
        log="$(mktemp)"
        declare -r log
        while true; do
            # Stream multi-gigabyte pushes so they do not appear hung.
            if "$@" 2>&1 | tee "${log}"; then
                rm -f -- "${log}"
                return 0
            fi
            if [ "${attempt}" -ge "${attempts}" ]; then
                >&2 echo "::error::${what} failed after ${attempts} attempts"
                rm -f -- "${log}"
                return 1
            fi
            # Match registry status and transport vocabulary shared by skopeo
            # and oras. Bound 403 so it cannot match inside a digest.
            if ! grep -qiE \
                    -e 'blob upload (unknown|invalid)|blob transfer' \
                    -e '\b(403|429|500|502|503|504)\b' \
                    -e 'forbidden|denied|too many requests|rate limit' \
                    -e 'internal server error|bad gateway|service unavailable|gateway time-?out' \
                    -e 'temporarily unavailable|try again' \
                    -e 'unexpected EOF|connection reset|broken pipe|i/o timeout|TLS handshake' \
                    "${log}"; then
                >&2 echo "::error::${what} failed with a non-retryable error"
                rm -f -- "${log}"
                return 1
            fi
            delay=$(( 5 * 2 ** (attempt - 1) + RANDOM % 5 ))
            >&2 echo "::warning::${what} failed (attempt ${attempt}/${attempts}), retrying in ${delay}s"
            sleep "${delay}"
            attempt=$(( attempt + 1 ))
        done
    }

    push_image() {
        declare -r image="$1"
        retry "push of ${image}" \
            skopeo copy --retry-times=3 --src-daemon-host="${DOCKER_HOST}" \
                {{ _skopeo_dest_insecure }} "docker-daemon:${image}" "docker://${image}"
        echo "Pushed ${image}"
    }

    case "{{target}}" in
        "dataplane")
            push_image "{{ oci_image_dataplane }}"
            ;;
        "dataplane-debugger")
            push_image "{{ oci_image_dataplane_debugger }}"
            ;;
        "debug-tools")
            >&2 echo "do not push the debug tools!"
            exit 1
            ;;
        "frr.dataplane")
            push_image "{{oci_image_frr_dataplane}}"
            ;;
        "frr.host")
            push_image "{{oci_image_frr_host}}"
            ;;
        "validator")
            if [ "{{platform}}" != "wasm32-wasip1" ]; then
              >&2 echo "Pushing non wasm32-wasip1 validator images is not supported, set platform=wasm32-wasip1"
              exit 1
            fi
            pushd ./results/workspace.validator/bin
            retry "push of {{ oci_image_dataplane_validator }}" \
                oras push {{ _oras_insecure }} --annotation version="{{ version }}" "{{ oci_image_dataplane_validator }}" ./validator.wasm
            popd
            echo "Pushed {{ oci_image_dataplane_validator }}"
            ;;
        *)
            >&2 echo "{{target}} is not a valid container"
            exit 99
    esac

# Note: deliberately ignores all recipe parameters save version, debug_justfile,
# oci_repo, and the jobs/cores build-parallelism caps.
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
        just jobs="{{jobs}}" cores="{{cores}}" debug_justfile="{{debug_justfile}}" oci_repo="{{oci_repo}}" version="{{version}}" profile=release platform="${platform}" sanitize= instrument=none push-container "${container}"
    done

# Print names of container images to build or push
[script]
print-container-tags:
    echo "{{ oci_image_dataplane }}"

# Check dependency licenses and security advisories
[script]
check-dependencies *args:
    {{ _just_debuggable_ }}
    cargo deny {{ _cargo_feature_flags }} check {{ args }}

# Ensure the shared dependency derivations stay reusable across revisions.
#
# Two things break that, and they are different kinds of thing, so they take
# different questions.
#
# The workspace source is a store path, so "the dependency build must not
# depend on it" is a statement about the derivation graph and nix can answer it
# outright: instantiate once and read the inputs. That is exact, it names the
# offending path, and it needs no edit to the working tree.
#
# The git version is a string. It reaches a derivation as an environment
# variable and never as an input path, so no graph walk can see it; the only
# way to ask is to instantiate under two tags and compare.
#
# Both have regressed before, and both surface as a slow cache miss rather than
# a failure, which is why they are checked at all.
[script]
check-deps-reuse:
    {{ _just_debuggable_ }}
    # Keep Nix stderr; it is the only diagnostic when instantiation fails.
    declare src
    src="$(nix eval --raw --impure --expr '(import ./default.nix { }).src.outPath')"
    declare -r src
    if [ -z "${src}" ]; then
        >&2 echo "::error::could not resolve the workspace source path"
        exit 1
    fi

    deps_drv() {
        declare drv
        drv="$(nix-instantiate default.nix -A "$1" --argstr tag "$3" | tail -1)"
        grep -ao "/nix/store/[a-z0-9]\{32\}-$2[^\"]*\.drv" "${drv}" | sort -u
    }

    # Report through the status; command substitution would run this in a
    # subshell and discard failure-count updates.
    check_reuse() {
        declare -r attr="$1" name="$2"

        declare baseline
        if ! baseline="$(deps_drv "${attr}" "${name}" dev)" || [ -z "${baseline}" ]; then
            >&2 echo "::error::could not resolve ${name} from ${attr}"
            return 1
        fi

        # The source question, put to the graph.
        declare drv
        while IFS= read -r drv; do
            [ -z "${drv}" ] && continue
            if nix-store -q --requisites "${drv}" | grep -qxF "${src}"; then
                >&2 echo "::error::${name} depends on the workspace source"
                >&2 echo "  ${src}"
                >&2 echo "  is a build input of ${drv}"
                return 1
            fi
        done <<<"${baseline}"

        # The version question, put to two instantiations.
        declare tagged
        if ! tagged="$(deps_drv "${attr}" "${name}" v0.25.2-15-gdeadbee-dirty)"; then
            >&2 echo "::error::could not resolve ${name} from ${attr} with a release tag"
            return 1
        fi
        if [ "${tagged}" != "${baseline}" ]; then
            >&2 echo "::error::${name} depends on the git version"
            >&2 echo "  tag=dev  -> ${baseline}"
            >&2 echo "  tag=v0.. -> ${tagged}"
            return 1
        fi

        printf '%s is reusable: %s\n' "${name}" "${baseline}"
    }

    # Check production and test flag sets independently: a regression in a
    # production-only flag would sail past a test-only guard.
    declare -r -A targets=(
        [workspace.dataplane]="dataplane-deps"
        [tests.all]="dataplane-tests-deps"
    )
    declare -i failures=0
    for attr in "${!targets[@]}"; do
        check_reuse "${attr}" "${targets[${attr}]}" || failures=$(( failures + 1 ))
    done

    if [ "${failures}" -ne 0 ]; then
        exit 1
    fi

[script]
opengrep:
    {{ _just_debuggable_ }}
    opengrep scan --experimental --verbose --error --config auto --config .semgrep/rules

[script]
pinact *args="--check --verify":
    {{ _just_debuggable_ }}
    pinact run {{ args }}

[script]
zizmor *args="":
    {{ _just_debuggable_ }}
    zizmor --persona=pedantic {{args}} .

# Run the CI-equivalent cached lint; direct Cargo remains the fast inner loop.
clippy package="" *args: (build (if package == "" { "clippy.all" } else { "clippy.pkg." + package }) args)
    {{ _just_debuggable_ }}

[script]
actionlint:
    {{ _just_debuggable_ }}
    actionlint

# Keep default.nix formatted without adopting legacy files under nix/.
[script]
nixfmt *args="--check":
    {{ _just_debuggable_ }}
    nixfmt {{ args }} default.nix

# Keep the lint recipe, workflow steps, and outcome aggregation aligned; drift
# in any of the three silently disables a check.
[script]
check-lint-wiring:
    {{ _just_debuggable_ }}
    declare -r wf=".github/workflows/dev.yml"
    declare -i failures=0

    # Nix-backed checks run under a `ci::check-` prefix; accept either spelling
    # so a recipe stays covered when it moves between workflow jobs.
    declare recipe
    while read -r recipe; do
        grep -qE "recipe: \"(ci::check-)?${recipe}\"" "${wf}" && continue
        >&2 echo "::error::\`just lint\` runs ${recipe}, but ${wf} never does"
        failures=$(( failures + 1 ))
    done < <(just --dump --dump-format json | jq -r '.recipes.lint.dependencies[].recipe')

    # Every lint step is `continue-on-error`, so a step the aggregator does not
    # read cannot fail the run.
    declare id
    while read -r id; do
        grep -qF "steps.${id}.outcome" "${wf}" && continue
        >&2 echo "::error::${wf} runs ${id} but never reads its outcome"
        failures=$(( failures + 1 ))
    done < <(yq -r '.jobs.lint.steps[] | select(.id) | .id' "${wf}")

    if [ "${failures}" -ne 0 ]; then
        exit 1
    fi
    echo "lint wiring agrees"

# Images are per-revision, so verify that each realized image and its
# dockerTools assembly paths are rejected by the actual Cachix push filter.
[script]
check-push-filter:
    {{ _just_debuggable_ }}
    declare -r action=".github/actions/nix-shell/action.yml"
    declare push_filter
    push_filter="$(yq -r '.runs.steps[] | select(.with.pushFilter) | .with.pushFilter' "${action}")"
    declare -r push_filter
    if [ -z "${push_filter}" ] || [ "${push_filter}" = "null" ]; then
        >&2 echo "::error::no pushFilter found in ${action}; nothing is keeping images out of the cache"
        exit 1
    fi

    # Walk `containers` and `dataplane` both: the latter holds `dataplane.tar`,
    # which the release build selects directly and which is per-revision for the
    # same reasons. Both nest, so recurse rather than assume one level.  Each line is "attr outPath drvPath".
    declare -a images=()
    mapfile -t images < <(
        nix eval --impure --raw --expr '
          let
            d = import ./default.nix { };
            lib = d.pkgs.lib;
            flatten = prefix: set:
              lib.concatLists (lib.mapAttrsToList (n: v:
                let nm = if prefix == "" then n else "${prefix}.${n}"; in
                if lib.isDerivation v then [ "${nm} ${v.outPath} ${v.drvPath}" ]
                else if builtins.isAttrs v then flatten nm v
                else [ ]
              ) set);
          in lib.concatStringsSep "\n" (flatten "" { inherit (d) containers dataplane; }) + "\n"
        '
    )
    if [ "${#images[@]}" -eq 0 ]; then
        >&2 echo "::error::found no container images to check; did the attribute move?"
        exit 1
    fi

    declare -i failures=0
    declare -i checked=0
    for entry in "${images[@]}"; do
        [ -z "${entry}" ] && continue
        declare name out drv base
        read -r name out drv <<<"${entry}"
        # Recover the base name after `source-volatile` has renamed the output.
        base="${out##*/}"
        base="${base#*-dataplane-volatile-}"
        base="${base%.tar.gz}"

        declare -a candidates=( "${out}" )
        # Test dockerTools artifacts; ordinary closure dependencies stay cached.
        mapfile -t -O "${#candidates[@]}" candidates < <(
            nix-store -q --requisites "${drv}" 2>/dev/null \
                | grep '\.drv$' \
                | xargs -r nix-store -q --outputs 2>/dev/null \
                | sort -u \
                | while IFS= read -r path; do
                    declare stem="${path##*/}"
                    case "${stem#*-}" in
                        "${base}-base.json" | "${base}-conf.json" \
                        | "${base}-customisation-layer" | "${base}-env" \
                        | "stream-${base}") printf '%s\n' "${path}" ;;
                    esac
                done
        )

        for path in "${candidates[@]}"; do
            checked=$(( checked + 1 ))
            if ! printf '%s\n' "${path}" | grep -qE "${push_filter}"; then
                >&2 echo "::error::${name} would push ${path##*/} to Cachix"
                failures=$(( failures + 1 ))
            fi
        done
    done

    if [ "${failures}" -ne 0 ]; then
        >&2 echo "::error::extend the pushFilter in ${action}, or mark the image with \`source-volatile\`"
        exit 1
    fi
    printf 'no cache leak: %d paths across %d artifacts\n' "${checked}" "${#images[@]}"

# Limit linting to tracked Markdown so generated files cannot affect CI.
[script]
markdownlint *args:
    {{ _just_debuggable_ }}
    git ls-files -z '*.md' | xargs -0 markdownlint-cli2 {{ args }}

[script]
license-headers:
    {{ _just_debuggable_ }}
    declare -i res=0
    for f in $(git ls-files '*.rs' '*.sh' justfile); do
        if ! head "${f}" | grep -wq 'SPDX'; then
            echo "::error::Missing SPDX license header in file ${f}"
            res=1
        fi
        if ! head "${f}" | grep -wqi 'copyright'; then
            echo "::error::Missing copyright notice in file ${f}"
            res=1
        fi
    done
    exit ${res}

# NOTE: commitlint-rs's `--from`/`--to` flags are unusable in any
# non-interactive shell (CI, this recipe, etc): its arg-handling checks stdin
# before checking --from/--to, and stdin is never a TTY there, so it silently
# lints empty/stray stdin content instead of the requested commit range.
# See https://github.com/KeisukeYamashita/commitlint-rs/blob/main/cli/src/args.rs
# Work around it by feeding each commit's message to commitlint individually
# over stdin, which is the one invocation mode that actually works.
[script]
commitlint base="origin/main":
    {{ _just_debuggable_ }}
    declare -i status=0
    while IFS= read -r sha; do
        if ! git log -1 --format=%B "${sha}" | commitlint; then
            echo "::error::commit ${sha} failed commitlint" >&2
            status=1
        fi
    done < <(git log --format=%H --no-merges "{{base}}"..HEAD)
    exit "${status}"

# Run linters
[script]
lint: \
    (fmt "--check") \
    (clippy) \
    (commitlint) \
    (check-dependencies) \
    (opengrep) \
    (zizmor) \
    (pinact "--fix=false" "--no-api") \
    (actionlint) \
    (markdownlint) \
    (nixfmt) \
    (check-lint-wiring) \
    (check-push-filter) \
    (license-headers) \
    (duvet-check)
    {{ _just_debuggable_ }}

# Cargo cannot archive doctests, so run them inside the Nix sandbox.
doctest package="" *args: (build (if package == "" { "doctests.all" } else { "doctests.pkg." + package }) args)
    {{ _just_debuggable_ }}


# Run instrumented tests and report coverage. Args are forwarded to nextest; for example,
# `just coverage -p dataplane-nat` scopes the run to this crate.
[script]
coverage *args: (setup-roots)
    {{ _just_debuggable_ }}
    export BOLERO_RANDOM_TEST_TIME_MS="{{ bolero_coverage_test_time_ms }}"
    # Export the scratch-container roots `setup-roots` just built, so that
    # `#[n_vm::test]` tests find them. The guard is for a tree where
    # `setup-roots` was skipped; the tests fail loudly rather than skip, so
    # this is a clearer error, not a fallback.
    if [[ -e testroot && -e vmroot ]]; then
      export N_VM_TEST_ROOT="$(pwd)/testroot"
      export N_VM_VM_ROOT="$(pwd)/vmroot"
    fi
    # See the `test` recipe: trybuild resolves its scratch project against the
    # local registry cache.
    cargo fetch --locked
    export LLVM_COV="$(pwd)/devroot/bin/llvm-cov"
    export LLVM_PROFDATA="$(pwd)/devroot/bin/llvm-profdata"
    declare -r out="./target/nextest/coverage"
    cargo llvm-cov clean --workspace
    cargo llvm-cov --no-report --branch nextest {{ args }}
    mkdir -p "${out}"
    cargo llvm-cov report --branch --html --output-dir="${out}"
    cargo llvm-cov report --branch --lcov --output-path="${out}/lcov.info"
    cargo llvm-cov report --branch --codecov --output-path="${out}/codecov.json"
    cargo llvm-cov report --branch --summary-only
    echo
    echo "html report: ${out}/html/index.html  (\`just serve-coverage\` to browse it)"

serve_host := "127.0.0.1"

[doc("Serve a directory of generated html over http")]
[script]
serve dir port="8080" index="index.html":
    {{ _just_debuggable_ }}
    if [ ! -d '{{ dir }}' ]; then
      echo "error: no such directory: {{ dir }}" >&2
      exit 1
    fi
    server="$(command -v static-web-server || true)"
    if [ -z "${server}" ] && [ -x ./devroot/bin/static-web-server ]; then
      server="$(pwd)/devroot/bin/static-web-server"
    fi
    if [ -z "${server}" ]; then
      echo "error: static-web-server not found; re-enter the dev shell, or \`just setup-roots\`" >&2
      exit 1
    fi
    echo "serving {{ dir }} at http://{{ serve_host }}:{{ port }}/{{ index }} (ctrl-c to stop)"
    "${server}" --root '{{ dir }}' --host '{{ serve_host }}' --port '{{ port }}' --log-level warn

serve-coverage port="8080": (serve "./target/nextest/coverage/html" port)

[script]
duvet *args:
    {{ _just_debuggable_ }}
    duvet report {{ args }}

[script]
duvet-check:
    {{ _just_debuggable_ }}
    for input in .duvet/config.toml .duvet/snapshot.txt; do
      if [ ! -f "${input}" ]; then
        echo "error: ${input} is missing; this check has nothing to compare and cannot pass" >&2
        exit 1
      fi
    done
    # `duvet report` rewrites the snapshot *and* every requirement TOML in place, so the
    # committed copies are set aside and put back either way. A check that leaves the
    # working tree dirty is a trap anywhere; in a repo with worktrees and a shared stash
    # stack it is a trap that costs someone else's work.
    committed="$(mktemp -d)"
    trap 'rm -rf .duvet/requirements .duvet/snapshot.txt; \
          mv "${committed}/requirements" .duvet/requirements; \
          mv "${committed}/snapshot.txt" .duvet/snapshot.txt; \
          rmdir "${committed}"' EXIT
    cp -r .duvet/requirements "${committed}/requirements"
    cp .duvet/snapshot.txt "${committed}/snapshot.txt"
    duvet report
    stale=0
    diff -u "${committed}/snapshot.txt" .duvet/snapshot.txt || stale=1
    diff -ru "${committed}/requirements" .duvet/requirements || stale=1
    if [ "${stale}" != 0 ]; then
      echo "error: the duvet report is stale; run \`just duvet\` and commit the result" >&2
      exit 1
    fi

[script]
mutants *args:
    {{ _just_debuggable_ }}
    cargo mutants --test-tool nextest {{ args }}

[script]
spec-interlock *args:
    {{ _just_debuggable_ }}
    ./scripts/spec-interlock.ts {{ args }}

[script]
duvet-summary *args:
    {{ _just_debuggable_ }}
    ./scripts/duvet-summary.ts {{ args }} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

# Use Nix-built archives so local and CI coverage report the same binaries.
[script]
coverage-archive package="tests.all" *args: (setup-roots)
    {{ _just_debuggable_ }}
    declare -r target="{{ if package == "tests.all" { "tests.all" } else { "tests.pkg." + package } }}"
    just \
        jobs="{{jobs}}" \
        cores="{{cores}}" \
        debug_justfile="{{debug_justfile}}" \
        profile="{{profile}}" \
        libc="{{libc}}" \
        sanitize="{{sanitize}}" \
        features="{{features}}" \
        default_features="{{default_features}}" \
        platform="{{platform}}" \
        nightly="{{nightly}}" \
        instrument=coverage \
        build "${target}"

    declare -r root="$(pwd)"
    declare -r out="${root}/target/coverage"
    declare -r profraw="${out}/profraw"
    declare -r extract="${out}/extract"

    rm -rf -- "${out}"
    mkdir -p -- "${profraw}" "${extract}"

    # Make the count below see zero instead of a literal unmatched glob.
    shopt -s nullglob
    declare -ra archives=( "results/${target}"/*.tar.zst )
    shopt -u nullglob
    if [ "${#archives[@]}" -ne 1 ]; then
        >&2 echo "::error::expected exactly one archive in results/${target}, found ${#archives[@]}"
        exit 1
    fi
    declare -r archive="${archives[0]}"

    declare -r prefix_file="results/${target}/source-prefix"
    if [ ! -r "${prefix_file}" ]; then
        >&2 echo "::error::${prefix_file} is missing; the archive predates it, rebuild it"
        exit 1
    fi
    declare src_prefix
    src_prefix="$(cat "${prefix_file}")"
    declare -r src_prefix
    # llvm-cov resolves relative remaps against the vanished build sandbox.
    # Reject absolute prefixes and redirect relative ones to this worktree.
    case "${src_prefix}" in
        /*)
            >&2 echo "::error::source prefix ${src_prefix} is absolute; coverage expects a relative remap"
            exit 1
            ;;
    esac

    # llvm-cov emits the resolved absolute paths and Codecov wants them relative
    # to the repository root, so the root goes into a BRE below.  Escape it.
    declare root_re
    root_re="$(sed -e 's#[].[^$*\\/]#\\&#g' <<<"${root}")"
    declare -r root_re

    # Nextest changes cwd; `%m` also pools compatible profiles across tests.
    export LLVM_PROFILE_FILE="${profraw}/cov-%m.profraw"

    # This recipe -- not `coverage` -- is what CI runs (`ci::coverage`), and it
    # runs the tests on the runner rather than in the nix sandbox, so the
    # guest-booting tests need the same two things `test` gives them.
    if [[ -e testroot && -e vmroot ]]; then
        export N_VM_TEST_ROOT="${root}/testroot"
        export N_VM_VM_ROOT="${root}/vmroot"
    fi
    # See the `test` recipe: trybuild resolves its scratch project against the
    # local registry cache, which a nix-only CI job never populates.
    cargo fetch --locked

    # Report partial coverage before propagating a test failure.
    declare -i test_status=0
    cargo nextest run \
        --archive-file "${archive}" \
        --extract-to "${extract}" \
        --workspace-remap "${root}" \
        {{ filter }} {{ args }} || test_status="$?"

    declare -r profraw_list="${out}/profraw.list"
    find "${profraw}" -type f -name '*.profraw' > "${profraw_list}"
    if [ ! -s "${profraw_list}" ]; then
        >&2 echo "::error::no raw profiles were written; was ${archive} built with instrument=coverage?"
        exit 1
    fi
    llvm-profdata merge -sparse --input-files="${profraw_list}" -o "${out}/coverage.profdata"

    # Pass one primary object and filter reports to workspace sources.
    declare target_dir
    target_dir="$(jq -er '."rust-build-meta"."target-directory"' "${extract}/target/nextest/binaries-metadata.json")"
    declare -r target_dir
    declare -a objects=()
    while IFS= read -r binary; do
        if [ ! -x "${binary}" ]; then
            >&2 echo "::error::${binary} is listed in the archive metadata but is not present"
            exit 1
        fi
        if [ "${#objects[@]}" -eq 0 ]; then
            objects+=( "${binary}" )
        else
            objects+=( -object "${binary}" )
        fi
    done < <(
        jq -er --arg prefix "${target_dir}/" --arg extract "${extract}/target/" \
            '."rust-binaries"[]."binary-path" | $extract + ltrimstr($prefix)' \
            "${extract}/target/nextest/binaries-metadata.json"
    )

    # Resolve remapped paths against this worktree and filter out the standard
    # library and native dependencies. llvm-cov ignores nonexistent filters,
    # so the trailing path must name the real tree.
    declare -ra scope=( --compilation-dir="${root}" "${objects[@]}" "${root}" )

    llvm-cov export \
        --format=lcov \
        --instr-profile="${out}/coverage.profdata" \
        "${scope[@]}" \
        | sed -e "s#^SF:${root_re}/#SF:#" > "${out}/lcov.info"

    # Codecov needs repository-relative paths; reject failed rewrites.
    if grep -q '^SF:/' "${out}/lcov.info"; then
        >&2 echo "::error::absolute paths survived the ${root} rewrite:"
        >&2 grep -m5 '^SF:/' "${out}/lcov.info"
        exit 1
    fi

    # A filter that matches nothing reports full coverage of an empty set, which
    # reads as success everywhere downstream.  Insist on some workspace source.
    if ! grep -q '^SF:' "${out}/lcov.info"; then
        >&2 echo "::error::no workspace sources in the report; the ${root} filter matched nothing"
        exit 1
    fi

    llvm-cov show \
        --format=html \
        --output-dir="${out}/html" \
        --show-branches=count \
        --instr-profile="${out}/coverage.profdata" \
        "${scope[@]}"

    llvm-cov report \
        --instr-profile="${out}/coverage.profdata" \
        "${scope[@]}"

    echo "lcov report: ${out}/lcov.info"
    echo "html report: ${out}/html/index.html"
    exit "${test_status}"

# Regenerate the dependency graph for the project
[script]
depgraph:
    {{ _just_debuggable_ }}
    cargo depgraph --exclude dataplane-test-utils,dataplane-dpdk-sysroot-helper --workspace-only \
      | sed 's/dataplane-//g' \
      | dot -Grankdir=TD -Gsplines=polyline -Granksep=1.5 -Tsvg > workspace-deps.svg

[script]
bump-actions:
    {{ _just_debuggable_ }}
    pinact run --update

export GITHUB_STEP_SUMMARY := env("GITHUB_STEP_SUMMARY", "")
export GITHUB_OUTPUT := env("GITHUB_OUTPUT", "")

[script]
bump-cargo-deps:
    {{ _just_debuggable_ }}
    declare BASE
    BASE="$(git rev-parse HEAD)"
    declare -r BASE

    # Run "cargo update"
    echo "::notice::Running cargo update"
    cargo update
    if ! git diff --quiet; then
        echo "Found changes after cargo update, creating commit"
        git add Cargo.lock
        git commit -sm "bump!: regular dependency update"
    fi

    # Check updates available with "cargo upgrade",
    # then bump each package individually through separate commits
    echo "::notice::Looking for dependencies to upgrade"
    declare upgrade_output
    upgrade_output="$(mktemp)"
    declare -r upgrade_output
    declare list_packages
    list_packages="$(mktemp)"
    declare -r list_packages
    cargo upgrade --incompatible=allow --dry-run | tee "${upgrade_output}"
    sed "/^====/d; /^name .*old req .*new req/d; s/ .*//" "${upgrade_output}" > "${list_packages}"
    nb_upgrades=$(wc -l < "${list_packages}")

    echo "Found the following ${nb_upgrades} upgrade(s) available:"
    cat "${list_packages}"

    echo "::notice::Upgrading packages that need an upgrade (if any), one by one"
    declare commit_msg
    commit_msg="$(mktemp)"
    declare -r commit_msg
    while read -r package; do
        echo "bump(cargo)!: bump $package (cargo upgrade)" | tee "${commit_msg}"
        tee -a "${commit_msg}" <<<""
        cargo upgrade --incompatible=allow --package "$package" | tee -a "${commit_msg}"
        git add Cargo.lock Cargo.toml cli/Cargo.toml
        git commit -sF "${commit_msg}"
    done < "${list_packages}"

    # If we did not create any commits, we do not need to create a PR message
    if [[ "$(git rev-parse HEAD)" = "${BASE}" ]]; then
        rm -f -- "${upgrade_output}" "${list_packages}" "${commit_msg}"
        exit 0
    fi
    echo "::notice::We created the following commits:"
    git log --reverse -p "${BASE}"..

    # Create Pull Request description
    declare upgrade_log
    upgrade_log="$(mktemp)"
    declare -r upgrade_log
    if [[ "${nb_upgrades}" -ge 1 ]]; then
        {
            echo "### :rocket: Upgrades available";
            echo ""
            echo "| name | old | req | compatible | latest |";
            echo "|------|-----|-----|------------|--------|";
            awk '{print "| " $1 " | " $2 " | " $3 " | " $4 " | " $5 " |"}' < <(sed 1,2d < "${upgrade_output}");
            echo ""
            echo ":warning: This Pull Request was automatically generated and should be carefully reviewed before acceptance. It may introduce **breaking changes**."
            echo ""
        } > "${upgrade_log}"
    fi

    if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -n "${GITHUB_OUTPUT:-}" ] && [ -w "${GITHUB_STEP_SUMMARY}" ] && [ -w "${GITHUB_OUTPUT}" ]; then
        cat "${upgrade_log}" > "${GITHUB_STEP_SUMMARY}"
        {
            echo "upgrade<<EOF";
            cat "${upgrade_log}";
            echo "EOF";
        } >> "${GITHUB_OUTPUT}"
    fi

    rm -f -- "${upgrade_log}" "${upgrade_output}" "${list_packages}" "${commit_msg}"


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
    declare -r new_version="{{ version }}"
    echo "New version: ${new_version}"
    sed -i "s/^version = \".*\"/version = \"${new_version}\"/" Cargo.toml
    cargo update --workspace

# Enter nix-shell
[script]
shell:
   nix-shell \
      --argstr default-features '{{ default_features }}' \
      --argstr features '{{ features }}' \
      --argstr instrumentation '{{ instrument }}' \
      --argstr kernel '{{ kernel }}' \
      --argstr libc '{{ libc }}' \
      --argstr nightly '{{nightly}}' \
      --argstr platform '{{ platform }}' \
      --argstr profile '{{ profile }}' \
      --argstr sanitize '{{ sanitize }}' \
      --argstr tag '{{version}}'

# OCI repo used by the vlab Zot registry
[private]
vlab_oci_repo := "192.168.19.1:30000"

# Start the vlab environment
[script]
vlab-up: (build "containers.vlab")
    {{ _just_debuggable_ }}
    docker load < ./results/containers.vlab
    pushd ./scripts/vlab
    ./run.sh
    popd

# Open a shell or run a command on the vlab control plane
[script]
vlab-control *args:
    {{ _just_debuggable_ }}
    pushd ./scripts/vlab
    ./control.sh {{ args }}
    popd

# Stop the vlab container and remove the docker network
[confirm]
[script]
vlab-down:
    {{ _just_debuggable_ }}
    docker stop vlab || true
    docker rm vlab || true
    docker network rm zot || true

# Stop vlab and remove all associated docker volumes
[confirm]
[script]
vlab-purge: vlab-down
    {{ _just_debuggable_ }}
    docker volume rm vlab || true
    docker volume rm zot || true
    docker volume rm vlab-secrets || true

# Address the vlab control node reaches the telemetry stack on: the gateway of the docker bridge
# the vlab container sits on, i.e. this host. Gateway nodes get there via control-proxy, which
# fabricator wires into the generated Alloy config on its own.
[private]
telemetry_host := "192.168.19.0"

# Start the persisted telemetry stack (Loki, Prometheus, Pyroscope, Grafana)
[script]
telemetry-up: (build "containers.lgtm")
    {{ _just_debuggable_ }}
    docker load < ./results/containers.lgtm
    docker rm -f lgtm 2>/dev/null || true
    docker volume create dataplane-telemetry
    docker run --detach --name lgtm --restart unless-stopped \
        --publish 3000:3000 \
        --publish 3100:3100 \
        --publish 4040:4040 \
        --publish 9099:9090 \
        --mount type=volume,source=dataplane-telemetry,target=/telemetry \
        lgtm:latest
    # Printing 127.0.0.1 is no help from another machine, which is where whoever wants to look at
    # a graph usually is. List every address this host actually answers on.
    echo
    echo "telemetry stack up. reachable at:"
    for addr in $(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' | sed 's/\.$//') \
                $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
        printf '  grafana    http://%s:3000\n' "${addr}"
    done
    printf '  prometheus http://<host>:9099   loki http://<host>:3100   pyroscope http://<host>:4040\n'

# Point the running fabric's Alloy at the telemetry stack
[script]
telemetry-wire:
    {{ _just_debuggable_ }}
    pushd ./scripts/vlab
    ./control.sh kubectl -n fab patch fab/default --type=merge -p '{"spec":{"config":{"observability":{"targets":{"loki":{"lab":{"url":"http://{{ telemetry_host }}:3100/loki/api/v1/push"}},"prometheus":{"lab":{"url":"http://{{ telemetry_host }}:9099/api/v1/write","sendIntervalSeconds":15}},"pyroscope":{"lab":{"url":"http://{{ telemetry_host }}:4040"}}}},"gateway":{"observability":{"dataplane":{"metrics":true,"metricsInterval":15}}},"control":{"observability":{"kubePodLogs":true,"kubeEvents":true}}}}}'
    popd

# Stop the telemetry stack, keeping its data
[script]
telemetry-down:
    {{ _just_debuggable_ }}
    docker rm -f lgtm || true

# Stop the telemetry stack and delete everything it has collected
[confirm]
[script]
telemetry-purge: telemetry-down
    {{ _just_debuggable_ }}
    docker volume rm dataplane-telemetry || true

# Build, push the dataplane image to the vlab registry, and patch the running fabric
[script]
vlab-patch-dataplane:
    {{ _just_debuggable_ }}
    just pyroscope_url="{{ pyroscope_url }}" dataplane_proxy_url="{{ dataplane_proxy_url }}" oci_insecure=true oci_repo="{{ vlab_oci_repo }}" push-container dataplane
    # The fabric ties the validator's tag to the dataplane's (`DataplaneValidatorRef` takes
    # `Versions.Gateway.Dataplane`), so patching one without pushing the other points the
    # fabric at a validator image that does not exist.
    VERSION="{{ version }}" just platform=wasm32-wasip1 oci_insecure=true oci_repo="{{ vlab_oci_repo }}" push-container validator
    # Patching the fabric to a tag the registry does not have takes the dataplane down with
    # ImagePullBackOff, and the resulting silence looks like a dataplane that is running and
    # simply has nothing to say. Confirm both images are actually there before pointing the
    # fabric at them.
    #
    # Built from `vlab_oci_repo` rather than reusing `oci_image_dataplane`, which is derived
    # from the default `oci_repo` (127.0.0.1) -- not the bridge address the push above used.
    #
    # `--raw`, because the validator is an OCI artifact rather than an image: oras pushes it with
    # artifactType `application/vnd.unknown.artifact.v1`, and plain `skopeo inspect` refuses that
    # with "unsupported image-specific operation" no matter that the push just reported success.
    # A guard that says "not in the registry" about something it is looking straight at sends you
    # hunting the push. `--raw` fetches the manifest, which is the whole question here.
    for image in "{{ vlab_oci_repo }}/{{ oci_name }}:{{ version }}" "{{ vlab_oci_repo }}/{{ oci_name }}/validator:{{ version }}"; do
        if ! skopeo inspect --raw --tls-verify=false "docker://${image}" >/dev/null 2>&1; then
            >&2 echo "vlab-patch-dataplane: ${image} is not in the registry; refusing to patch"
            exit 1
        fi
    done
    pushd ./scripts/vlab
    ./control.sh kubectl -n fab patch fab/default --type=merge -p '{"spec":{"overrides":{"versions":{"gateway":{"dataplane":"{{version}}"}}}}}'
    popd

# Build, push the FRR image to the vlab registry, and patch the running fabric
[script]
vlab-patch-frr:
    {{ _just_debuggable_ }}
    just oci_insecure=true oci_repo="{{ vlab_oci_repo }}" push-container frr.dataplane
    pushd ./scripts/vlab
    ./control.sh kubectl -n fab patch fab/default --type=merge -p '{"spec":{"overrides":{"versions":{"gateway":{"frr":"{{version}}"}}}}}'
    popd

# Checkout of github.com/githedgehog/fabric, which is where the gateway DaemonSets are built.
#
# Not the `gateway` repo, which carries a copy of `pkg/ctrl/gateway_ctrl.go` that no longer runs:
# fabricator wires `DataplaneRef` into `fabric/api/meta`'s FabricConfig and never reads
# `Versions.Gateway.Controller`, so it is the fabric controller that reconciles the dataplane pod.
[private]
fabric_repo := env("FABRIC_REPO", "")

# Build, push the fabric controller to the vlab registry, and patch the running fabric
[script]
vlab-patch-fabric:
    {{ _just_debuggable_ }}
    # This is how a change to the way the dataplane is *launched* -- its command, its arguments,
    # the volumes and namespaces it gets -- reaches vlab. `vlab-patch-dataplane` replaces the
    # image; this replaces the controller that decides what to run out of it.
    repo="{{ fabric_repo }}"
    if [ -z "${repo}" ]; then
        >&2 echo "vlab-patch-fabric: set FABRIC_REPO to a checkout of github.com/githedgehog/fabric"
        exit 1
    fi
    if [ ! -d "${repo}/pkg/ctrl" ]; then
        >&2 echo "vlab-patch-fabric: ${repo} does not look like the fabric repository"
        exit 1
    fi
    # Fabric builds with the system Go, which this dev shell deliberately does not carry -- it is
    # not a dataplane dependency and does not belong in the shipped shell. Borrow one from the
    # ambient nixpkgs rather than failing: fabric's own toolchain is unpinned anyway (it `go
    # install`s kustomize, helm, helmify and skopeo at fixed versions into its `bin/`), so the
    # compiler is the one thing here nobody has an opinion about.
    declare -a with_go=(bash -c)
    if ! command -v go >/dev/null 2>&1; then
        if ! command -v nix-shell >/dev/null 2>&1; then
            >&2 echo "vlab-patch-fabric: no go and no nix-shell on PATH; fabric needs a Go toolchain"
            exit 1
        fi
        echo "vlab-patch-fabric: no go on PATH, borrowing one from nixpkgs"
        with_go=(nix-shell -p go --run)
    fi
    # Pinned once and passed to every invocation. Fabric derives its own version from
    # `git describe` plus, on a dirty tree, two random characters -- so two `just` runs in that
    # repo disagree about what they are building, and the image would land under a tag the chart
    # does not name. The timestamp is what makes each push a new tag, which is what makes the
    # controller pod actually roll.
    fabric_version="$(git -C "${repo}" describe --tags --dirty --always)-dp$(date -u +%H%M%S)"
    echo "vlab-patch-fabric: building fabric ${fabric_version}"
    # Only the controller: `Versions.Fabric.Controller` names both the `fabric` image and the
    # `fabric` chart, and nothing else. Leaving api/agent/boot/dhcpd alone avoids reloading the
    # agent on every switch in the lab for a change that does not touch them.
    # `oci=http` and an override, because fabric's two settings for it disagree. That one knob
    # gives skopeo `--dest-tls-verify=false` -- HTTPS, unverified -- and helm `--plain-http`,
    # cleartext. The vlab zot is TLS with a self-signed certificate, so skopeo is right and helm
    # talks cleartext at a TLS listener: `curl http://.../v2/` answers 400 where `curl -k
    # https://` answers 200, and helm reports that 400 as an unexpected status from a blob HEAD
    # with no hint that the scheme is what is wrong. Nothing reaches zot, so its log is silent.
    for recipe in "_docker-build fabric" "_helm-fabric" "_docker-push fabric" "_helm-push fabric"; do
        # Both forms of `with_go` take the command as one string, so it stays quoted here: the
        # nix-shell branch is `--run <string>` and would otherwise swallow only the first word.
        (cd "${repo}" && "${with_go[@]}" "just version=${fabric_version} oci=http helm_insecure_push=--insecure-skip-tls-verify oci_repo={{ vlab_oci_repo }} ${recipe}")
    done
    # Same reasoning as vlab-patch-dataplane: pointing the fabric at a tag the registry does not
    # have takes the controller down with ImagePullBackOff, and a controller that is not running
    # looks exactly like a controller with nothing to do.
    #
    # Both artifacts, because `Versions.Fabric.Controller` names both and either one missing is
    # equally fatal. Checking only the image is how a chart push that failed on its own gets
    # mistaken for a successful patch.
    #
    # `--raw`, because a helm chart is an OCI artifact and not an image: plain `skopeo inspect`
    # refuses it with "unsupported image-specific operation on artifact with type
    # application/vnd.cncf.helm.config.v1+json" even when the chart is sitting right there.
    # `--raw` just fetches the manifest, which is all this needs and works for both.
    for artifact in "fabric" "charts/fabric"; do
        if ! skopeo inspect --raw --tls-verify=false "docker://{{ vlab_oci_repo }}/githedgehog/fabric/${artifact}:${fabric_version}" >/dev/null 2>&1; then
            >&2 echo "vlab-patch-fabric: ${artifact}:${fabric_version} is not in the registry; refusing to patch"
            exit 1
        fi
    done
    pushd ./scripts/vlab
    ./control.sh kubectl -n fab patch fab/default --type=merge -p "{\"spec\":{\"overrides\":{\"versions\":{\"fabric\":{\"controller\":\"${fabric_version}\"}}}}}"
    popd
