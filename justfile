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

# Nix build cores per derivation; `jobs * cores` is the total budget. Zero
# means every available core. Recipes pass `_cores`, which applies `share`.
cores := "0"

# Fraction of `cores` available to this invocation, as a decimal or fraction.
share := "1"

# Resolve zero before scaling and never return less than one. The epsilon
# prevents floating-point results just below an integer from rounding down.
[private]
_cores := if share == "1" { cores } else { shell('''
    cores="$1"
    if [ "${cores}" = "0" ]; then cores="$(nproc)"; fi
    awk -v cores="${cores}" -v share="$2" '
      BEGIN {
        count = split(share, part, "/")
        number = "^[0-9]+([.][0-9]+)?$"
        if (count == 1 && share ~ number) {
          factor = share
        } else if (count == 2 && part[1] ~ number && part[2] ~ number && part[2] != 0) {
          factor = part[1] / part[2]
        } else {
          print "invalid share: " share > "/dev/stderr"
          exit 1
        }
        if (factor <= 0) {
          print "share must be positive" > "/dev/stderr"
          exit 1
        }
        result = int(cores * factor + 1e-9)
        print (result < 1 ? 1 : result)
      }
    '
  ''', cores, share) }

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
oci_image_dataplane_core_viewer := oci_repo + "/" + oci_name + "/core-viewer:" + version
oci_image_dataplane_dev_debugger := oci_repo + "/" + oci_name + "/dev-debugger:" + version
oci_image_dataplane_syscall_tracer := oci_repo + "/" + oci_name + "/syscall-tracer:" + version
oci_image_dataplane_validator := oci_repo + "/" + oci_name + "/validator:" + version
oci_image_frr_dataplane := oci_repo + "/" + oci_frr_prefix + ":" + version
oci_image_frr_host := oci_repo + "/" + oci_frr_prefix + "-host:" + version

[private]
_skopeo_dest_insecure := if oci_insecure == "true" { "--dest-tls-verify=false" } else { "" }

[private]
nightly := "false"

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
      --argstr nightly '{{nightly}}' \
      --print-build-logs \
      --show-trace \
      --out-link "results/${target}" \
      --max-jobs "{{jobs}}" \
      --cores "{{ _cores }}" \
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
test package="tests.all" *args: (build (if package == "tests.all" { "tests.all" } else { "tests.pkg." + package }) args)
    {{ _just_debuggable_ }}
    declare -r target="{{ if package == "tests.all" { "tests.all" } else { "tests.pkg." + package } }}"
    cargo nextest run --archive-file results/${target}/*.tar.zst --workspace-remap $(pwd) {{ filter }}

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
    cargo bolero test '{{ target }}' --rustc-bootstrap -T '{{ time }}' \
        {{ if sanitize != "" { "--sanitizer " + sanitize } else { "" } }} \
        {{ if sanitize == "thread" { "--build-std" } else { "" } }} \
        {{ _cargo_feature_flags }} {{ args }}

# Build and run the criterion benches. The rte_acl benches are gated behind the
# `dpdk` feature, so run `just features=dpdk bench` to exercise them; a plain
# `just bench` builds them as empty `main()` and only runs the reference benches.
[script]
bench: (build "benches")
    {{ _just_debuggable_ }}
    shopt -s nullglob
    for bench in ./results/benches/bin/*; do "$bench" --bench; done

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
test-each *args: (build "tests.pkg" args)
    {{ _just_debuggable_ }}
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

# Create devroot and sysroot symlinks for local development
[script]
setup-roots *args:
    {{ _just_debuggable_ }}
    for root in devroot sysroot; do
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

# Check that the debug images actually do what the README says they do.
#
# Building an image proves it links; it does not prove the entrypoint runs.
# Both of these shipped broken: the tracer's documented `docker run` produced a
# well-formed JSON trace of its own child failing to start, and still exited 0.
[script]
smoke-container target: (build-container target)
    {{ _just_debuggable_ }}
    declare -xr DOCKER_HOST="${DOCKER_HOST:-unix://{{ docker_sock }}}"
    case "{{ target }}" in
        "dataplane-syscall-tracer")
            # A trace runs to megabytes, so keep it in a file: a shell variable
            # that size overruns the here-string limit and every grep against
            # it fails with E2BIG, which reads exactly like a failed trace.
            declare trace
            trace="$(mktemp)"
            declare -r trace
            trap 'rm -f -- "${trace}"' EXIT
            # No seccomp relaxation on purpose: this is the documented command.
            timeout 60 docker run --rm "{{ oci_image_dataplane_syscall_tracer }}" \
                >"${trace}" 2>&1 || true
            if grep -q "Unable to set ADDR_NO_RANDOMIZE" "${trace}"; then
                >&2 echo "::error::lurk could not disable ASLR, so the tracee never ran"
                exit 1
            fi
            # The tracee has to actually execute, not merely be attached to.
            if ! grep -q '"syscall":"execve"' "${trace}"; then
                >&2 echo "::error::no execve in the trace: the traced program never started"
                >&2 head -20 "${trace}"
                exit 1
            fi
            printf 'syscall-tracer: traced %s syscalls\n' "$(grep -c '"type":"SYSCALL"' "${trace}")"
            ;;
        "dataplane-dev-debugger")
            declare cid
            cid="$(docker run -d --rm -p 47110:4711 "{{ oci_image_dataplane_dev_debugger }}")"
            declare -r cid
            trap 'docker kill "${cid}" >/dev/null 2>&1 || true' EXIT
            ./scripts/dap-smoke.py 47110 /bin/dataplane
            ;;
        "dataplane-core-viewer")
            # The Rust pretty-printers are the reason this image exists, and
            # what registers them is the entrypoint's own `--directory` and
            # `source` flags -- so drive the real entrypoint rather than
            # invoking gdb directly, which would only test a copy of them.
            declare out
            out="$(printf 'info pretty-printer\nquit\n' \
                | timeout 120 docker run --rm -i "{{ oci_image_dataplane_core_viewer }}" 2>&1)"
            if grep -qiE "traceback|no module named" <<<"${out}"; then
                >&2 echo "::error::gdb could not load the rust pretty-printers"
                >&2 printf '%s\n' "${out}"
                exit 1
            fi
            # A registered printer set, not merely a clean start.
            for want in StdString StdVec StdHashMap; do
                if ! grep -q "${want}" <<<"${out}"; then
                    >&2 echo "::error::rust pretty-printer ${want} is not registered"
                    exit 1
                fi
            done
            echo "core-viewer: rust pretty-printers registered"
            ;;
        *)
            >&2 echo "::error::no smoke test defined for {{ target }}"
            exit 1
            ;;
    esac

# Build the dataplane container image
[script]
build-container target="dataplane" *args: (build (if target == "dataplane" { "dataplane.tar" } else if target == "validator" { "workspace.validator" } else { "containers." + target }) args)
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
            img="$(docker import --platform "${docker_platform}" --change 'ENTRYPOINT ["/bin/dataplane"]' ./results/dataplane.tar)"
            declare -r img
            docker tag "${img}" "{{oci_image_dataplane}}"
            echo "imported {{ oci_image_dataplane }} (${docker_platform})"
            ;;
        "dataplane-core-viewer")
            docker load < ./results/containers.dataplane-core-viewer
            docker tag "ghcr.io/githedgehog/dataplane/core-viewer:{{version}}" "{{oci_image_dataplane_core_viewer}}"
            echo "imported {{ oci_image_dataplane_core_viewer }}"
            ;;
        "dataplane-dev-debugger")
            docker load < ./results/containers.dataplane-dev-debugger
            docker tag "ghcr.io/githedgehog/dataplane/dev-debugger:{{version}}" "{{oci_image_dataplane_dev_debugger}}"
            echo "imported {{ oci_image_dataplane_dev_debugger }}"
            ;;
        "dataplane-syscall-tracer")
            docker load < ./results/containers.dataplane-syscall-tracer
            docker tag "ghcr.io/githedgehog/dataplane/syscall-tracer:{{version}}" "{{oci_image_dataplane_syscall_tracer}}"
            echo "imported {{ oci_image_dataplane_syscall_tracer }}"
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
    case "{{target}}" in
        "dataplane")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} "docker-daemon:{{ oci_image_dataplane }}" "docker://{{ oci_image_dataplane }}"
            echo "Pushed {{ oci_image_dataplane }}"
            ;;
        "dataplane-core-viewer")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} "docker-daemon:{{ oci_image_dataplane_core_viewer }}" "docker://{{ oci_image_dataplane_core_viewer }}"
            echo "Pushed {{ oci_image_dataplane_core_viewer }}"
            ;;
        "dataplane-dev-debugger")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} "docker-daemon:{{ oci_image_dataplane_dev_debugger }}" "docker://{{ oci_image_dataplane_dev_debugger }}"
            echo "Pushed {{ oci_image_dataplane_dev_debugger }}"
            ;;
        "dataplane-syscall-tracer")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} "docker-daemon:{{ oci_image_dataplane_syscall_tracer }}" "docker://{{ oci_image_dataplane_syscall_tracer }}"
            echo "Pushed {{ oci_image_dataplane_syscall_tracer }}"
            ;;
        "debug-tools")
            >&2 echo "do not push the debug tools!"
            exit 1
            ;;
        "frr.dataplane")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} "docker-daemon:{{oci_image_frr_dataplane}}" "docker://{{oci_image_frr_dataplane}}"
            echo "Pushed {{ oci_image_frr_dataplane }}"
            ;;
        "frr.host")
            skopeo copy --src-daemon-host="${DOCKER_HOST}" {{ _skopeo_dest_insecure }} "docker-daemon:{{oci_image_frr_host}}" "docker://{{oci_image_frr_host}}"
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
            >&2 echo "{{target}} is not a valid container"
            exit 99
    esac

[script]
push:
    {{ _just_debuggable_ }}
    # Debug images must match the release they inspect.
    for container in \
        dataplane \
        dataplane-core-viewer \
        dataplane-dev-debugger \
        dataplane-syscall-tracer \
        frr.dataplane \
        validator; do
        if [ "${container}" = "validator" ]; then
          platform="wasm32-wasip1"
        else
          platform="x86-64-v3"
        fi
        just jobs="{{jobs}}" cores="{{ _cores }}" debug_justfile="{{debug_justfile}}" oci_repo="{{oci_repo}}" version="{{version}}" profile=release platform="${platform}" sanitize= instrument=none push-container "${container}"
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

[script]
clippy *args:
    {{ _just_debuggable_ }}
    cargo clippy --all-targets {{ _cargo_feature_flags }} {{ _cargo_profile_flag }} {{ args }} -- -D warnings

[script]
actionlint:
    {{ _just_debuggable_ }}
    actionlint

# Lint markdown against .markdownlint.json. Pass `--fix` to repair what is mechanical.
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
    (license-headers)
    {{ _just_debuggable_ }}

# Run doctests
[script]
doctest *args:
    {{ _just_debuggable_ }}
    cargo test --doc {{ _cargo_feature_flags }} {{ _cargo_profile_flag }} {{ args }}

# Run instrumented tests and report coverage. Args are forwarded to nextest; for example,
# `just coverage -p dataplane-nat` scopes the run to this crate.
[script]
coverage *args:
    {{ _just_debuggable_ }}
    export LLVM_COV="$(pwd)/devroot/bin/llvm-cov"
    export LLVM_PROFDATA="$(pwd)/devroot/bin/llvm-profdata"
    declare -r out="./target/nextest/coverage"
    cargo llvm-cov clean --workspace
    cargo llvm-cov --no-report --branch nextest {{ args }}
    mkdir -p "${out}"
    cargo llvm-cov report --branch --html --output-dir="${out}"
    cargo llvm-cov report --branch --codecov --output-path="${out}/codecov.json"
    cargo llvm-cov report --branch --summary-only

# Report coverage from a Nix-built nextest archive. The optional package
# matches `just test`; remaining arguments are forwarded to nextest.
[script]
coverage-archive package="tests.all" *args:
    {{ _just_debuggable_ }}
    declare -r target="{{ if package == "tests.all" { "tests.all" } else { "tests.pkg." + package } }}"
    just \
        jobs="{{jobs}}" \
        cores="{{ _cores }}" \
        debug_justfile="{{debug_justfile}}" \
        profile="{{profile}}" \
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

    # Nextest changes cwd; `%m` also pools compatible profiles across tests.
    export LLVM_PROFILE_FILE="${profraw}/cov-%m.profraw"

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

    llvm-cov export \
        --format=lcov \
        --instr-profile="${out}/coverage.profdata" \
        "${objects[@]}" \
        "${src_prefix}" \
        | sed -e "s#^SF:${src_prefix}/#SF:#" > "${out}/lcov.info"

    # Codecov needs repository-relative paths; reject failed rewrites.
    if grep -q '^SF:/' "${out}/lcov.info"; then
        >&2 echo "::error::absolute paths survived the ${src_prefix} rewrite:"
        >&2 grep -m5 '^SF:/' "${out}/lcov.info"
        exit 1
    fi

    llvm-cov show \
        --format=html \
        --output-dir="${out}/html" \
        --show-branches=count \
        --instr-profile="${out}/coverage.profdata" \
        "${objects[@]}" \
        "${src_prefix}"

    llvm-cov report \
        --instr-profile="${out}/coverage.profdata" \
        "${objects[@]}" \
        "${src_prefix}"

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
