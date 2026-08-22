# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set unstable := true
set shell := ["/usr/bin/env", "bash", "-euo", "pipefail", "-c"]
set script-interpreter := ["/usr/bin/env", "bash", "-euo", "pipefail"]

mod bench
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

# sanitizer to use (address/thread/safe-stack/cfi/"")
sanitize := ""

# Wall-clock budget bolero gets per property under coverage instrumentation, in milliseconds.
# Overridable so a slower machine can buy more without editing this file.
bolero_coverage_test_time_ms := env("BOLERO_COVERAGE_TEST_TIME_MS", "15000")

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
oci_image_dataplane_debugger := oci_repo + "/" + oci_name + "/debugger:" + version
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
                oras push --annotation version="{{ version }}" "{{ oci_image_dataplane_validator }}" ./validator.wasm
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
coverage *args:
    {{ _just_debuggable_ }}
    # Bolero draws cases against a wall-clock budget, and coverage instrumentation makes each
    # case far more expensive: an instrumented run drew one or two cases where a clean one draws
    # hundreds, which is under the floor the fuzz properties' own vacuity guards enforce.  Buy
    # back a comparable number of draws rather than lowering those guards -- a guard that has
    # been lowered to fit the slowest configuration no longer catches a property that has
    # genuinely stopped reaching its assertion.
    export BOLERO_RANDOM_TEST_TIME_MS="{{ bolero_coverage_test_time_ms }}"
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

# Report specification compliance. See development/code/spec-compliance.md
[script]
duvet *args:
    {{ _just_debuggable_ }}
    duvet report {{ args }}

# Fail if the compliance snapshot is out of date
[script]
duvet-check:
    {{ _just_debuggable_ }}
    # `duvet report` takes milliseconds and is bit-for-bit deterministic, so unlike mutation
    # testing this can be a gate, and it is the cheapest correctness check in the repo. It is
    # one because the snapshot had already drifted two commits after being introduced: a
    # regenerate-by-hand rule is one nobody runs.
    #
    # The inputs are checked first because their absence is the one way this gate passes while
    # measuring nothing: `duvet report` succeeds over zero specifications, and `git diff` over a
    # file that does not exist is empty, so a tree with no `.duvet` reports compliance rather than
    # the truth. A gate that cannot tell "nothing has drifted" from "there is nothing here" is
    # worse than no gate, because it is believed.
    for input in .duvet/config.toml .duvet/snapshot.txt; do
      if [ ! -f "${input}" ]; then
        echo "error: ${input} is missing; this check has nothing to compare and cannot pass" >&2
        exit 1
      fi
    done
    duvet report
    if ! git diff --quiet -- .duvet/snapshot.txt; then
      echo "error: .duvet/snapshot.txt is stale; run \`just duvet\` and commit the result" >&2
      git --no-pager diff -- .duvet/snapshot.txt >&2
      exit 1
    fi

# Mutation-test a crate or a diff. See development/code/mutation-testing.md
[script]
mutants *args:
    {{ _just_debuggable_ }}
    # Deliberately not a gate, and deliberately not the whole workspace by default: a full
    # sweep is hours, and the product is the list of survivors rather than the score. Scope
    # it, as in `just mutants -p dataplane-nat` or `just mutants --in-diff <(git diff main)`.
    cargo mutants --test-tool nextest {{ args }}

# Check that each `type=test` citation tests its `type=implementation` citation
[script]
spec-interlock *args:
    {{ _just_debuggable_ }}
    # The cross-check duvet cannot do alone: mutate only the cited implementation region, run
    # only the cited tests, and report a citation whose test notices nothing as decorative.
    # See development/code/spec-compliance.md.
    ./scripts/spec-interlock.ts {{ args }}

# Render the compliance tables as markdown, for a job summary
[script]
duvet-summary *args:
    {{ _just_debuggable_ }}
    # Replaces the HTML report, whose viewer we do not build (see nix/pkgs/duvet). Pass
    # `--results <path>`, as written by `just spec-interlock --results <path>`, to carry the
    # interlock's verdicts; without it the summary says the interlock has not run rather than
    # implying the citations are checked.
    #
    # Appended to the job summary when there is one, and printed either way. The redirection
    # lives here rather than in the workflow because `.github/actions/just` passes recipe
    # arguments to `just` without a shell to interpret them, so a `>>` in the workflow would
    # arrive as a filename.
    ./scripts/duvet-summary.ts {{ args }} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

# Use Nix-built archives so local and CI coverage report the same binaries.
[script]
coverage-archive package="tests.all" *args:
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
