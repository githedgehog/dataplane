# GitHub Workflows

This document provides an overview of the CI/CD workflows used in this
repository. These workflows help maintain code quality, automate dependency
management, and validate changes before they are merged.

## Table of Contents

- [Main Development Workflow](#main-development-workflow-devyml)
- [Linting and Validation Workflows](#linting-and-validation-workflows-for-pull-requests)
- [Dependency Management](#dependency-management)
- [Version Management](#version-management)
- [License and Security Scanning](#license-and-security-scanning)
- [Merge Control](#merge-control)

---

## Main Development Workflow (`dev.yml`)

### Purpose

Primary CI workflow that builds and tests the codebase using the nix-based
build system. All build steps run inside `nix-shell` to ensure a reproducible
toolchain matching what developers use locally.

Production artifacts are produced via nix builds in a separate CI workflow.

### Triggers

- Pull Requests
- Pushes to `main` branch
- Tag pushes (`v*`)
- Merge group checks
- Manual dispatch (workflow_dispatch)

### Main steps

1. Plan jobs from the event and `ci:+` labels
2. Run lint, debug checks, and debug coverage on pull requests
3. Run expensive profiles and specialized jobs on labeled or deep runs
4. Build and push containers required by VLAB/HLAB
5. Aggregate required results in the `Summary` job
6. Publish release artifacts and bump fabricator on tag pushes

### Manual dispatch options

- `debug_enabled` - Enable tmate session for debugging on failure
- `debug_justfile` - Show debug statements from just recipes
- `skip_vlab_tests` - Skip VLAB (virtual lab) tests
- `run_hlab_tests` - Run HLAB (hybrid lab) tests
- `enable_release_tests` - Enable release tests for VLAB/HLAB

### Pull Request label options

- `ci:+merge-ready` - Run everything the merge queue will run, so a failure
  is found before queueing; HLAB remains excluded, because the merge queue does
  not run it either.  It tests this branch's head while the queue tests the
  result of merging it, so a green run here can still fail in the queue if
  `main` moved underneath it
- `ci:+test/all-profiles` - Add release and fuzz checks plus fuzz coverage
- `ci:+sanitize` - Run address and thread sanitizer tests
- `ci:+test-each` - Test each workspace package independently
- `ci:+miri` - Run Miri checks
- `ci:+wasm` - Run the WASM build check
- `ci:+concurrency` - Run Shuttle and Loom tests
- `ci:+cross` - Build all cross-platform containers
- `ci:+cross/full` - Also run the workspace test suite under qemu-user, on the
  two aarch64 musl legs. Gated like every other job, so the merge queue and
  `ci:+merge-ready` include it
- `ci:+vlab` - Run VLAB tests on this PR
- `ci:+hlab` - Run HLAB tests on this PR
- `ci:+release` - Enable release tests for VLAB/HLAB on this PR
- `ci:-upgrade` - Disable upgrade tests on this PR. `ci:+merge-ready`
  overrides it, because the merge queue has no labels to read and would
  run the upgrade legs anyway; a `merge-ready` run that skipped them would
  not be the preview it claims to be

Labels are additive, and optional: a pull request needs none of them.
`ci:-upgrade` is the sole exception, subtracting a job that would otherwise run.

Adding a label starts a **new** workflow run, and that run repeats the default
jobs as well as the ones the label enabled.  This applies to _every_ label, not
only the `ci:` ones: the trigger cannot filter by name and the run in flight is
cancelled, so adding `bug` or `documentation` mid-run discards whatever it had
finished.  Label first, or wait for the run to end.
GitHub cannot add a job to a run that already exists, so this is unavoidable
without teaching jobs to skip work an earlier run finished for the same commit.
Set the labels you expect to need when opening the pull request and the repeat
does not arise.

Not labelling is also a reasonable choice.
The gated jobs are the ones judged unlikely to fail, and the merge queue runs
the full suite regardless, so a bad assumption costs a re-queue rather than a
bad merge.
When the merge queue does catch one of these, add the matching label and push
the fix, which keeps the check on the pull request from then on.
If those queue failures stop being rare, the phasing is worth revisiting.

### Job matrix

- Checks: `debug` by default; `release` and `fuzz` on deep runs
- Coverage: `debug` by default; `fuzz` on deep runs
- Miri: required on deep runs; opt-in on pull requests with `ci:+miri`
- Containers: debug/release for dataplane and FRR; release for validator
- VLAB configurations: spine-leaf fabric mode, L2VNI/L3VNI VPC modes,
  with gateway enabled

### Artifacts

- Container images pushed to GitHub Container Registry (GHCR)
- Release containers published on tag pushes via `just push`
- Coverage reports from each `coverage/<profile>` job, kept for 7 days:
  - `coverage-html-<profile>.tar.gz` - `llvm-cov` HTML report, including the
    per-branch counts that Codecov does not render. Unpack and open
    `html/index.html`
  - `lcov-<profile>.info` - LCOV report with repository-relative paths, for
    feeding to other coverage tooling

  Both upload unarchived, so they download as the named file rather than
  wrapped in a zip.

---

## Linting and Validation Workflows for Pull Requests

### Rust Code Formatting (`lint-cargo-fmt.yml`)

Ensure Rust code is consistently formatted using `rustfmt`. Runs inside
`nix-shell` to use the same toolchain version that developers use locally.

### License Headers Check (`lint-license-headers.yml`)

Verify that all source files have SPDX license headers and copyright notices.

### Commit Message Validation (`lint-commitlint.yml`)

Ensure commit messages follow the [Conventional Commits] specification.

[Conventional Commits]: https://www.conventionalcommits.org/

Accepted commit title prefixes:

- `build`, `bump`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`,
  `revert`, `style`, `test`

### Dependabot Configuration Validation (`lint-validate-dependabot.yml`)

Validate the Dependabot configuration file for correctness.

Triggers for Pull Requests that modify `.github/dependabot.yml` or the
associated workflow file.

---

## Dependency Management

### Automated Dependency Updates (`bump.yml`)

#### Purpose

Automatically check for and update Cargo dependencies, creating a Pull Request
with the changes. Each package is upgraded in a separate commit to ease review.
Runs inside `nix-shell` for access to the nix-managed toolchain.

#### Triggers

- Weekly schedule: Mondays at 3:18 AM UTC
- Manual dispatch (workflow_dispatch)

#### Manual dispatch options

- `debug_enabled` - Enable tmate session for debugging on failure

#### Main steps

1. Set up nix environment with cachix binary cache
2. Run `cargo deny check` (pre-upgrade, continue on error)
3. Run `cargo update` to update within version constraints
4. Run `cargo upgrade` to find and apply upgrades (including incompatible
   versions)
5. Create individual commits for each package upgrade
6. Run `cargo deny check` again (post-upgrade, must pass)
7. Create a Pull Request with all upgrade commits

---

## Version Management

### Version Bump (`version-bump.yml`)

#### Purpose

Bump the dataplane version in `Cargo.toml` and create a Pull Request with the
change. Runs inside `nix-shell` for access to the nix-managed toolchain.

#### Triggers

- Manual dispatch only (workflow_dispatch)

#### Manual dispatch options

- `new_version` - Explicit version string (e.g. `0.15.0`). If not provided,
  the minor version is bumped automatically.

---

## License and Security Scanning

### FOSSA Scan (`fossa.yml`)

Perform license compliance and security vulnerability scanning using FOSSA.
Reports are available on the [FOSSA Dashboard].

[FOSSA Dashboard]: https://app.fossa.com/projects/custom%252B43661%252Fgithub.com%252Fgithedgehog%252Fdataplane/

---

## Merge Control

### Mergeability Check (`mergeability.yml`)

Block Pull Request merges if the `dont-merge` label is set.

Runs and checks for the presence of the label on various Pull Request events:
`synchronize`, `opened`, `reopened`, `labeled`, `unlabeled`.
