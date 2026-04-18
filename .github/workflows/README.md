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

1. Check code changes to determine which tests are required
2. Build and test across a matrix of nix targets and profiles:
   - Nix targets: `tests.all`, `frr.dataplane`, `dataplane`
   - Profiles: `debug`, `release`
3. Run `cargo deny` checks for license and security issues
4. Execute tests:
   - Regular tests using `cargo nextest` (via `just test`)
   - Shuttle tests (concurrent execution testing with `features=shuttle`)
5. Run `cargo clippy` for linting (via `just lint`)
6. Build documentation with `rustdoc` (via `just docs`)
7. Run doctests (via `just doctest`)
8. Push container images to GHCR (for non-test targets)
9. Run VLAB/HLAB integration tests (virtual/hybrid lab environments)
10. Publish release artifacts and bump fabricator on tag pushes

### Manual dispatch options

- `debug_enabled` - Enable tmate session for debugging on failure
- `debug_justfile` - Show debug statements from just recipes
- `skip_vlab_tests` - Skip VLAB (virtual lab) tests
- `run_hlab_tests` - Run HLAB (hybrid lab) tests
- `enable_release_tests` - Enable release tests for VLAB/HLAB

### Pull Request label options

- `ci:+vlab` - Run VLAB tests on this PR
- `ci:+hlab` - Run HLAB tests on this PR
- `ci:+release` - Enable release tests for VLAB/HLAB on this PR
- `ci:-upgrade` - Disable upgrade tests on this PR

### Job matrix

- Nix targets: `tests.all` (runs tests, lints, docs), `frr.dataplane`
  and `dataplane` (build and push containers)
- Profiles: `debug`, `release`
- VLAB configurations: spine-leaf fabric mode, L2VNI/L3VNI VPC modes,
  with gateway enabled

### Artifacts

- Container images pushed to GitHub Container Registry (GHCR)
- Release containers published on tag pushes via `just push`

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
