# GitHub Workflows

This document provides an overview of the CI/CD workflows used in this
repository. These workflows help maintain code quality, automate dependency
management, and validate changes before they are merged.

## Table of Contents

- [Main Development Workflow](#main-development-workflow-devyml)
- [Linting and Validation Workflows](#linting-and-validation-workflows)
- [Dependency Management](#dependency-management)
- [License and Security Scanning](#license-and-security-scanning)
- [Merge Control](#merge-control)

---

## Main Development Workflow (`dev.yml`)

### Purpose

Primary CI workflow that ensures developer experience is good by building and
testing the codebase in a vanilla Ubuntu environment using standard tooling.

The workflow runs several jobs. Some of them only run if users opt in, such as
the VLAB/HLAB tests. See the lists of dispatch options and Pull Requests labels
below for details.

### Triggers

- Pull Requests
- Pushes to `main` branch
- Merge group checks
- Manual dispatch (workflow\_dispatch)

### Main steps

1. Check code changes to determine which tests are required
2. Build and test across multiple profiles and environments:
   - Profiles: `debug`, `release`, `fuzz`
   - Build modes: sterile (clean environment) and developer (local-like
     environment)
3. Run cargo deny checks for license and security issues
4. Push container images (for sterile release/debug builds)
5. Execute tests:
   - Regular tests using `cargo nextest`
   - Shuttle tests (concurrent execution testing)
   - Fuzz tests with coverage
6. Run `cargo clippy` for linting
7. Generate documentation with `rustdoc`
8. Upload test results and coverage to Codecov
9. Publish test reports with flaky test detection
10. Run VLAB/HLAB integration tests (virtual/hybrid lab environments)

### Manual dispatch options

- `debug_enabled` - Enable tmate session for debugging on failure
- `debug_justfile` - Show debug statements from just recipes
- `run_vlab_tests` - Run VLAB (virtual lab) tests
- `run_hlab_tests` - Run HLAB (hybrid lab) tests
- `enable_release_tests` - Enable release tests for VLAB/HLAB

### Pull Request label options

- `ci:+vlab` - Run VLAB tests on this PR
- `ci:+hlab` - Run HLAB tests on this PR
- `ci:+release` - Enable release tests for VLAB/HLAB on this PR

### Job matrix

- Profiles: debug, release, fuzz
- Build modes: sterile and developer environments
- VLAB configurations: spine-leaf fabric mode, with/without gateway,
  L2VNI/L3VNI VPC modes

### Artifacts

- Test results (JUnit XML)
- Coverage reports (Codecov JSON)
- Container images pushed to GitHub Container Registry

---

## Linting and Validation Workflows for Pull Requests

### Rust Code Formatting (`lint-cargo-fmt.yml`)

Ensure Rust code is consistently formatted using `rustfmt`.

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

#### Triggers

- Weekly schedule: Mondays at 3:18 AM UTC
- Manual dispatch (workflow\_dispatch)

#### Manual dispatch options

- `debug_enabled` - Enable tmate session for debugging on failure

#### Main steps

1. Install required tools (`just`, `cargo-edit`, `cargo-deny`)
2. Set up build environment
3. Run `cargo deny check` (pre-upgrade, continue on error)
4. Run `cargo update` to update within version constraints
5. Run `cargo upgrade` to find and apply upgrades (including incompatible versions)
6. Create individual commits for each package upgrade
7. Run `cargo deny check` again (post-upgrade, must pass)
8. Create a Pull Request with all upgrade commits

---

## License and Security Scanning

### FOSSA Scan (`fossa.yml`)

Perform license compliance and security vulnerability scanning using FOSSA.
Reports are available on the [FOSSA Dashboard].

[FOSSA Dashboard]: https://app.fossa.com/projects/custom%252B43661%252Fgithub.com%252Fgithedgehog%252Fdataplane/

---

## Merge Control

### Mergeability Check (`mergeability.yml`)

Block Pull Request merges based if the `dont-merge` label is set.

Runs and checks for the presence of the label on various Pull Request events:
`synchronize`, `opened`, `reopened`, `labeled`, `unlabeled`.
