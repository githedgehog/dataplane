#!/usr/bin/env bash

set -euxo pipefail

# This script must be run from within a nix shell

# Step 1: check npins

npins verify

# Step 2: build sys and devroot

nix --extra-experimental-features nix-command build -f default.nix devroot --out-link devroot --max-jobs 4
nix --extra-experimental-features nix-command build -f default.nix sysroot --out-link sysroot --max-jobs 4

# Step 3: build test env (min-tar)

mkdir -p results
nix --extra-experimental-features nix-command build -f default.nix min-tar --out-link results/min.tar
# docker import results/min.tar min:release

# Step 4: build dataplane image
nix --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link results/dataplane.tar
# docker import results/dataplane.tar dataplane:debug

# Step 5: cargo build

cargo build

# Step 6: cargo nextest run

cargo nextest run

# Step 7: cargo test run

cargo test

# Step 7: build and run test archive

nix --extra-experimental-features nix-command build -f default.nix tests.all --out-link results/tests.all
cargo nextest run --archive-file results/tests.all/*.tar.zst --workspace-remap "$(pwd)" || true

# Step 8: build individual tests archives

nix --extra-experimental-features nix-command build -f default.nix tests.pkg --out-link results/tests.pkg --max-jobs 4
for pkg in results/tests.pkg/*/*.tar.zst; do
  # (one test is xfail)
  cargo nextest run --archive-file "${pkg}" --workspace-remap "$(pwd)" || true
done
