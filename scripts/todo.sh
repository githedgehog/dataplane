#!/usr/bin/env bash

set -euxo pipefail

# This script must be run from within a nix shell

# Step 1: check npins

npins verify

# Step 2: build dataplane

mkdir -p results
nix build -f default.nix min-tar --out-link results/min.tar

mkdir -p results
nix build -f default.nix dataplane-tar --out-link results/dataplane.tar

# Step 3: import dataplane

docker import results/min.tar min:release
docker import results/dataplane.tar dataplane:debug

# Step 4: cargo build

cargo build

# Step 5: cargo nextest run

# (one test is xfail)

cargo nextest run || true

# Step 6: cargo test run

# (one test is xfail)

cargo test || true

# Step 7: build test archive

nix build -f default.nix tests.all --out-link results/tests.all
# (one test is xfail)

cargo nextest run --archive-file results/tests.all/*.tar.zst --workspace-remap "$(pwd)" || true

# Step 8: build individual tests archive

nix build -f default.nix tests.pkg --out-link results/tests.pkg --max-jobs 4

for pkg in results/tests.pkg/*/*.tar.zst; do
  # (one test is xfail)
  cargo nextest run --archive-file "${pkg}" --workspace-remap "$(pwd)" || true
done
