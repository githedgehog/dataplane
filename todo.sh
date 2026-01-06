#!/usr/bin/env bash

set -euxo pipefail

# already done

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix sysroot --out-link sysroot
nix --extra-experimental-features nix-command build -f default.nix devroot --out-link devroot

# build dataplane container (debug mode)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar
docker import /tmp/dataplane.tar dataplane:v0.0.0-debug
docker run --rm -it dataplane:v0.0.0-debug /bin/dataplane || true

# # build dataplane container (release mode)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar --argstr profile release
docker import /tmp/dataplane.tar dataplane:v0.0.0-release
docker run --rm -it dataplane:v0.0.0-release /bin/dataplane || true

# build dataplane container (address sanitizer mode)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar --argstr sanitize address
docker import /tmp/dataplane.tar dataplane:v0.0.0-debug-sanitize-address
docker run --rm -it dataplane:v0.0.0-debug-sanitize-address /bin/dataplane || true

# build dataplane container (thread sanitizer mode)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar --argstr sanitize thread
docker import /tmp/dataplane.tar dataplane:v0.0.0-debug-sanitize-thread
docker run --rm -it dataplane:v0.0.0-debug-sanitize-thread /bin/dataplane || true

# build dataplane container (release with stack sanitizer mode)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar --argstr profile release --argstr sanitize safe-stack
docker import /tmp/dataplane.tar dataplane:v0.0.0-release-sanitize-stack
docker run --rm -it dataplane:v0.0.0-release-sanitize-stack /bin/dataplane || true

# build dataplane container (release with stack sanitizer mode zen5)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar --argstr platform zen5 --argstr profile release --argstr sanitize safe-stack
docker import /tmp/dataplane.tar dataplane:v0.0.0-release-sanitize-stack-zen5
docker run --rm -it dataplane:v0.0.0-release-sanitize-stack-zen5 /bin/dataplane || true

# build dataplane container (debug mode for bluefield3) (expected to build but not run)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar --argstr platform bluefield3 --argstr profile debug
docker import /tmp/dataplane.tar dataplane:v0.0.0-bluefield3-debug

# build dataplane container (release mode for bluefield3) (expected to build but not run)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar --argstr platform bluefield3 --argstr profile release
docker import /tmp/dataplane.tar dataplane:v0.0.0-bluefield3-release

# build dataplane container (debug mode with coverage)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar --argstr instrumentation coverage
docker import /tmp/dataplane.tar dataplane:v0.0.0-debug-coverage
docker run --rm -it dataplane:v0.0.0-debug-coverage /bin/dataplane || true

# build dataplane container (complex build)

nix --max-jobs 8 --extra-experimental-features nix-command build -f default.nix dataplane-tar --out-link /tmp/dataplane.tar \
    --argstr platform zen4 \
    --argstr profile release \
    --argstr sanitize address,leak \
    --argstr instrumentation coverage
docker import /tmp/dataplane.tar dataplane:v0.0.0-complex
docker run --rm -it dataplane:v0.0.0-complex /bin/dataplane || true
