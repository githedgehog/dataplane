# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
#
# Install a prebuilt Verus release (https://github.com/verus-lang/verus).
#
# Verus is a rustc driver: `rust_verify` links `librustc_driver-<hash>.so`
# dynamically, so each Verus release works with exactly one Rust release.
#
# That release is deliberately *not* our pinned `rust-toolchain`.  Verus
# tracks stable Rust a couple of weeks behind and skips some patch releases,
# while we bump within days, take every patch, and also build with nightly
# (miri).  Tying the two together would block Rust bumps on Verus.  Instead
# the package carries the exact toolchain its release was built for, from
# rust-overlay, and uses it for verification only:
#
#   * autoPatchelfHook gives every binary an rpath into that toolchain's lib,
#     which also makes rustc find its sysroot (and so `std`) there.
#   * the wrappers set `VERUS_USE_RUSTUP=0`, which skips rustup and runs
#     `rust_verify` directly, and put that toolchain's `cargo` first on PATH
#     for `cargo verus`.
#
# The cost: crates that set `[package.metadata.verus] verify = true` must
# also build with this (slightly older) rustc and cargo.
#
# To update, pick a newer Verus release, set `version`, the hashes, and
# `rust` to the toolchain its `version.json` names; the build checks that
# `rust` matches.  Verus is not an npins pin because `version` and `rust`
# must move together.
{
  lib,
  stdenvNoCC,
  stdenv,
  fetchzip,
  autoPatchelfHook,
  makeWrapper,
  jq,
  rust-bin,
}:
let
  version = "0.2026.11.02.8bf68ee";
  # The toolchain this release was built against (its version.json).
  rust = "1.99.1";
  # Only what verification needs: rustc (and its librustc_driver), the host
  # std that vstd was compiled against, and cargo.
  verus-toolchain = rust-bin.stable.${rust}.minimal;
  # Release asset per build machine, and its unpacked hash.
  assets = {
    x86_64-linux = {
      name = "x86-linux";
      hash = "sha256-m7u6bXGFeis39gpBlD5o3z4Btl1/CpbYuog03tzmKQA=";
    };
    aarch64-linux = {
      name = "arm64-linux";
      hash = "sha256-oPeng3aQhXtbC3hf+MG/uTlR5yL4udF1ZYzC/rse8F4=";
    };
  };
  asset =
    assets.${stdenvNoCC.hostPlatform.system}
      or (throw "verus: no release asset for ${stdenvNoCC.hostPlatform.system}");
in
stdenvNoCC.mkDerivation {
  pname = "verus";
  inherit version;

  src = fetchzip {
    url = "https://github.com/verus-lang/verus/releases/download/release%2F${version}/verus-${version}-${asset.name}.zip";
    inherit (asset) hash;
  };

  nativeBuildInputs = [
    autoPatchelfHook
    makeWrapper
    jq
  ];
  buildInputs = [
    verus-toolchain # librustc_driver for rust_verify
    stdenv.cc.cc.lib # libstdc++ for z3, libgcc_s for everything
  ];

  dontConfigure = true;
  dontBuild = true;
  dontStrip = true;

  installPhase = ''
    runHook preInstall

    toolchain="$(jq --exit-status --raw-output .verus.toolchain version.json)"
    case "$toolchain" in
      ${rust}-*) ;;
      *)
        echo "version.json says this release needs $toolchain, expected ${rust}" >&2
        exit 1
        ;;
    esac

    # Everything stays in one directory: `verus` finds `rust_verify`, `z3`
    # and vstd next to its own executable, and `cargo-verus` finds `verus`
    # the same way.
    mkdir -p $out/libexec/verus $out/bin
    cp -r . $out/libexec/verus/
    for prog in verus cargo-verus; do
      makeWrapper $out/libexec/verus/$prog $out/bin/$prog \
        --set VERUS_USE_RUSTUP 0 \
        --prefix PATH : ${verus-toolchain}/bin
    done

    runHook postInstall
  '';

  # Prove the package can verify something, and refute something false, so a
  # broken toolchain pairing fails here rather than in CI.
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    cat > ok.rs <<'RS'
    use vstd::prelude::*;
    verus! {
        fn max(a: u64, b: u64) -> (r: u64) ensures r >= a && r >= b { if a > b { a } else { b } }
        fn main() {}
    }
    RS
    cat > bad.rs <<'RS'
    use vstd::prelude::*;
    verus! {
        fn inc(a: u64) -> (r: u64) ensures r > a { a + 1 }
        fn main() {}
    }
    RS
    $out/bin/verus ok.rs
    if $out/bin/verus bad.rs; then
      echo "verus accepted an overflowing add" >&2
      exit 1
    fi
    runHook postInstallCheck
  '';

  meta = {
    description = "Verified Rust for low-level systems code";
    homepage = "https://github.com/verus-lang/verus";
    license = lib.licenses.mit;
    mainProgram = "verus";
    platforms = builtins.attrNames assets;
  };
}
