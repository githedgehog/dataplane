# CodeQL for the lint queries in `.codeql/`.
#
# Three things here are not obvious.
#
# We take the *bundle* from codeql-action, not nixpkgs' `codeql` (which packages
# the bare CLI) and not the codeql-cli-binaries release. Only the bundle ships
# the extractors and the `codeql/rust-*` query packs; the CLI on its own cannot
# build or analyse a database.
#
# Versioning works like opengrep's: the npins `codeql-bundle` pin tracks the
# `codeql-bundle-v*` release tags, and the release asset's hash lives in
# ./bundle.sri, refreshed by scripts/bump.sh. The extractor embeds a
# rust-analyzer, which must be able to read our toolchain's sysroot: check
# `just codeql-lint-test` after a toolchain bump.
#
# The wrapper pins the extractor to the workspace toolchain. Left alone it finds
# `rustc`/`cargo` through `$RUSTC`/`$CARGO`, then PATH, then rustup -- on a
# developer machine that is whatever toolchain rustup defaults to (often a
# nightly), not ours.
{
  lib,
  stdenv,
  fetchurl,
  src,
  zstd,
  autoPatchelfHook,
  makeWrapper,
  zlib,
  # The workspace toolchain; the extractor analyses against its sysroot.
  rust-toolchain,
  ...
}:
stdenv.mkDerivation {
  pname = "codeql";
  # src.version carries the tag ("codeql-bundle-v2.27.4").
  version = lib.removePrefix "codeql-bundle-v" src.version;
  src = fetchurl {
    url = "https://github.com/github/codeql-action/releases/download/${src.version}/codeql-bundle-linux64.tar.zst";
    hash = lib.removeSuffix "\n" (builtins.readFile ./bundle.sri);
  };

  nativeBuildInputs = [
    zstd
    autoPatchelfHook
    makeWrapper
  ];
  buildInputs = [
    zlib
    stdenv.cc.cc.lib
  ];

  unpackPhase = ''
    runHook preUnpack
    tar --use-compress-program=unzstd -xf "$src"
    runHook postUnpack
  '';

  # The bundle ships every language. We analyse Rust only, and carrying the rest
  # costs ~750 MiB in every developer's store for no benefit.
  #
  # Both lists are DENYLISTS, naming the languages we drop. Do not invert either
  # one into an allowlist of what Rust needs: `codeql/rust-all` pulls in eleven
  # shared qlpacks (namebinding, tutorial, typeinference, ...) and an allowlist
  # that misses one fails at query-compile time with a pack-resolution error
  # rather than at build time. The language-specific packs are 494 MiB of the
  # 515 MiB total, so keeping every shared pack costs almost nothing.
  installPhase = ''
    runHook preInstall

    cd codeql

    dropped="cpp java csharp go javascript ruby python swift actions"

    for lang in $dropped html xml csv properties yaml; do
      rm -rf "$lang"
    done

    for lang in $dropped; do
      rm -rf qlpacks/codeql/"$lang"-all \
             qlpacks/codeql/"$lang"-queries \
             qlpacks/codeql/"$lang"-examples
    done

    # 32-bit build tracers cannot be patched without a full i686 package set and
    # are only used when tracing a compiled-language build, which Rust's
    # build-mode=none never does.
    rm -f tools/linux64/*32*.so tools/linux64/i386-linux-gnu*.so

    mkdir -p "$out/libexec"
    cp -r . "$out/libexec/codeql"

    # The bundle's helper scripts are `#!/bin/bash`, which does not exist on
    # NixOS; without this `codeql test run` dies with a bare
    # "IOException ... error: 2 (No such file or directory)".
    patchShebangs "$out/libexec/codeql"

    # A nix toolchain is a symlink farm: `library/Cargo.toml` points into the
    # separate rust-src store path while the sysroot is the rust-default path.
    # rust-analyzer cannot reconcile the two and reports "failed to determine
    # rust edition" for the sysroot crates. Extraction still *looks* fine --
    # macros resolve, no extraction errors -- but path resolution into std is
    # dead, so every resolution-based query silently returns nothing. That is
    # what `.codeql/tests` catches; without this, StringyError and
    # NoStdSyncDirect both drop to zero results.
    #
    # Pointing sysroot-src at the realpath of the rust-src store path fixes it.
    # Computed rather than hardcoded so it tracks the toolchain, and embedding
    # the path in $out registers the store reference.
    sysrootSrc="$(dirname "$(realpath "${rust-toolchain}/lib/rustlib/src/rust/library/Cargo.toml")")"
    test -f "$sysrootSrc/std/src/lib.rs" || {
      echo "rust-src layout unexpected at $sysrootSrc" >&2
      exit 1
    }

    # CODEQL_PLATFORM short-circuits the launcher's `uname` probe, which would
    # otherwise make coreutils an undeclared runtime dependency.
    makeWrapper "$out/libexec/codeql/codeql" "$out/bin/codeql" \
      --prefix PATH : "${rust-toolchain}/bin" \
      --set RUSTC "${rust-toolchain}/bin/rustc" \
      --set CARGO "${rust-toolchain}/bin/cargo" \
      --set CODEQL_EXTRACTOR_RUST_OPTION_SYSROOT_SRC "$sysrootSrc" \
      --set-default CODEQL_PLATFORM linux64

    runHook postInstall
  '';

  # The bundled JRE carries libraries for platforms we stripped.
  autoPatchelfIgnoreMissingDeps = true;

  meta = {
    description = "CodeQL CLI bundle, Rust extractor and query packs only";
    homepage = "https://github.com/github/codeql-action";
    # GitHub CodeQL CLI terms; free for use on open-source code.
    license = lib.licenses.unfree;
    mainProgram = "codeql";
    platforms = [ "x86_64-linux" ];
  };
}
