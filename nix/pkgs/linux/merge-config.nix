# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Merge Linux kernel config fragments into a complete .config file.
#
# Uses the kernel's own scripts/kconfig/merge_config.sh to combine fragments
# left-to-right (later fragments override earlier ones) on top of an
# allnoconfig base, then resolves Kconfig dependencies to produce a fully
# consistent configuration.
#
# The allnoconfig base means every option starts as "n" — only values
# explicitly requested by the fragments (and options pulled in via Kconfig
# `select` statements) will be enabled.  This keeps the resulting kernel
# minimal, but it also means fragments must specify the full `depends on`
# chain for every option they request.  merge_config.sh prints warnings for
# any requested value that did not survive dependency resolution, which makes
# it straightforward to identify missing dependencies.
#
# The output is a single file suitable for use as the `configfile` argument
# to `linuxManualConfig`.
{
  stdenv,
  lib,
  src,
  version,
  fragments,
  flex,
  bison,
  bc,
  perl,
  python3,
  llvmPackages ? null,
}:

assert lib.assertMsg (fragments != [ ]) "merge-config: at least one config fragment is required";
assert lib.assertMsg (builtins.isList fragments) "merge-config: fragments must be a list of paths";

stdenv.mkDerivation {
  pname = "linux-merged-config";
  inherit version src;

  nativeBuildInputs = [
    flex
    bison
    bc
    perl
    python3
  ]
  # When building with the LLVM stdenv, ld.lld must be on PATH for the
  # kernel's Kconfig probing (scripts/Kconfig.include checks for $(LD) by name,
  # and LLVM=1 sets LD=ld.lld).  The stdenv's cc.bintools is GNU ld — we need
  # the LLVM bintools wrapper which ships ld.lld.
  ++ lib.optionals stdenv.cc.isClang
    [ (assert llvmPackages != null; llvmPackages.bintools) ];

  # We only generate a config file — skip build and fixup entirely.
  dontBuild = true;
  dontFixup = true;

  configurePhase =
    let
      # Copy each fragment into a local writable directory.
      # merge_config.sh touches the first file in-place, so Nix store paths
      # (which are read-only) cannot be used directly.
      copyFragment = i: f:
        "cp ${f} fragments/${toString i}-${baseNameOf (toString f)}";
      copyCommands = lib.concatStringsSep "\n"
        (lib.imap0 copyFragment fragments);
    in
    ''
      runHook preConfigure

      # Use the LLVM toolchain when the stdenv provides clang.
      ${lib.optionalString stdenv.cc.isClang "export LLVM=1"}

      # Point kconfig host-tool builds at the stdenv compilers.
      export HOSTCC=$CC
      export HOSTCXX=$CXX
      export HOSTLD=$LD
      export HOSTAR=$AR

      mkdir -p fragments
      ${copyCommands}
      chmod u+w fragments/*

      echo "Merging ${toString (builtins.length fragments)} config fragment(s) (allnoconfig base)..."
      # -n: use allnoconfig instead of alldefconfig — every option starts as
      #     "n" so the kernel contains only what fragments explicitly request.
      bash scripts/kconfig/merge_config.sh -n $(ls -v fragments/*)

      runHook postConfigure
    '';

  installPhase = ''
    runHook preInstall
    cp .config $out
    runHook postInstall
  '';
}