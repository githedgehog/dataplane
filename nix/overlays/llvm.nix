# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
}:
let
  fenix = import sources.fenix { };
  rust-toolchain = fenix.fromToolchainFile {
    file = ../../rust-toolchain.toml;
    sha256 = (builtins.fromJSON (builtins.readFile ../.rust-toolchain.manifest-lock.json)).hash.sha256;
  };
in
final: prev: {
  # It is essential that we always use the same version of llvm that our rustc is backed by.
  # To minimize maintenance burden, we explicitly compute the version of LLVM we need by asking rustc
  # which version it is using.
  # This is significantly less error prone than hunting around for all versions of pkgs.llvmPackages_${version}
  # every time rust updates.
  llvmPackages =
    let
      version = builtins.readFile (
        final.runCommandLocal "llvm-version-for-our-rustc"
          {
            RUSTC = "${rust-toolchain.out}/bin/rustc";
            GREP = "${final.pkgsBuildHost.gnugrep}/bin/grep";
            SED = "${final.pkgsBuildHost.gnused}/bin/sed";
          }
          ''
            $RUSTC --version --verbose | \
              $GREP '^LLVM version:' | \
              $SED -z 's|LLVM version: \([0-9]\+\)\.[0-9]\+\.[0-9]\+\n|\1|' > $out
          ''
      );
    in
    final."llvmPackages_${version}";
}
