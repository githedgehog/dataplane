# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  ...
}:
final: prev:
let
  override-packages = {
    stdenv = final.llvmPackages'.stdenv;
    rustPlatform = final.rustPlatform'-dev;
  };
in
{
  kopium = import ../pkgs/kopium (
    override-packages
    // {
      src = sources.kopium;
    }
  );
  opengrep = final.callPackage ../pkgs/opengrep {
    src = sources.opengrep;
  };
  cargo-bolero = prev.cargo-bolero.override { inherit (override-packages) rustPlatform; };
  cargo-deny = prev.cargo-deny.override { inherit (override-packages) rustPlatform; };
  cargo-edit = prev.cargo-edit.override { inherit (override-packages) rustPlatform; };
  cargo-llvm-cov = (prev.cargo-llvm-cov.override override-packages).overrideAttrs (orig: {
    # the test suite is very impractical in our CI (fails on nightly for spurious reasons), and has nothing to do with
    # our project.
    doCheck = false;
  });
  cargo-nextest = prev.cargo-nextest.override override-packages;
  just = prev.just.override override-packages;
  npins = prev.npins.override { inherit (override-packages) rustPlatform; };
  gateway-crd =
    let
      p = "config/crd/bases/gwint.githedgehog.com_gatewayagents.yaml";
    in
    final.writeTextFile {
      name = "gateway-crd";
      text = builtins.readFile "${sources.fabric}/${p}";
      executable = false;
      destination = "/src/fabric/${p}";
    };

  gdb' = prev.gdb.overrideAttrs (orig: {
    CFLAGS = "-Os -flto";
    CXXFLAGS = "-Os -flto";
    LDFLAGS = "-flto -Wl,--as-needed,--gc-sections -static-libstdc++ -static-libgcc";
    buildInputs = (orig.buildInputs or [ ]);
    configureFlags = (orig.configureFlags or [ ]) ++ [
      "--enable-static"
      "--disable-inprocess-agent"
      "--disable-source-highlight" # breaks static compile
    ];
  });

  linux-fancy =
    let
      version = "6.18.20";
      # True only when the kernel's target arch differs from the builder.
      isCross = final.stdenv.hostPlatform.system != final.stdenv.buildPlatform.system;
      # Cross stdenv: builds the (possibly aarch64) kernel itself.
      crossStdenv = final.llvmPackages'.stdenv;
      # Stdenv/toolchain that runs the .config codegen, which must execute
      # on the builder.  For a native build keep the original (so the
      # output is byte-identical); for a cross build switch to the
      # build-platform toolchain so the setup tools actually run.
      buildStdenv = if isCross then final.pkgsBuildHost.llvmPackages'.stdenv else crossStdenv;
      buildLlvm = if isCross then final.pkgsBuildHost.llvmPackages' else final.llvmPackages';
      # Target kernel ARCH, only set when cross-compiling (null leaves a
      # native build's config output byte-identical).
      kernelArch = if isCross then final.stdenv.hostPlatform.linuxArch else null;
      src = fetchTarball {
        url = "https://cdn.kernel.org/pub/linux/kernel/v${final.lib.versions.major version}.x/linux-${version}.tar.xz";
        sha256 = "sha256:1sbidvi0zi1a8nlzrdjmk3yq50gdc5qjvcf4n4ah70pis25912ba";
      };
      # Fragments are merged left-to-right; later entries override earlier ones.
      # Place broad settings first and targeted overrides (especially disables) last.
      #
      # The shared list is arch-neutral in intent: x86-only symbols
      # (CONFIG_X86_*, 8250, x86 PARAVIRT) that don't exist on arm64 are
      # warned-and-dropped by merge_config.sh, harmlessly.  The aarch64
      # `virt`-machine essentials (GIC, PL011, PSCI, arch timer, generic
      # PCI host) are appended via an arch-specific fragment.
      sharedFragments = [
        "base.config"
        "serial-console.config"
        "kvm-guest.config"
        "virtio.config"
        "hugepages.config"
        "cgroups-ns.config"
        "filesystems.config"
        "crypto.config"
        "net-core.config"
        "net-tc-qos.config"
        "net-virt-devices.config"
        "intel-e1000.config"
        "mlx5-sriov.config"
        # "debug-fuzz.config"
        "disable.config"
      ];
      # Appended last so its enables win over earlier fragments/disables.
      archFragments = final.lib.optionals final.stdenv.hostPlatform.isAarch64 [
        "aarch64-virt.config"
      ];
      fragments = map (f: ../pkgs/linux/fragments + "/${f}") (sharedFragments ++ archFragments);
      configfile = final.callPackage ../pkgs/linux/merge-config.nix {
        inherit src version fragments kernelArch;
        stdenv = buildStdenv;
        llvmPackages = buildLlvm;
      };
    in
    final.linuxManualConfig {
      inherit version src configfile;
      stdenv = crossStdenv;
    };
}
