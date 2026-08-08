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
  duvet = final.callPackage ../pkgs/duvet {
    src = sources.duvet;
    inherit (override-packages) rustPlatform;
  };
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
  cargo-expand = prev.cargo-expand.override { inherit (override-packages) rustPlatform; };
  cargo-show-asm = prev.cargo-show-asm.override { inherit (override-packages) rustPlatform; };
  cargo-mutants = prev.cargo-mutants.override { inherit (override-packages) rustPlatform; };
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

  # Builds a guest kernel from the shared fragment list plus whatever else
  # the caller asks for.
  #
  # Parameterised because profiles need more than one kernel: the default is
  # fully static, while exercising the initramfs boot path needs one whose
  # virtiofs is a module.  `extraFragments` are merged *last*, after the
  # arch fragments and after disable.config, so a caller can override any
  # earlier setting -- which is the whole point for `modular.config`, whose
  # job is to turn `=y` into `=m`.
  mkLinuxFancy =
    {
      extraFragments ? [ ],
    }:
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
      fragments = map (f: ../pkgs/linux/fragments + "/${f}") (
        sharedFragments ++ archFragments ++ extraFragments
      );
      configfile = final.callPackage ../pkgs/linux/merge-config.nix {
        inherit src version fragments kernelArch;
        stdenv = buildStdenv;
        llvmPackages = buildLlvm;
      };
    in
    final.linuxManualConfig {
      inherit version src configfile;
      stdenv = crossStdenv;
      # nixpkgs decides at *eval* time whether this kernel has modules, and
      # that decision creates a whole extra output (`modules`) plus the
      # `modules_install` step.  It normally learns this by reading the
      # configfile -- but only when the configfile is a literal path or
      # `allowImportFromDerivation` is set.  Ours is a derivation
      # (merge-config.nix), so without help nixpkgs sees an empty config,
      # concludes the kernel is not modular, and silently ships a kernel
      # whose `.ko` files were never installed anywhere.
      #
      # Answered by reading our own fragments, which *are* paths, so no
      # import-from-derivation is involved.  IFD would be the obvious
      # alternative but it forces the config derivation to build during
      # evaluation and is unavailable under restricted eval; a hand-set flag
      # would be a second source of truth that could drift from the
      # fragments it is supposed to describe.
      config = final.lib.optionalAttrs (
        final.lib.any (f: final.lib.hasInfix "CONFIG_MODULES=y" (builtins.readFile f)) fragments
      ) { CONFIG_MODULES = "y"; };
    };

  # A pinned Flatcar release, repackaged into the layout the kernel
  # manifest expects.  This is the kernel the dataplane actually ships on,
  # which is the whole reason for running tests against it.
  flatcar-kernel = final.callPackage ../pkgs/flatcar {
    # `extract-ikconfig` is version-agnostic -- it scans an image for the
    # embedded IKCFG_ST block -- so our own kernel source's copy reads
    # Flatcar's image fine, and this avoids a second kernel source fetch.
    extractIkconfig = "${final.linux-fancy.src}/scripts/extract-ikconfig";
  };

  # A pinned Ubuntu kernel, repackaged into the same layout.  Not a second
  # copy of the Flatcar test: this one exists to find out whether the harness
  # is distro-agnostic or merely Flatcar-shaped.  Needs no `extractIkconfig`
  # -- Ubuntu does not set `CONFIG_IKCONFIG`, so its config comes from a
  # separate package instead of from the image.
  ubuntu-kernel = final.callPackage ../pkgs/ubuntu { };

  # The default guest kernel: everything built in, no modules at all.
  linux-fancy = final.mkLinuxFancy { };

  # Same kernel with virtiofs and fuse demoted to modules, reproducing the
  # bootstrap deadlock a distro kernel presents (see modular.config).
  linux-fancy-modular = final.mkLinuxFancy {
    extraFragments = [ "modular.config" ];
  };
}
