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
  # cargoDeps must be fetched from the overridden source too.
  bugstalker = prev.bugstalker.overrideAttrs (orig: {
    version = final.lib.removePrefix "v" sources.bugstalker.version;
    src = sources.bugstalker;
    cargoDeps = prev.rustPlatform.fetchCargoVendor {
      src = sources.bugstalker;
      hash = "sha256-GGi5hnrK5WpvnXHNckpsBch/SJ4lDvH7peSlrCdk218=";
    };
  });
  # lurk disables ASLR in the tracee before exec, and treats failure as fatal.
  # Docker's default seccomp profile answers personality(ADDR_NO_RANDOMIZE) with
  # EPERM, so under a plain `docker run` the traced program never starts -- and
  # lurk still exits 0 after emitting a well-formed JSON trace of its own child
  # failing, which the `jq -R 'fromjson? // empty'` filter we document accepts
  # without complaint.
  #
  # Nothing in the tracer image symbolizes an address, so a fixed layout buys us
  # nothing.  Make it advisory rather than telling users to pass
  # `--security-opt seccomp=unconfined`, which drops confinement on a container
  # whose whole job is ptracing a process.
  #
  # Two single-line substitutions rather than one spanning both: nix strips the
  # common indentation from an indented string, so a multi-line search pattern
  # would not match the source's own indentation.
  lurk = prev.lurk.overrideAttrs (orig: {
    postPatch = (orig.postPatch or "") + ''
      substituteInPlace src/lib.rs \
        --replace-fail \
          'personality::set(Persona::ADDR_NO_RANDOMIZE)' \
          'let _ = personality::set(Persona::ADDR_NO_RANDOMIZE);' \
        --replace-fail \
          '.map_err(|_| anyhow!("Unable to set ADDR_NO_RANDOMIZE"))?;' \
          ""
    '';
  });

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
}
