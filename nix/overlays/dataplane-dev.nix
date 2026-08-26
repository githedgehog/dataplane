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
  # Keep in step with the `iai-callgrind` version in `Cargo.toml`; see the package's comment.
  iai-callgrind-runner = final.callPackage ../pkgs/iai-callgrind-runner {
    inherit (override-packages) rustPlatform;
    version = "0.16.1";
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

  # A gdb that can be copied into a VM or an image that has no nix store, and
  # still run: musl, no interpreter, no shared libraries at all.
  #
  # Configure flags cannot get you here.  `--enable-static` and
  # `--disable-shared` -- which nixpkgs already passes -- only decide whether
  # the libbfd, libopcodes, and libctf that this tree builds are archives; they
  # say nothing about how the gdb executable links against readline, ncurses,
  # expat, or python, and those have no static outputs in the default package
  # set.  Hence pkgsStatic, which rebuilds the dependencies rather than the
  # link line.
  #
  # pkgsStatic gates python support on host == build, so this gdb configures
  # `--without-python` and cannot load the Rust pretty printers.  It is a
  # bare-metal debugger, not a replacement for the ordinary `gdb` that
  # `containers.dataplane-core-viewer` ships with `rust-gdb-printers`.
  gdb' = final.pkgsStatic.gdb.override {
    # dejagnu is a buildInput only so that gdb's own test suite can run, and we
    # never run it.  It also cannot be built here: expect resolves `tclStubsPtr`
    # from tcl's stub library, which exists to be filled in by a dynamic loader,
    # so a static link leaves it undefined.
    dejagnu = final.pkgsStatic.emptyDirectory;
  };

  # A perf that can be copied into a VM or an image with no nix store, for the
  # same reason as `gdb'`.
  #
  # Unlike gdb this cannot come from pkgsStatic: elfutils carries
  # `badPlatforms = isStatic` because its Makefile builds libelf.so
  # unconditionally, and a static toolchain cannot emit a shared object at all
  # (`crtbeginT.o: relocation R_X86_64_32 against hidden symbol __TMC_END__`).
  # perf without libelf/libdw is not worth shipping, so build against ordinary
  # glibc packages -- whose elfutils already installs libelf.a and libdw.a --
  # and make only the final link static.
  perf' =
    let
      # Every dependency below is either unusable in a static binary or not
      # worth its transitive static closure.  Dropping them at the argument
      # layer keeps them out of the build; the NO_* flags tell perf's own
      # configure-equivalent the same thing, so the two cannot disagree.
      none = final.emptyDirectory;
    in
    (final.perf.override {
      stdenv = final.stdenvAdapters.makeStaticBinaries final.stdenv;
      withPython = false;
      withLibcap = false;
      newt = none;
      slang = none;
      babeltrace = none;
      libunwind = none;
      libpfm = none;
      numactl = none;
      openssl = none;
      libopcodes = none;
      libtraceevent = none;
      systemtap-unwrapped = none;
    }).overrideAttrs
      (orig: {
        # dlfilters are dlopen-ed plugins, which a static perf could not load
        # even if the toolchain could build them.
        postPatch = orig.postPatch + ''
          substituteInPlace Makefile.perf \
            --replace-fail \
              'DLFILTERS := dlfilter-test-api-v0.so dlfilter-test-api-v2.so dlfilter-show-cycles.so' \
              'DLFILTERS :=' \
            --replace-fail '$(INSTALL) $(DLFILTERS) ' 'true '
        '';
        # perf keys off -static in LDFLAGS to add `-lelf -lz -llzma -lbz2 -ldl`
        # to the libdw link.  Without it the libdw probe fails and perf builds
        # with DWARF support silently off -- it still links, so this is only
        # visible in `perf version --build-options`.  Pass it in the
        # environment, not via makeFlags, so Makefile.config's own `LDFLAGS +=`
        # still appends.
        env = orig.env // {
          LDFLAGS = "-static";
        };
        # A static link does not follow a library's own dependencies, so
        # libelf.a and libdw.a's compression backends have to be named here,
        # as archives rather than the shared objects the normal outputs carry.
        buildInputs = orig.buildInputs ++ [
          final.zlib.static
          (final.zstd.override { static = true; })
          (final.xz.override { enableStatic = true; })
          (final.bzip2.override { enableStatic = true; })
        ];
        makeFlags = orig.makeFlags ++ [
          "NO_LIBPYTHON=1"
          "NO_LIBPERL=1"
          "NO_SLANG=1"
          "NO_NEWT=1"
          "NO_LIBBABELTRACE=1"
          "NO_LIBNUMA=1"
          "NO_LIBAUDIT=1"
          "NO_LIBBPF=1"
          "NO_LIBPFM4=1"
          "NO_LIBCRYPTO=1"
          "NO_JVMTI=1"
          "NO_LIBUNWIND=1"
          "NO_LIBDEBUGINFOD=1"
          "NO_LIBTRACEEVENT=1"
          "NO_SDT=1"
          # Only C++ demangling.  perf's Rust v0 demangler is built in and
          # unaffected, which is what matters for a Rust dataplane.
          "NO_DEMANGLE=1"
        ];
        # wrapProgram would replace the binary with a shell script, defeating
        # the point of a static build.  It only put objdump on PATH for
        # `perf annotate`, which needs a toolchain on the target regardless.
        preFixup = "";
      });
}
