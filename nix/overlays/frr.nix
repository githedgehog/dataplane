# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  sanitizers,
  platform,
  profile,
  libc,
  ...
}:
final: prev:
let
  dep =
    pkg:
    (pkg.override { stdenv = final.stdenv'; }).overrideAttrs (orig: {
      nativeBuildInputs = (orig.nativeBuildInputs or [ ]) ++ [ prev.removeReferencesTo ];
      postInstall = (orig.postInstall or "") + ''
        find "$out" \
            -type f \
            -exec remove-references-to -t ${final.stdenv'.cc} '{}' +;
        if [ -n "$lib" ] && [ -d "$lib" ]; then
            find "$lib" \
                -type f \
                -exec remove-references-to -t ${final.stdenv'.cc} '{}' +;
        fi
      '';
    });
  frr-build =
    frrSrc:
    dep (
      (final.callPackage ../pkgs/frr (
        final.fancy
        // {
          stdenv = final.stdenv';
          inherit frrSrc;
        }
      )).overrideAttrs
        (orig: {
          LDFLAGS =
            (orig.LDFLAGS or "")
            + " -L${final.fancy.readline}/lib -lreadline "
            + " -L${final.fancy.json_c}/lib -ljson-c "
            # libatomic must end up as a single dynamic dep in the process:
            # libatomic's lock_for_pointer state is per-image, so a static
            # copy inside libfrr.so cannot synchronize with any other
            # consumer that picks up libatomic.so dynamically.  Path differs
            # by libc because the libatomic.so that pairs with the chosen
            # cross-compiler stdenv lives in a different store path:
            #
            #   glibc: `${fancy.libgccjit}/lib/libatomic.so.1`
            #     The libgccjit overlay is currently built with the host
            #     stdenv (see TODO note on the libgccjit override below), so
            #     the libatomic next to it is glibc-targeted -- safe to link
            #     against a glibc FRR.
            #
            #   musl: `${stdenv.cc.cc.lib}/${triple}/lib/libatomic.so.1`
            #     This is the gcc-libs output of the cross-musl gcc that
            #     backs the cross-musl clang stdenv (note: stdenv, not
            #     stdenv' -- the prime is the clang stdenv whose cc.cc is
            #     clang and contains no libatomic at all).
            + (
              if libc == "musl" then
                " -L${final.stdenv.cc.cc.lib}/${final.stdenv.hostPlatform.config}/lib -latomic "
              else if libc == "gnu" then
                " -L${final.fancy.libgccjit}/lib -latomic "
              else
                throw "unhandled libc=${libc} for FRR -latomic LDFLAGS"
            )
            + " -L${final.fancy.libxcrypt}/lib -lcrypt "
            + " -Wl,--push-state,--as-needed,--no-whole-archive,-Bstatic "
            + " -L${final.fancy.pcre2}/lib -lpcre2-8 "
            + " -L${final.fancy.xxhash}/lib -lxxhash "
            + " -Wl,--pop-state";
          configureFlags = orig.configureFlags ++ [
            "--enable-shared"
            "--enable-static"
            # FRR's build system has an ODR violation when static bins are enabled;
            # this overrides the base package's --enable-static-bin.
            "--disable-static-bin"
          ];
          # `buildPackages.nukeReferences` rather than `prev.nukeReferences`:
          # the `nuke-refs` script substitutes a perl path at build time, and
          # under a cross pkgset `prev.nukeReferences` picks up target-arch
          # perl.  The script is executed during this derivation's build
          # phase on the build host, so the target-arch perl interpreter is
          # unrunnable ("Exec format error").  `buildPackages` resolves to
          # the build-host variant.  `removeReferencesTo` is shell-only and
          # picks up build-host bash via `stdenvNoCC.shell` regardless of
          # which pkgset it came from, so no equivalent fix is needed there.
          nativeBuildInputs = (orig.nativeBuildInputs or [ ]) ++ [ final.buildPackages.nukeReferences ];
          # disallowedReferences = (orig.disallowedReferences or []) ++ [ final.stdenv'.cc ];
          preFixup = ''
            find "$out" \
                -type f \
                -exec nuke-refs \
                -e "$out" \
                -e ${final.stdenv'.cc.libc} \
                -e ${final.python3Minimal} \
                -e ${final.fancy.readline} \
                -e ${final.fancy.libxcrypt} \
                -e ${final.fancy.json_c} \
                ${if libc == "gnu" then "-e ${final.fancy.libgccjit}" else ""} \
                ${if libc == "musl" then "-e ${final.stdenv.cc.cc.lib}" else ""} \
                '{}' +;
          '';
        })
    );
in
{
  fancy = prev.fancy // {
    inherit sources;
    xxhash = (dep prev.xxhash).overrideAttrs (orig: {
      cmakeFlags = (orig.cmakeFlags or [ ]) ++ [
        "-DBUILD_SHARED_LIBS=OFF"
        "-DXXH_STATIC_LINKING_ONLY=ON"
      ];
    });
    libyang = (
      (prev.libyang.override {
        stdenv = final.stdenv';
        pcre2 = final.fancy.pcre2;
        xxhash = final.fancy.xxhash;
      }).overrideAttrs
        (orig: {
          cmakeFlags = (orig.cmakeFlags or [ ]) ++ [ "-DBUILD_SHARED_LIBS=OFF" ];
          propagatedBuildInputs = [
            final.fancy.pcre2
            final.fancy.xxhash
          ];
        })
    );
    libcap = (
      (prev.libcap.override {
        stdenv = final.stdenv';
        usePam = false;
        withGo = false;
      }).overrideAttrs
        (orig: {
          doCheck = false; # tests require privileges
          separateDebugInfo = false;
          CFLAGS = "-ffat-lto-objects -fsplit-lto-unit";
          makeFlags = [
            "lib=lib"
            "PAM_CAP=no"
            "CC:=${final.stdenv'.cc.targetPrefix}clang"
            # _makenames is a build-host helper run during the build; pin it to
            # a build-host clang so cross-arch builds (e.g. bluefield3) don't
            # produce an aarch64 binary the build host cannot execute.
            "BUILD_CC:=${final.pkgsBuildBuild.llvmPackages'.clang}/bin/clang"
            "SHARED=no"
            "LIBCSTATIC=no"
            "GOLANG=no"
          ];
          configureFlags = (orig.configureFlags or [ ]) ++ [ "--enable-static" ];
          postInstall = orig.postInstall + ''
            # extant postInstall removes .a files for no reason
            cp ./libcap/*.a $lib/lib;
          '';
        })
    );
    json_c =
      (dep prev.json_c).overrideAttrs (orig: {
        cmakeFlags = (orig.cmakeFlags or [ ]) ++ [
          "-DENABLE_STATIC=1"
        ];
        postInstall = (orig.postInstall or "") + ''
          mkdir -p $dev/lib
          $RANLIB libjson-c.a;
          cp libjson-c.a $out/lib;
          find "$out" \
              -type f \
              -exec remove-references-to -t ${final.stdenv'.cc} '{}' +;
        '';
        nativeBuildInputs = (orig.nativeBuildInputs or [ ]) ++ [ prev.removeReferencesTo ];
        disallowedReferences = (orig.disallowedReferences or [ ]) ++ [ final.stdenv'.cc ];
      });
    rtrlib = dep (
      prev.rtrlib.overrideAttrs (orig: {
        cmakeFlags = (orig.cmakeFlags or [ ]) ++ [ "-DENABLE_STATIC=1" ];
      })
    );
    abseil-cpp = dep prev.abseil-cpp;
    zlib = (
      prev.zlib.override {
        stdenv = final.stdenv';
        static = true;
        shared = false;
      }
    );
    pcre2 = dep (
      prev.pcre2.overrideAttrs (orig: {
        configureFlags = (orig.configureFlags or [ ]) ++ [
          "--enable-static"
          "--disable-shared"
        ];
      })
    );
    ncurses = dep (
      prev.ncurses.override {
        stdenv = final.stdenv';
        enableStatic = true;
        withCxx = false;
      }
    );
    readline = dep (
      (prev.readline.override {
        stdenv = final.stdenv';
        ncurses = final.fancy.ncurses;
      }).overrideAttrs
        (orig: {
          nativeBuildInputs = (orig.nativeBuildInputs or [ ]) ++ [ prev.removeReferencesTo ];
          disallowedReferences = (orig.disallowedReferences or [ ]) ++ [ final.stdenv'.cc ];
          configureFlags = (orig.configureFlags or [ ]) ++ [
            "--enable-static"
            "--enable-shared"
          ];
          postInstall = (orig.postInstall or "") + ''
            find "$out" \
                -type f \
                -exec remove-references-to -t ${final.stdenv'.cc} '{}' +;
          '';
        })
    );
    libxcrypt = (dep prev.libxcrypt).overrideAttrs (orig: {
      configureFlags = (orig.configureFlags or [ ]) ++ [
        "--enable-static"
        "--disable-shared"
      ];
    });
    libgccjit =
      (prev.libgccjit.override {
        # TODO: debug issue preventing clang build
        # stdenv = final.stdenv';
        libxcrypt = final.fancy.libxcrypt;
      }).overrideAttrs
        (orig: {
          configureFlags = (orig.configureFlags or [ ]) ++ [
            "--disable-static"
            "--enable-shared"
          ];
        });
    c-ares = dep (
      prev.c-ares.overrideAttrs (orig: {
        cmakeFlags = (orig.cmakeFlags or [ ]) ++ [
          "-DCARES_SHARED=OFF"
          "-DCARES_STATIC=ON"
        ];
      })
    );
    frr-agent = dep (
      (final.callPackage ../pkgs/frr-agent final.fancy).overrideAttrs (orig: {
        # See `nukeReferences` note in `frr-build` above: must be the
        # build-host variant so the `nuke-refs` script's substituted perl is
        # runnable on the build host under cross compilation.
        nativeBuildInputs = (orig.nativeBuildInputs or [ ]) ++ [ final.buildPackages.nukeReferences ];
        # Keep refs to libc and (on glibc only) the libgcc path the
        # ld-linux search list points at -- that's where glibc-dynamic
        # Rust binaries find `libgcc_s.so.1` for unwinding.  Musl Rust
        # uses llvm-libunwind and has no libgcc_s consumer, so don't
        # bake glibc-targeted outputs into a musl image.
        fixupPhase = ''
          find "$out" \
              -exec nuke-refs \
              -e "$out" \
              -e ${final.stdenv.cc.libc} \
              ${if libc == "gnu" then "-e ${final.pkgsHostHost.glibc.libgcc}" else ""} \
              '{}' +;
        '';
      })
    );
    frr-config = dep (final.callPackage ../pkgs/frr-config final.fancy);
    dplane-rpc = dep (final.callPackage ../pkgs/dplane-rpc final.fancy);
    dplane-plugin = dep (final.callPackage ../pkgs/dplane-plugin final.fancy);
    frr.host = frr-build sources.frr;
    frr.dataplane = frr-build sources.frr-dp;
  };
}
