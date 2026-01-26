# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  sanitizers,
  platform,
  profile,
  ...
}:
final: prev:
let
  dep = pkg: pkg.override { stdenv = final.stdenv'; };
  frr-build =
    frrSrc:
    (dep (
      final.callPackage ../pkgs/frr (
        final.fancy
        // {
          stdenv = final.stdenv';
          inherit frrSrc;
        }
      )
    )).overrideAttrs
      (orig: {
        LDFLAGS =
          (orig.LDFLAGS or "")
          + " -L${final.fancy.libxcrypt}/lib -lcrypt "
          + " -L${final.fancy.pcre2}/lib -lpcre2-8 "
          + " -L${final.fancy.xxHash}/lib -lxxhash ";
        configureFlags = orig.configureFlags ++ [
          "--enable-shared"
          "--enable-static"
          "--enable-static-bin"
        ];
      });
in
{
  fancy = prev.fancy // {
    xxHash = (dep prev.xxHash).overrideAttrs (orig: {
      cmakeFlags = (orig.cmakeFlags or [ ]) ++ [
        "-DBUILD_SHARED_LIBS=OFF"
        "-DXXH_STATIC_LINKING_ONLY=ON"
      ];
    });
    libyang = (
      (prev.libyang.override {
        stdenv = final.stdenv';
        pcre2 = final.fancy.pcre2;
        xxHash = final.fancy.xxHash;
      }).overrideAttrs
        (orig: {
          cmakeFlags = (orig.cmakeFlags or [ ]) ++ [ "-DBUILD_SHARED_LIBS=OFF" ];
          propagatedBuildInputs = [
            final.fancy.pcre2
            final.fancy.xxHash
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
            "CC:=clang"
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
    json_c = (
      (dep prev.json_c).overrideAttrs (orig: {
        cmakeFlags = (orig.cmakeFlags or [ ]) ++ [
          "-DENABLE_STATIC=1"
        ];
        postInstall = (orig.postInstall or "") + ''
          mkdir -p $dev/lib
          $RANLIB libjson-c.a;
          cp libjson-c.a $out/lib;
        '';
      })
    );
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
    ncurses = (
      prev.ncurses.override {
        stdenv = final.stdenv';
        enableStatic = true;
        withCxx = false;
      }
    );
    readline = (
      prev.readline.override {
        stdenv = final.stdenv';
        ncurses = final.fancy.ncurses;
      }
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
            "--enable-static"
            "--disable-shared"
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
    frr.host = frr-build sources.frr;
    frr.dataplane = frr-build sources.frr-dp;
  };
}
