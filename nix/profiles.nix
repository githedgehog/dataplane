# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  profile,
}:
let
  common.NIX_CFLAGS_COMPILE = [
    "-g3"
    "-gdwarf-5"
    # odr or strict-aliasing violations are indicative of LTO incompatibility, so check for that
    "-Werror=odr"
    "-Werror=strict-aliasing"
    "-Wno-error=unused-command-line-argument"
  ];
  common.NIX_CXXFLAGS_COMPILE = common.NIX_CFLAGS_COMPILE;
  common.NIX_CFLAGS_LINK = [
    # getting proper LTO from LLVM compiled objects is best done with lld rather than ld, mold, or wild (at least at the
    # time of writing)
    "-fuse-ld=lld"
    "-Wl,--build-id"
  ];
  common.RUSTFLAGS = [
    "--cfg=tokio_unstable"
    "-Cdebuginfo=full"
    "-Cdwarf-version=5"
    "-Csymbol-mangling-version=v0"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") common.NIX_CFLAGS_LINK);
  optimize-for.debug.NIX_CFLAGS_COMPILE = [
    "-fno-inline"
    "-fno-omit-frame-pointer"
  ];
  optimize-for.debug.NIX_CXXFLAGS_COMPILE = optimize-for.debug.NIX_CFLAGS_COMPILE;
  optimize-for.debug.NIX_CFLAGS_LINK = [ ];
  optimize-for.debug.RUSTFLAGS = [
    "-Copt-level=0"
    "-Cdebug-assertions=on"
    "-Coverflow-checks=on"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") optimize-for.debug.NIX_CFLAGS_LINK);
  optimize-for.performance.NIX_CFLAGS_COMPILE = [
    "-O3"
    "-flto=thin"
  ];
  optimize-for.performance.NIX_CXXFLAGS_COMPILE = optimize-for.performance.NIX_CFLAGS_COMPILE ++ [
    "-fwhole-program-vtables"
  ];
  optimize-for.performance.NIX_CFLAGS_LINK = optimize-for.performance.NIX_CXXFLAGS_COMPILE ++ [
    "-Wl,--lto-whole-program-visibility"
    "-Wl,--gc-sections"
    "-Wl,--as-needed"
  ];
  optimize-for.performance.RUSTFLAGS = [
    "-Clinker-plugin-lto"
    "-Cembed-bitcode=yes"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") optimize-for.performance.NIX_CFLAGS_LINK);
  combine-profiles =
    features:
    builtins.foldl' (
      acc: element: acc // (builtins.mapAttrs (var: val: (acc.${var} or [ ]) ++ val) element)
    ) { } features;
  profile-map = {
    debug = combine-profiles [
      common
      optimize-for.debug
    ];
    release = combine-profiles [
      common
      optimize-for.performance
    ];
  };
in
combine-profiles [
  profile-map."${profile}"
]
