# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  arch,
  profile,
  sanitizers,
  instrumentation,
}:
let
  common.NIX_CFLAGS_COMPILE = [
    "-g3"
    "-gdwarf-5"
    # odr or strict-aliasing violations are indicative of LTO incompatibility, so check for that
    "-Werror=odr"
    "-Werror=strict-aliasing"
  ];
  common.NIX_CXXFLAGS_COMPILE = common.NIX_CFLAGS_COMPILE;
  common.NIX_CFLAGS_LINK = [
    # getting proper LTO from LLVM compiled objects is best done with lld rather than ld, mold, or wild (at least at the
    # time of writing)
    "-fuse-ld=lld"
    # we always want pic/pie and GOT offsets should be computed at compile time whenever possible
    "-Wl,-z,relro,-z,now"
  ];
  common.RUSTFLAGS = [
    "-Cdebug-info=full"
    "-Cdwarf-version=5"
  ];
  debug.NIX_CFLAGS_COMPILE = [
    "-fno-inline"
    "-fno-omit-frame-pointer"
    # "-D_FORTIFY_SOURCE=0" # disable security stuff because the goal is to make the asm as easy to understand as possible
    # "-Wno-macro-redefined" # many apps opt in to _FORTIFY_SOURCE={1,2,3} explicitly, and -Wall errors when you redefine
  ];
  debug.NIX_CXXFLAGS_COMPILE = debug.NIX_CFLAGS_COMPILE;
  debug.NIX_CFLAGS_LINK = [ ];
  optimize.NIX_CFLAGS_COMPILE = [
    "-O3"
    "-flto=thin"
    "-fsplit-lto-unit" # important for compatibility with rust's LTO
  ];
  optimize.NIX_CXXFLAGS_COMPILE = optimize.NIX_CFLAGS_COMPILE ++ [
    "-fwhole-program-vtables"
  ];
  optimize.NIX_CFLAGS_LINK = optimize.NIX_CXXFLAGS_COMPILE ++ [
    "-Wl,--lto-whole-program-visibility"
    # just to keep the artifacts small, we don't currently use any linked artifact anyway
    "-Wl,--gc-sections"
    "-Wl,--as-needed"
  ];
  secure.NIX_CFLAGS_COMPILE = [
    "-fstack-protector-strong"
    "-fstack-clash-protection"
    # "-fcf-protection=full" # requires extra testing before we enable
  ];
  secure.NIX_CXXFLAGS_COMPILE = secure.NIX_CFLAGS_COMPILE;
  # handing the CFLAGS back to clang/lld is basically required for -fsanitize
  secure.NIX_CFLAGS_LINK = secure.NIX_CFLAGS_COMPILE;
  march.x86_64.NIX_CFLAGS_COMPILE = [
    # DPDK functionally requires some -m flags on x86_64.
    # These features have been available for a long time and can be found on any reasonably recent machine, so just
    # enable them here for all x86_64 builds.
    "-mrtm"
    "-mcrc32"
    "-mssse3"
  ];
  march.x86_64.NIX_CXXFLAGS_COMPILE = march.x86_64.NIX_CFLAGS_COMPILE;
  march.aarch64.NIX_CFLAGS_COMPILE = [ ];
  march.aarch64.NIX_CXXFLAGS_COMPILE = march.aarch64.NIX_CFLAGS_COMPILE;
  march.aarch64.NIX_CFLAGS_LINK = [ ];
  sanitize.address.NIX_CFLAGS_COMPILE = [
    "-fsanitize=address,local-bounds"
  ];
  sanitize.address.NIX_CXXFLAGS_COMPILE = sanitize.address.NIX_CFLAGS_COMPILE;
  sanitize.address.NIX_CFLAGS_LINK = sanitize.address.NIX_CFLAGS_COMPILE ++ [
    "-static-libasan"
  ];
  sanitize.leak.NIX_CFLAGS_COMPILE = [
    "-fsanitize=leak"
  ];
  sanitize.leak.NIX_CXXFLAGS_COMPILE = sanitize.leak.NIX_CFLAGS_COMPILE;
  sanitize.leak.NIX_CFLAGS_LINK = sanitize.leak.NIX_CFLAGS_COMPILE;
  sanitize.thread.NIX_CFLAGS_COMPILE = [
    "-fsanitize=thread"
  ];
  sanitize.thread.NIX_CXXFLAGS_COMPILE = sanitize.thread.NIX_CFLAGS_COMPILE;
  sanitize.thread.NIX_CFLAGS_LINK = sanitize.thread.NIX_CFLAGS_COMPILE ++ [
    "-Wl,--allow-shlib-undefined"
  ];
  # note: cfi _requires_ LTO and is fundamentally ill suited to debug builds
  sanitize.cfi.NIX_CFLAGS_COMPILE = [
    "-fsanitize=cfi"
    # visibility=default is functionally required if you use basically any cfi higher than icall.
    # In theory we could set -fvisibility=hidden, but in practice that doesn't work because too many dependencies
    # fail to build with that setting enabled.
    # NOTE: you also want to enable -Wl,--lto-whole-program-visibility in the linker flags if visibility=default so that
    # symbols can be refined to hidden visibility at link time.
    # This "whole-program-visibility" flag is already enabled by the optimize profile, and
    # given that the optimize profile is required for cfi to even bild, we don't explicitly enable it again here.
    "-fvisibility=default"
    # required to properly link with rust
    "-fsanitize-cfi-icall-experimental-normalize-integers"
    # required in cases where perfect type strictness is not maintained but you still want to use CFI.
    # Type fudging is common in C code, especially in cases where function pointers are used with lax const correctness.
    # Ideally we wouldn't enable this, but we can't really re-write all of the C code in the world.
    "-fsanitize-cfi-icall-generalize-pointers"
  ];
  sanitize.cfi.NIX_CXXFLAGS_COMPILE = sanitize.cfi.NIX_CFLAGS_COMPILE;
  sanitize.cfi.NIX_CFLAGS_LINK = sanitize.cfi.NIX_CFLAGS_COMPILE;
  sanitize.safe-stack.NIX_CFLAGS_COMPILE = [
    "-fsanitize=safe-stack"
  ];
  sanitize.safe-stack.NIX_CXXFLAGS_COMPILE = sanitize.safe-stack.NIX_CFLAGS_COMPILE;
  sanitize.safe-stack.NIX_CFLAGS_LINK = sanitize.safe-stack.NIX_CFLAGS_COMPILE ++ [
    "-Wl,--allow-shlib-undefined"
  ];
  instrument.none.NIX_CFLAGS_COMPILE = [ ];
  instrument.none.NIX_CXXFLAGS_COMPILE = instrument.none.NIX_CFLAGS_COMPILE;
  instrument.none.NIX_CFLAGS_LINK = instrument.none.NIX_CFLAGS_COMPILE;
  instrument.produce.NIX_CFLAGS_COMPILE = [
    "-fprofile-instr-generate"
    "-fcoverage-mapping"
    "-fno-omit-frame-pointer"
  ];
  instrument.produce.NIX_CXXFLAGS_COMPILE = instrument.produce.NIX_CFLAGS_COMPILE;
  instrument.produce.NIX_CFLAGS_LINK = instrument.produce.NIX_CFLAGS_COMPILE;
  combine-profiles =
    features:
    builtins.foldl' (
      acc: elem: acc // (builtins.mapAttrs (var: val: (acc.${var} or [ ]) ++ val) elem)
    ) { } features;
  profile-map = {
    debug = combine-profiles [
      common
      debug
    ];
    release = combine-profiles [
      common
      optimize
      secure
    ];
  };
in
combine-profiles (
  [
    profile-map."${profile}"
    march."${arch}"
    instrument."${instrumentation}"
  ]
  ++ (builtins.map (s: sanitize.${s}) sanitizers)
)
