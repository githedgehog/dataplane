# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  arch,
  profile,
  sanitizers,
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
  secure.NIX_CFLAGS_COMPILE = [
    "-fstack-protector-strong"
    "-fstack-clash-protection"
    # we always want pic/pie and GOT offsets should be computed at compile time whenever possible
    "-Wl,-z,relro,-z,now"
    # "-fcf-protection=full" # requires extra testing before we enable
  ];
  secure.NIX_CXXFLAGS_COMPILE = secure.NIX_CFLAGS_COMPILE;
  # handing the CFLAGS back to clang/lld is basically required for -fsanitize
  secure.NIX_CFLAGS_LINK = secure.NIX_CFLAGS_COMPILE;
  secure.RUSTFLAGS = [
    "-Crelro-level=full"
    # "-Zcf-protection=full"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") secure.NIX_CFLAGS_LINK);
  march.x86_64.NIX_CFLAGS_COMPILE = [
    # DPDK functionally requires some -m flags on x86_64.
    # These features have been available for a long time and can be found on any reasonably recent machine, so just
    # enable them here for all x86_64 builds.
    # In the (very) unlikely event that you need to edit these flags, also edit the associated RUSTFLAGS to match.
    "-mrtm" # TODO: try to convince DPDK not to rely on rtm
    "-mcrc32"
    "-mssse3"
  ];
  march.x86_64.NIX_CXXFLAGS_COMPILE = march.x86_64.NIX_CFLAGS_COMPILE;
  march.x86_64.NIX_CFLAGS_LINK = march.x86_64.NIX_CXXFLAGS_COMPILE;
  march.x86_64.RUSTFLAGS = [
    # Ideally these should be kept in 1:1 alignment with the x86_64 NIX_CFLAGS_COMPILE settings.
    # That said, rtm and crc32 are only kinda supported by rust, and rtm is functionally deprecated anyway, so we should
    # try to remove DPDK's insistence on it.  We are absolutely not using hardware memory transactions anyway; they
    # proved to be broken in Intel's implementation, and AMD never built them in the first place.
    # "-Ctarget-feature=+rtm,+crc32,+ssse3"
    "-Ctarget-feature=+ssse3"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") march.x86_64.NIX_CFLAGS_LINK);
  march.aarch64.NIX_CFLAGS_COMPILE = [ ];
  march.aarch64.NIX_CXXFLAGS_COMPILE = march.aarch64.NIX_CFLAGS_COMPILE;
  march.aarch64.NIX_CFLAGS_LINK = [ ];
  march.aarch64.RUSTFLAGS = [ ] ++ (map (flag: "-Clink-arg=${flag}") march.aarch64.NIX_CFLAGS_LINK);
  sanitize.address.NIX_CFLAGS_COMPILE = [
    "-fsanitize=address,local-bounds"
  ];
  sanitize.address.NIX_CXXFLAGS_COMPILE = sanitize.address.NIX_CFLAGS_COMPILE;
  sanitize.address.NIX_CFLAGS_LINK = sanitize.address.NIX_CFLAGS_COMPILE ++ [
    "-static-libasan"
  ];
  sanitize.address.RUSTFLAGS = [
    "-Zsanitizer=address"
    "-Zexternal-clangrt"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.address.NIX_CFLAGS_LINK);
  sanitize.leak.NIX_CFLAGS_COMPILE = [
    "-fsanitize=leak"
  ];
  sanitize.leak.NIX_CXXFLAGS_COMPILE = sanitize.leak.NIX_CFLAGS_COMPILE;
  sanitize.leak.NIX_CFLAGS_LINK = sanitize.leak.NIX_CFLAGS_COMPILE;
  sanitize.leak.RUSTFLAGS = [
    "-Zsanitizer=leak"
    "-Zexternal-clangrt"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.leak.NIX_CFLAGS_LINK);
  sanitize.thread.NIX_CFLAGS_COMPILE = [
    "-fsanitize=thread"
  ];
  sanitize.thread.NIX_CXXFLAGS_COMPILE = sanitize.thread.NIX_CFLAGS_COMPILE;
  sanitize.thread.NIX_CFLAGS_LINK = sanitize.thread.NIX_CFLAGS_COMPILE ++ [
    "-Wl,--allow-shlib-undefined"
  ];
  sanitize.thread.RUSTFLAGS = [
    "-Zsanitizer=thread"
    "-Zexternal-clangrt"
    # gimli doesn't like thread sanitizer, but it shouldn't be an issue since that is all build time logic
    "-Cunsafe-allow-abi-mismatch=sanitizer"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.thread.NIX_CFLAGS_LINK);
  # note: cfi _requires_ LTO and is fundamentally ill suited to debug builds
  sanitize.cfi.NIX_CFLAGS_COMPILE = [
    "-fsanitize=cfi"
    # visibility=default is functionally required if you use basically any cfi higher than icall.
    # In theory we could set -fvisibility=hidden, but in practice that doesn't work because too many dependencies
    # fail to build with that setting enabled.
    # NOTE: you also want to enable -Wl,--lto-whole-program-visibility in the linker flags if visibility=default so that
    # symbols can be refined to hidden visibility at link time.
    # This "whole-program-visibility" flag is already enabled by the optimize profile, and
    # given that the optimize profile is required for cfi to even build, we don't explicitly enable it again here.
    "-fvisibility=default"
    # required to properly link with rust
    "-fsanitize-cfi-icall-experimental-normalize-integers"
    # required in cases where perfect type strictness is not maintained but you still want to use CFI.
    # Type fudging is common in C code, especially in cases where function pointers are used with lax const correctness.
    # Ideally we wouldn't enable this, but we can't really re-write all of the C code in the world.
    "-fsanitize-cfi-icall-generalize-pointers"
    # "-fsanitize-cfi-cross-dso"
    "-fsplit-lto-unit" # important for compatibility with rust's LTO
  ];
  sanitize.cfi.NIX_CXXFLAGS_COMPILE = sanitize.cfi.NIX_CFLAGS_COMPILE;
  sanitize.cfi.NIX_CFLAGS_LINK = sanitize.cfi.NIX_CFLAGS_COMPILE;
  sanitize.cfi.RUSTFLAGS = [
    "-Zsanitizer=cfi"
    "-Zsanitizer-cfi-normalize-integers"
    "-Zsanitizer-cfi-generalize-pointers"
    # "-Zsanitizer-cfi-cross-dso"
    "-Zsplit-lto-unit"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.cfi.NIX_CFLAGS_LINK);
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
      secure
    ];
  };
in
combine-profiles (
  [
    profile-map."${profile}"
    march."${arch}"
  ]
  ++ (map (s: sanitize.${s}) sanitizers)
)
