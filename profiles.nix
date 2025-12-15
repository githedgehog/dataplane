let
  common.NIX_CFLAGS_COMPILE = [
    "-glldb"
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
  debug.NIX_CFLAGS_COMPILE = [
    "-fno-inline"
    "-fno-omit-frame-pointer"
    "-D_FORTIFY_SOURCE=0" # disable security stuff because the goal is to make the asm as easy to understand as possible
    "-Wno-macro-redefined" # many apps opt in to _FORTIFY_SOURCE={1,2,3} explicitly, and -Wall errors when you redefine
  ];
  debug.NIX_CXXFLAGS_COMPILE = debug.NIX_CFLAGS_COMPILE;
  debug.NIX_CFLAGS_LINK = [ ];
  optimize.NIX_CFLAGS_COMPILE = [
    "-O3"
    "-flto=full"
    "-fsplit-lto-unit" # important for compatibility with rust's LTO
  ];
  optimize.NIX_CXXFLAGS_COMPILE = optimize.NIX_CFLAGS_COMPILE ++ [
    "-fwhole-program-vtables"
  ];
  optimize.NIX_CFLAGS_LINK = [
    "-flto=full"
    "-Wl,--lto-whole-program-visibility"
    # just to keep the artifacts small, we don't currently use any linked artifact anyway
    "-Wl,--gc-sections"
    "-Wl,--as-needed"
  ];
  secure.NIX_CFLAGS_COMPILE = [
    "-fstack-protector-strong"
    "-fstack-clash-protection"
    # "-fcf-protection=full" # requires extra testing before we enable
    # "-fsanitize=safe-stack" # requires extra testing before we enable (not compatible with musl)
    # "-fsanitize=cfi" # requires extra testing before we enable
    # enable if you turn on cfi to properly link with rust
    # "-fsanitize-cfi-icall-experimental-normalize-integers"
    # consider enabling if you turn on cfi (not compatible with cross DSO cfi)
    # "-fsanitize-cfi-icall-generalize-pointers"
  ];
  secure.NIX_CXXFLAGS_COMPILE = secure.NIX_CFLAGS_COMPILE;
  # handing the CFLAGS back to clang/lld is basically required for -fsanitize
  secure.NIX_CFLAGS_LINK = secure.NIX_CFLAGS_COMPILE;
  combine-profiles =
    features:
    builtins.foldl' (
      acc: elem: builtins.mapAttrs (var: val: (acc.${var} or [ ]) ++ val) elem
    ) { } features;
in
{
  debug = combine-profiles [
    common
    debug
  ];
  release = combine-profiles [
    common
    optimize
    secure
  ];
}
