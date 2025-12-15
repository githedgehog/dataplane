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
in
{

}
