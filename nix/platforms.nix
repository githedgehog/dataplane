{
  lib,
  platform,
  kernel ? "linux",
  libc,
}:
let
  hardware = import ./hardware.nix { inherit lib; };
  triples = import ./triples.nix;
in
lib.fix (
  final:
  hardware.${platform}
  // {
    name =
      {
        # NOTE: sadly, bluefield2 compiles with the name bluefield in DPDK (for some DPDK specific reason).
        # That said, we generate the correct cross compile file for bluefield2 (unlike the soc defn
        # in the dpdk meson.build file, which only goes half way and picks armv8-a instead of 8.2-a, or, better yet
        # cortex-a72, which is the actual CPU of bluefield 2).
        # We don't currently expect to meaningfully support BF2, but it is a handy test target for the build tooling.
        bluefield2 = "bluefield";
        # aarch64 is marked as "generic" in DPDK to distinguish from more specific SOCs, but we use "aarch64" for
        # consistency with other platforms.  Need to map here tho.
        aarch64 = "generic";
      }
      .${platform} or platform;
    info = triples.${final.arch}.${kernel}.${libc};
  }
)
