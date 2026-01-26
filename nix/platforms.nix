{
  lib,
  platform,
  kernel ? "linux",
  libc,
}:
let
  platforms = rec {
    x86-64-v3 = rec {
      arch = "x86_64";
      march = "x86-64-v3";
      numa = {
        max-nodes = 8;
      };
      override = {
        stdenv.env = rec {
          NIX_CFLAGS_COMPILE = [ "-march=${march}" ];
          NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
          NIX_CFLAGS_LINK = [ ];
        };
      };
    };
    x86-64-v4 = lib.recursiveUpdate x86-64-v3 rec {
      march = "x86-64-v4";
      override.stdenv.env = rec {
        NIX_CFLAGS_COMPILE = [ "-march=${march}" ];
        NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
        NIX_CFLAGS_LINK = [ ];
      };
    };
    zen3 = lib.recursiveUpdate x86-64-v4 rec {
      march = "znver3";
      override.stdenv.env = rec {
        NIX_CFLAGS_COMPILE = [ "-march=${march}" ];
        NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
        NIX_CFLAGS_LINK = [ ];
      };
    };
    zen4 = lib.recursiveUpdate zen3 rec {
      march = "znver4";
      override.stdenv.env = rec {
        NIX_CFLAGS_COMPILE = [ "-march=${march}" ];
        NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
        NIX_CFLAGS_LINK = [ ];
      };
    };
    zen5 = lib.recursiveUpdate zen4 rec {
      march = "znver5";
      override.stdenv.env = rec {
        NIX_CFLAGS_COMPILE = [ "-march=${march}" ];
        NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
        NIX_CFLAGS_LINK = [ ];
      };
    };
    bluefield2 = rec {
      arch = "aarch64";
      march = "armv8.2-a";
      mcpu = "cortex-a72";
      numa = {
        max-nodes = 1;
      };
      override = {
        stdenv.env = rec {
          NIX_CFLAGS_COMPILE = [ "-mcpu=${mcpu}" ];
          NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
          NIX_CFLAGS_LINK = [ ];
        };
      };
    };
    bluefield3 = lib.recursiveUpdate bluefield2 rec {
      march = "armv8.4-a";
      mcpu = "cortex-a78ae";
      override.stdenv.env = rec {
        NIX_CFLAGS_COMPILE = [ "-mcpu=${mcpu}" ];
        NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
        NIX_CFLAGS_LINK = [ ];
      };
    };
  };
in
lib.fix (
  final:
  platforms.${platform}
  // {
    # NOTE: sadly, bluefield2 compiles with the name bluefield in DPDK (for some DPDK specific reason).
    # That said, we generate the correct cross compile file for bluefield2 (unlike the soc defn
    # in the dpdk meson.build file, which only goes half way and picks armv8-a instead of 8.2-a, or, better yet
    # cortex-a72, which is the actual CPU of bluefield 2).
    # We don't currently expect to meaningfully support BF2, but it is a handy test target for the build tooling.
    name =
      {
        bluefield2 = "bluefield";
      }
      .${platform} or platform;
    info =
      {
        x86_64 = {
          linux = {
            gnu = {
              target = "x86_64-unknown-linux-gnu";
              machine = "x86_64";
              nixarch = "gnu64";
              libc = "gnu";
            };
            musl = {
              target = "x86_64-unknown-linux-musl";
              machine = "x86_64";
              nixarch = "musl64";
              libc = "musl";
            };
          };
        };
        aarch64 = {
          linux = {
            gnu = {
              target = "aarch64-unknown-linux-gnu";
              machine = "aarch64";
              nixarch = "aarch64-multiplatform";
              libc = "gnu";
            };
            musl = {
              target = "aarch64-unknown-linux-musl";
              machine = "aarch64";
              nixarch = "aarch64-multiplatform-musl";
              libc = "musl";
            };
          };
        };
      }
      .${final.arch}.${kernel}.${libc};
  }
)
