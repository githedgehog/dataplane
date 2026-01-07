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
    bluefield3 = rec {
      arch = "aarch64";
      march = "armv8.4-a";
      mcpu = "cortex-a78ae";
      numa = {
        max-nodes = 1;
      };
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
    name = platform;
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
