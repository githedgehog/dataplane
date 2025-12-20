{
  lib ? (import <nixpkgs> { }).lib,
}:
rec {
  x86-64-v3 = rec {
    arch = "x86_64";
    march = "x86-64-v3";
    numa = {
      max-nodes = 8;
    };
    override = {
      stdenv'.env = rec {
        NIX_CFLAGS_COMPILE = [ "-march=${march}" ];
        NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
        NIX_CFLAGS_LINK = [ ];
      };
      dpdk = {
        buildInputs = {
          rdma-core = true;
          libbsd = true;
          libnl = true;
          numactl = true;
        };
      };
    };
  };
  x86-64-v4 = lib.recursiveUpdate x86-64-v3 rec {
    march = "x86-64-v4";
    override.stdenv'.env = rec {
      NIX_CFLAGS_COMPILE = [ "-march=${march}" ];
      NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
      NIX_CFLAGS_LINK = [ ];
    };
  };
  zen4 = lib.recursiveUpdate x86-64-v4 rec {
    march = "zen4";
    override.stdenv'.env = rec {
      NIX_CFLAGS_COMPILE = [ "-march=${march}" ];
      NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
      NIX_CFLAGS_LINK = [ ];
    };
  };
  zen5 = lib.recursiveUpdate zen4 rec {
    march = "zen5";
    override.stdenv'.env = rec {
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
      stdenv'.env = rec {
        NIX_CFLAGS_COMPILE = [ "-mcpu=${mcpu}" ];
        NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
        NIX_CFLAGS_LINK = [ ];
      };
      dpdk = {
        buildInputs = {
          rdma-core = true;
          libbsd = true;
          libnl = true;
          numactl = false;
        };
      };
    };
  };
  bluefield3 = lib.recursiveUpdate bluefield2 rec {
    march = "armv8.4-a";
    mcpu = "cortex-a78ae";
    override.stdenv'.env = rec {
      NIX_CFLAGS_COMPILE = [ "-mcpu=${mcpu}" ];
      NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
      NIX_CFLAGS_LINK = [ ];
    };
  };
}
