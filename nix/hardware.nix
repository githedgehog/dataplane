{
  lib,
}:
rec {
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
  aarch64 = rec {
    arch = "aarch64";
    march = "generic";
    numa = {
      max-nodes = 8;
    };
    override = {
      stdenv.env = rec {
        NIX_CFLAGS_COMPILE = [ ];
        NIX_CXXFLAGS_COMPILE = NIX_CFLAGS_COMPILE;
        NIX_CFLAGS_LINK = [ ];
      };
    };
  };
  bluefield2 = lib.recursiveUpdate aarch64 rec {
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
  wasm32-wasip1 = {
    arch = "wasm32";
    march = "wasm32";
    override.stdenv.env = { };
  };
}
