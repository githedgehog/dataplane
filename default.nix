{
  overlay ? "dataplane",
  target ? "x86_64-unknown-linux-gnu",
  prof ? "debug",
}:
let
  arch =
    {
      "x86_64-unknown-linux-gnu" = {
        target = "x86_64-unknown-linux-gnu";
        machine = "x86_64";
        nixarch = "gnu64";
        libc = "gnu";
      };
      "x86_64-unknown-linux-musl" = {
        target = "x86_64-unknown-linux-musl";
        machine = "x86_64";
        nixarch = "musl64";
        libc = "musl";
      };
      "aarch64-unknown-linux-gnu" = {
        target = "aarch64-unknown-linux-gnu";
        machine = "aarch64";
        nixarch = "aarch64-multiplatform";
        libc = "glibc";
      };
      "aarch64-unknown-linux-musl" = {
        target = "aarch64-unknown-linux-musl";
        machine = "aarch64";
        nixarch = "aarch64-multiplatform-musl";
        libc = "musl";
      };
    }
    .${target};
  sources = import ./npins;
  profile = import ./nix/profiles.nix {
    inherit prof;
    arch = arch.machine;
  };
  overlays = import ./nix/overlays {
    inherit sources;
    env = profile;
  };
  pkgs = import sources.nixpkgs {
    overlays = [
      overlays.${overlay}
    ];
  };
in
{
  inherit sources;
  pkgs = pkgs.pkgsCross.${arch.nixarch};
}
