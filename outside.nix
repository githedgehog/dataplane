{
  pkgs ? import <nixpkgs> {},
  overlays ? import ./nix/overlays.nix { build-flags = (import ./nix/flags.nix).release; },
}: {
    muslEnv = (import pkgs.path {
      overlays = [
        (self: prev: {
          pkgsCross.musl64 = import prev.path {
            overlays = builtins.attrValues (overlays {
              targetPlatform = prev.pkgsCross.musl64.stdenv.targetPlatform;
            });
          };
        })
      ];
    }).pkgsCross.musl64;

    gnuEnv = (import pkgs.path {
      overlays = [
        (self: prev: {
          pkgsCross.gnu64 = import prev.path {
            overlays = builtins.attrValues (overlays {
              targetPlatform = prev.pkgsCross.gnu64.stdenv.targetPlatform;
            });
          };
        })
      ];
    }).pkgsCross.gnu64;
}
