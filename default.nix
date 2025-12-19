let
  sources = import ./npins;
  profiles = import ./nix/profiles.nix;
  overlays.debug = import ./nix/overlays {
    inherit sources;
    env = profiles.debug;
  };
  overlays.release = import ./nix/overlays {
    inherit sources;
    env = profiles.release;
  };
  pkgs.debug = import sources.nixpkgs {
    overlays = [
      overlays.debug.dataplane
    ];
  };
  pkgs.release = import sources.nixpkgs {
    overlays = [
      overlays.release.dataplane
    ];
  };
in
{

}:
{
  inherit sources pkgs;
}
