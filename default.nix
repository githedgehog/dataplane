let
  sources = import ./npins;
  overlays = import ./nix/overlays {
    inherit sources;
  };
  pkgs = import sources.nixpkgs {
    overlays = [
      overlays.dataplane
    ];
  };
in
{

}:
{
  inherit sources pkgs;
}
