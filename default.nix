let
  sources = import ./npins;
  pkgs = import sources.nixpkgs { };
in
{

}:
{
  inherit sources pkgs;
}
