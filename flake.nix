{
  description = "Hedgehog dataplane";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:

    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        default = import ./default.nix { inherit pkgs; };
      in
      {
        devShell = default.shell;
        packages.design-docs = default.design-docs;
      }
    );
}
