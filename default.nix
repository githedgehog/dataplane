{
  pkgs ? import <nixpkgs> { },
}: rec {
  project-name = "hedgehog-dataplane";
  inherit pkgs;
  mdbook-alerts = pkgs.callPackage import ./nix/mdbook-alerts.nix {};
  buildDeps = pkgs: (with pkgs; [
    bash
    coreutils
    git
    mdbook
    mdbook-katex
    mdbook-mermaid
    mdbook-plantuml
    plantuml # needed for mdbook-plantuml to work (runtime exe dep)
  ]) ++ [
    mdbook-alerts
  ];
  design-docs = pkgs.stdenv.mkDerivation {
    name = "${project-name}-design-docs";
    src = ./design-docs/src/mdbook;
    buildInputs = buildDeps pkgs;
    buildPhase = ''
      set -euo pipefail;
      rm --force --recursive book;
      mdbook build;
    '';
    installPhase = ''
      set -euo pipefail;
      cp -a book $out;
    '';
  };
}
