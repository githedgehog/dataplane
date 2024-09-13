{
  pkgs ? import <nixpkgs> { },
}: rec {

  project-name = "hedgehog-dataplane";

  inherit pkgs;

  mdbook-citeproc = import ./nix/mdbook-citeproc.nix (with pkgs; {
  	inherit lib stdenv fetchFromGitHub rustPlatform CoreServices;
  });

  mdbook-alerts = import ./nix/mdbook-alerts.nix (with pkgs; {
	inherit lib stdenv fetchFromGitHub rustPlatform CoreServices;
  });

  buildDeps = pkgs: (with pkgs; [
    bash
    bash-completion
    coreutils
    git
    mdbook
    mdbook-admonish
    mdbook-katex
    mdbook-mermaid
    mdbook-plantuml
    pandoc # needed for mdbook-citeproc to work (runtime exe dep)
    plantuml # needed for mdbook-plantuml to work (runtime exe dep)
  ]) ++ [
    mdbook-citeproc
    mdbook-alerts
  ];

  shell = pkgs.buildFHSUserEnv {
    name = "${project-name}-shell";
    targetPkgs = buildDeps;
  };

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
