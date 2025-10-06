{
  pkgs ? import <nixpkgs> { },
}:
(pkgs.buildFHSEnv {
  name = "dataplane-shell";
  targetPkgs =
    pkgs:
    (with pkgs; [
      # dev tools
      bash
      direnv
      just
      mermaid-cli.out
      nil
      nixd
      wget
    ]);
}).env
