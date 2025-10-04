{
  pkgs ? import <nixpkgs> { },
}:
(pkgs.mkShell {
  # name = "dataplane-shell";
  buildInputs = (
    with pkgs;
    [
      # dev tools
      bash
      direnv
      just
      nil
      nixd
      wget
    ]
  );
})
