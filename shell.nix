{ default ? import ./default.nix {},
  nixpkgs ? default.nixpkgs,
}: default.shell.env