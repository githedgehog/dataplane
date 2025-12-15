{
  sources,
}:
{
  dataplane = import ./dataplane.nix {
    inherit sources;
    env = { };
  };
}
