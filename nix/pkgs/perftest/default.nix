{
  src,
  stdenv,
  rdma-core,
  autoreconfHook,
  pciutils,
  ...
}:
stdenv.mkDerivation (final: {
  pname = "perftest";
  version = src.revision;
  src = src.outPath;
  nativeBuildInputs = [
    autoreconfHook
  ];
  buildInputs = [
    pciutils
    rdma-core
  ];
})
