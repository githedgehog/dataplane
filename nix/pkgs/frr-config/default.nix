{
  stdenv,
  ...
}:

stdenv.mkDerivation {
  pname = "frr-config";
  version = "0";

  doCheck = false;
  enableParallelBuilding = true;
  dontPatchShebangs = true;

  dontUnpack = true;

  src = ./config;

  installPhase = ''
    cp -r $src $out
    chmod +x $out/libexec/frr/docker-start
  '';

}
