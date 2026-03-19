{
  stdenv,

  # build time
  sources,
  cmake,

  # args
  cmakeBuildType ? "Release",
  ...
}:

stdenv.mkDerivation
(finalAttrs: {
  pname = "dplane-rpc";
  version = sources.dplane-rpc.revision;
  src = sources.dplane-rpc.outPath;

  doCheck = false;
  enableParallelBuilding = true;

  outputs = ["out" "dev"];

  nativeBuildInputs = [
    cmake
  ];

  configurePhase = ''
    cmake \
      -DCMAKE_BUILD_TYPE=${cmakeBuildType} \
      -DCMAKE_C_STANDARD=23 \
      -S ./clib .
  '';

  buildPhase = ''
    make DESTDIR="$out";
  '';

  installPhase = ''
    make DESTDIR="$out" install;
    mv $out/usr/local/* $out
    rmdir $out/usr/local

    mv $out/usr/include $out/include
    rmdir $out/usr
  '';

})
