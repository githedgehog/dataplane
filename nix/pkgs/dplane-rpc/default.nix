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

  # workaround: cpmock.c uses memset/strcpy/strerror/memcmp without including
  # <string.h>.  glibc transitively exposes those declarations through
  # unrelated system headers; musl's header layout doesn't, so the compile
  # fails with `call to undeclared library function 'memset'` under -std=c23.
  # remove once fixed upstream in githedgehog/dplane-rpc.
  postPatch = ''
    sed -i '1i#include <string.h>' clib/bin/cpmock.c
  '';

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
