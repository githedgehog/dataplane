{
  stdenv,

  sources,
  # build time
  cmake,
  dplane-rpc,
  frr,
  libyang,
  pcre2,
  protobufc,
  json_c,

  # args
  cmakeBuildType ? "Release",
  ...
}:

stdenv.mkDerivation (final: {
  pname = "dplane-plugin";
  version = sources.dplane-plugin.revision;
  src = sources.dplane-plugin.outPath;

  doCheck = false;
  doFixup = false;
  enableParallelBuilding = true;
  dontPatchElf = true;

  dontUnpack = true;

  nativeBuildInputs = [
    cmake
    dplane-rpc
    frr.dataplane
    json_c
    libyang
    pcre2
    protobufc
  ];

  configurePhase = ''
    cmake \
      -DCMAKE_BUILD_TYPE=${cmakeBuildType} \
      -DGIT_BRANCH=${sources.dplane-plugin.branch} \
      -DGIT_COMMIT=${sources.dplane-plugin.revision} \
      -DGIT_TAG=${sources.dplane-plugin.revision} \
      -DBUILD_DATE=0 \
      -DOUT=${placeholder "out"} \
      -DHH_FRR_SRC=${frr.dataplane.build}/src/frr \
      -DHH_FRR_INCLUDE=${frr.dataplane}/include/frr \
      -DCMAKE_C_STANDARD=23 \
      -S "$src"
  '';

  buildPhase = ''
    make DESTDIR="$out";
  '';

})
