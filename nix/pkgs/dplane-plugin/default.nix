{
  stdenv,
  fetchFromGitHub,

  # build time
  cmake,
  dplane-rpc,
  frr,
  libyang,
  pcre2,
  protobufc,
  json_c,

  rev,
  hash,
  commit_date,

  # args
  cmakeBuildType ? "Release",
}:

stdenv.mkDerivation (final: {
  pname = "dplane-plugin";
  version = rev;

  doCheck = false;
  doFixup = false;
  enableParallelBuilding = true;
  dontPatchElf = true;

  dontUnpack = true;

  src = fetchFromGitHub {
    owner = "githedgehog";
    repo = final.pname;
    inherit rev hash;
  };

  nativeBuildInputs = [
    cmake
    dplane-rpc
    frr
    json_c
    libyang
    pcre2
    protobufc
  ];

  configurePhase = ''
    cmake \
      -DCMAKE_BUILD_TYPE=${cmakeBuildType} \
      -DGIT_BRANCH=${rev} \
      -DGIT_COMMIT=${rev} \
      -DGIT_TAG=${rev} \
      -DBUILD_DATE=${commit_date} \
      -DOUT=${placeholder "out"} \
      -DHH_FRR_SRC=${frr.build}/src/frr \
      -DHH_FRR_INCLUDE=${frr}/include/frr \
      -DCMAKE_C_STANDARD=23 -S $src
  '';

  buildPhase = ''
    make DESTDIR="$out";
  '';

})
