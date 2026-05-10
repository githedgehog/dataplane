{
  stdenv,

  sources,
  # build time
  cmake,
  dplane-rpc,
  frr,
  libyang,
  pcre2,
  json_c,

  # args
  cmakeBuildType ? "Release",
  ...
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "dplane-plugin";
  version = sources.dplane-plugin.revision;
  src = sources.dplane-plugin.outPath;

  # workaround: src/hh_dp_msg.c reaches into a glibc-internal anonymous
  # union name (`.__in6_u.__u6_addr8`) on struct in6_addr.  musl exposes
  # the POSIX-standard `.s6_addr` member directly without that wrapping
  # union, so the access fails to compile.
  # remove once fixed upstream in githedgehog/dplane-plugin.
  postPatch = ''
    sed -i 's/\.__in6_u\.__u6_addr8/.s6_addr/g' src/hh_dp_msg.c
  '';

  doCheck = false;
  doFixup = false;
  enableParallelBuilding = true;

  nativeBuildInputs = [
    cmake
  ];

  buildInputs = [
    dplane-rpc
    frr.dataplane
    json_c
    libyang
    pcre2
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
      -S .
  '';

  buildPhase = ''
    make DESTDIR="$out";
  '';

})
