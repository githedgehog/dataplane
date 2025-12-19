{
  stdenv,
  dpdk,
  libbsd,
}:
stdenv.mkDerivation {
  pname = "dpdk-wrapper";
  version = dpdk.version;

  src = ./src;

  nativeBuildInptus = [
    dpdk
    libbsd
  ];

  outputs = [
    "dev"
    "out"
  ];

  # DPDK marks all experimental apis as deprecated, but we wish to wrap such apis as well. Thus, turn off deprecation
  # warnings.
  CFLAGS = [ "-Wno-deprecated-declarations" ];

  buildPhase = ''
    set euxo pipefail
    mkdir -p $dev/include $out/lib
    $CC $CFLAGS -I${dpdk}/include -I${libbsd.dev}/include -c $src/dpdk_wrapper.c -o wrapper.o;
    $AR rcs $out/lib/libdpdk_wrapper.a wrapper.o;
    $RANLIB $out/lib/libdpdk_wrapper.a;
    cp $src/*.h $dev/include
  '';

}
