{
  frrSrc,
  lib,
  stdenv,

  # build time
  autoreconfHook,
  bison,
  buildPackages,
  flex,
  perl,
  pkg-config,
  python3Minimal,

  c-ares,
  elfutils,
  json_c,
  libcap,
  libxcrypt,
  libyang,
  pcre2,
  readline,
  rtrlib,
  # xz,
  libgccjit,

  # tests
  nixosTests,

  # other general options besides snmp support
  numMultipath ? 8,

  # routing daemon options
  bgpdSupport ? true,
  bfddSupport ? true,
  staticdSupport ? true,
  ospfdSupport ? false,
  isisdSupport ? false,

  babeldSupport ? false,
  eigrpdSupport ? false,
  fabricdSupport ? false,
  ldpdSupport ? false,
  nhrpdSupport ? false,
  ospf6dSupport ? false,
  pathdSupport ? false,
  pbrdSupport ? false,
  pim6dSupport ? false,
  pimdSupport ? false,
  ripdSupport ? false,
  ripngdSupport ? false,
  sharpdSupport ? false,
  vrrpdSupport ? false,

  # BGP options
  bgpAnnounce ? true,
  bgpBmp ? true,
  bgpVnc ? false,
  bgpRpki ? false,

  # OSPF options
  ospfApi ? false,

  vtysh-extensions ? false,

  ...
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "frr";
  version = frrSrc.branch;
  dontPatchShebangs = false;
  dontFixup = false;
  dontPatchElf = false;

  outputs = [
    "out"
    "build"
  ];

  src = frrSrc.outPath;

  # Without the std explicitly set, we may run into abseil-cpp
  # compilation errors.
  CXXFLAGS = "-std=gnu++23";

  nativeBuildInputs = [
    autoreconfHook
    bison
    elfutils
    flex
    perl
    pkg-config
    python3Minimal
  ];

  buildInputs = [
    c-ares
    json_c
    libcap
    libgccjit
    libxcrypt
    libyang
    pcre2
    python3Minimal
    readline
  ]
  ++ lib.optionals bgpRpki [ rtrlib ];

  # cross-compiling: clippy is compiled with the build host toolchain, split it out to ease
  # navigation in dependency hell
  clippy-helper = buildPackages.callPackage ./clippy-helper.nix {
    inherit frrSrc;
  };

  configureFlags = [
    "--enable-python-runtime"
    "--enable-fpm=netlink" # try to disable later
    "--with-moduledir=/lib/frr/modules"
    # rpath causes confusion in module linking where bmp gets linked to /build (which is broken).
    # dontPatchElf and dontFixup are both set to false, so nix will adjust to rpath correctly for us after
    # the initial linking step.
    "--enable-rpath=no"

    "--enable-configfile-mask=0640"
    "--enable-logfile-mask=0640"
    "--enable-user=frr"
    "--enable-group=frr"
    "--enable-vty-group=frrvty"

    "--enable-config-rollbacks=no"
    "--disable-doc"
    "--disable-doc-html"
    "--enable-grpc=no"
    "--enable-protobuf=no"
    "--enable-scripting=no"
    "--enable-sysrepo=no"
    "--enable-zeromq=no"

    "--with-libpam=no"

    "--disable-silent-rules"
    "--enable-configfile-mask=0640"
    "--enable-logfile-mask=0640"
    "--enable-multipath=${toString numMultipath}"
    "--localstatedir=/run/frr"
    "--includedir=/include"
    "--sbindir=/libexec/frr"
    "--bindir=/bin"
    "--libdir=/lib"
    "--prefix=/frr"
    "--sysconfdir=/etc"
    "--with-clippy=${finalAttrs.clippy-helper}/bin/clippy"
    # general options
    "--enable-irdp=no"
    "--enable-mgmtd=yes"
    "--enable-rtadv=yes"
    "--enable-watchfrr=yes"

    "--enable-shared"
    "--enable-static"
    "--enable-static-bin"

    # routing protocols
    (lib.strings.enableFeature babeldSupport "babeld")
    (lib.strings.enableFeature bfddSupport "bfdd")
    (lib.strings.enableFeature bgpdSupport "bgpd")
    (lib.strings.enableFeature eigrpdSupport "eigrpd")
    (lib.strings.enableFeature fabricdSupport "fabricd")
    (lib.strings.enableFeature isisdSupport "isisd")
    (lib.strings.enableFeature ldpdSupport "ldpd")
    (lib.strings.enableFeature nhrpdSupport "nhrpd")
    (lib.strings.enableFeature ospf6dSupport "ospf6d")
    (lib.strings.enableFeature ospfdSupport "ospfd")
    (lib.strings.enableFeature pathdSupport "pathd")
    (lib.strings.enableFeature pbrdSupport "pbrd")
    (lib.strings.enableFeature pim6dSupport "pim6d")
    (lib.strings.enableFeature pimdSupport "pimd")
    (lib.strings.enableFeature ripdSupport "ripd")
    (lib.strings.enableFeature ripngdSupport "ripngd")
    (lib.strings.enableFeature sharpdSupport "sharpd")
    (lib.strings.enableFeature staticdSupport "staticd")
    (lib.strings.enableFeature vrrpdSupport "vrrpd")
    # BGP options
    (lib.strings.enableFeature bgpAnnounce "bgp-announce")
    (lib.strings.enableFeature bgpBmp "bgp-bmp")
    (lib.strings.enableFeature bgpRpki "rpki")
    (lib.strings.enableFeature bgpVnc "bgp-vnc")
    # OSPF options
    (lib.strings.enableFeature ospfApi "ospfapi")
    # Cumulus options
    "--enable-cumulus=no"
    "--disable-cumulus"
  ];

  patches = [
    ./patches/yang-hack.patch
    ./patches/xrelifo.py.fix.patch
  ]
  ++ lib.optionals vtysh-extensions [
    ./patches/vtysh-extensions.h.patch
  ];

  buildPhase = ''
    make "-j$(nproc)";
  '';

  installPhase = ''
    make DESTDIR=$out install;
    mkdir -p $build/src/
    cp -r . $build/src/frr
  '';

  doCheck = false;

  enableParallelBuilding = true;

  passthru.tests = { inherit (nixosTests) frr; };
})
