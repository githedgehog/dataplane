{
  frrSrc,
  lib,
  stdenv,

  # build time
  autoreconfHook,
  bison,
  buildPackages,
  flex,
  makeWrapper,
  perl,
  pkg-config,
  python3Minimal,
  nukeReferences,
  removeReferencesTo,

  c-ares,
  elfutils,
  json_c,
  libcap,
  libxcrypt,
  libyang,
  pcre2,
  readline,
  rtrlib,
  libgccjit,

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

  # Whether this FRR source carries our vtysh extension loader, i.e. whether
  # its vtysh understands `-X <path-to-extension.so>`.  Our fork (`frr-dp`)
  # does; upstream (`frr`, used for the host image) does not, and passing it
  # `-X` would only earn us an "invalid option".  When set, the install phase
  # wraps `vtysh` so that it loads `vtysh-extension-libs` without being asked.
  vtysh-extensions ? false,

  # Extensions the `vtysh` wrapper loads, as paths in the *image*, not the nix
  # store.  Store paths are not an option here: the only extension we ship,
  # `libvtysh_hedgehog.so`, is built by `dplane-plugin`, which links against
  # this derivation.  Naming its output would be a dependency cycle.  Absolute
  # image paths are how the rest of this build already talks about FRR's own
  # runtime layout (see `--with-moduledir` and `--libdir` below), so the
  # wrapper is in good company.
  vtysh-extension-libs ? [ "/lib/libvtysh_hedgehog.so" ],

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
    nukeReferences
    removeReferencesTo
  ]
  # Conditional so that the host FRR, which gets no wrapper, keeps the exact
  # derivation it has today rather than rebuilding to reach the same bytes.
  ++ lib.optionals vtysh-extensions [ makeWrapper ];

  buildInputs = [
    c-ares
    json_c
    libcap
    libxcrypt
    libyang
    pcre2
    python3Minimal
    readline
  ]
  # libgccjit is only the carrier for libatomic.so.1 on glibc targets
  # (see the LDFLAGS comment in nix/overlays/frr.nix).  On musl FRR pulls
  # libatomic from the cross-musl gcc-libs output via `stdenv.cc.cc.lib`
  # in the overlay, so pulling libgccjit into the build closure here just
  # bloats the runtime image without contributing any symbol.
  ++ lib.optionals stdenv.hostPlatform.isGnu [ libgccjit ]
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
    "--disable-grpc"
    "--disable-protobuf"
    "--enable-scripting=no"
    "--enable-sysrepo=no"
    "--enable-zeromq=no"

    "--with-libpam=no"

    "--disable-silent-rules"
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
}
# Teach `vtysh` to load our extensions without being asked.
#
# The flag exists because our FRR fork patches vtysh to take `-X <path>`, and
# the gateway's commands live in such an extension.  Leaving the flag to the
# caller -- the shell alias the issue asked for -- only reaches callers that
# read a shell rc, and `kubectl exec` and `docker exec` do not: the alias would
# be missing in exactly the session someone opened to find out what a running
# gateway is doing.  Wrapping the binary puts the flag where every caller gets
# it, which is the guide's "make the easy path the correct path"
# (development/code/avoid-global-reasoning.md).
#
# `optionalAttrs` rather than an `optionalString` postFixup so the attribute is
# absent, not empty, when the wrapper is off: an empty `postFixup` is still an
# environment variable in the derivation, and setting one would rebuild the
# upstream host FRR to arrive at exactly the bytes it builds today.
#
# `postFixup` rather than anywhere earlier, because `preFixup` (see
# nix/overlays/frr.nix) runs `nuke-refs` over `$out`, which blanks the hash of
# any store path it finds in a file -- including the interpreter and the real
# binary that `wrapProgram` writes into the wrapper.
//
  lib.optionalAttrs vtysh-extensions {
    postFixup = ''
      wrapProgram "$out/bin/vtysh" --add-flags ${
        lib.escapeShellArg (lib.concatMapStringsSep " " (ext: "-X ${ext}") vtysh-extension-libs)
      }
    '';
  })
