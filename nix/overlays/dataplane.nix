{
  env ? { },
}:
final: prev:
let
  helpers.addToEnv =
    add: orig:
    orig
    // (
      with builtins; (mapAttrs (var: val: (toString (orig.${var} or "")) + " " + (toString val)) add)
    );
  adapt = final.stdenvAdapters;
  bintools = final.buildPackages.llvmPackages.bintools;
  lld = final.buildPackages.llvmPackages.lld;
  stdenv-llvm = adapt.addAttrsToDerivation (orig: {
    doCheck = false;
    nativeBuildInputs = (orig.nativeBuildInputs or [ ]) ++ [
      bintools
      lld
    ];
  }) (adapt.makeStaticLibraries final.buildPackages.llvmPackages.stdenv);
  stdenv-llvm-with-flags = adapt.addAttrsToDerivation (orig: {
    env = helpers.addToEnv env (orig.env or { });
  }) stdenv-llvm;
  dataplane-dep = pkg: pkg.override { stdenv = stdenv-llvm-with-flags; };
in
{
  # Don't bother adapting ethtool or iproute2's build to our custom flags / env.  Failure to null this can trigger
  # _massive_ builds because ethtool depends on libnl (et al), and we _do_ overlay libnl.  Thus, the ethtool / iproute2
  # get rebuilt and you end up rebuilding the whole world.
  #
  # To be clear, we can still use ethtool / iproute2 if we want, we just don't need to optimize / lto it.
  # If you want to include ethtool / iproute2, I recommend just cutting another small overlay and static linking them.
  # Alternatively, you could skip that and just ship the default build of ethtool.
  ethtool = null;
  iproute2 = null;

  # These are only used in docs and can make our build explode in size if we let any of this rebuild in this overlay.
  # It is much easier to just not build docs in this overlay.  We don't care if the build depends on pandoc per se, but
  # you will regret the need to rebuild ghc :shrug:
  gd = null;
  graphviz = null;
  mscgen = null;
  pandoc = null;

  # We should avoid accepting anything in our dpdk + friends pkgs which depends on udev / systemd; our deploy won't
  # support any such mechanisms.
  #
  # Usually this type of dependency takes the form of udev rules / systemd service files being generated (which is no
  # problem).  That said, builds which hard and fast depend on systemd or udev are very suspicious in this context, so
  # exceptions to this removal should be granted with care and some level of prejudice.  At minimum, such exceptions
  # tend to make it hard to cross compile which is an important test case for our sysroot.
  systemd = null;
  udev = null;
  udevCheckHook = null;

  # libmd is used by libbsd (et al) which is an optional dependency of dpdk.
  #
  # We _might_ actually care about perf here, so we lto this package.
  # At minimum, the provided functions are generally quite small and likely to benefit from inlining, so static linking
  # is a solid plan.
  libmd = (dataplane-dep prev.libmd).overrideAttrs (orig: {
    outputs = (orig.outputs or [ "out" ]) ++ [ "static" ];
    # we need to enable shared libs (in addition to static) to make dpdk's build happy. Basically, DPDK's build has no
    # means of disabling shared libraries, and it doesn't really make any sense to static link this into each .so
    # file.  Ideally we would just _not_ build those .so files, but that would require doing brain surgery on dpdk's
    # meson build, and maintaining such a change set is not worth it to avoid building some .so files.
    configureFlags = (orig.configureFlags or [ ]) ++ [
      "--enable-shared"
    ];
    postInstall = (orig.postInstall or "") + ''
      mkdir -p "$static/lib";
      mv $out/lib/*.a $static/lib;
    '';
  });

  # This is a (technically optional) dependency of DPDK used for secure string manipulation and some hashes we value;
  # static link + lto for sure.
  #
  # This is also a reasonably important target for `-fsanitize=cfi` and or `-fsanitize=safe-stack` as libbsd provides
  # more secure versions of classic C string manipulation utilities, and I'm all about that defense-in-depth.
  libbsd = (dataplane-dep prev.libbsd).overrideAttrs (orig: {
    outputs = (orig.outputs or [ "out" ]) ++ [ "static" ];
    # we need to enable shared (in addition to static) to build dpdk.
    # See the note on libmd for reasoning.
    configureFlags = orig.configureFlags ++ [
      "--enable-shared"
    ];
    postInstall = (orig.postInstall or "") + ''
      mkdir -p "$static/lib";
      mv $out/lib/*.a $static/lib;
    '';
  });
}
