{
  sources,
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

  # This is (for better or worse) used by dpdk to parse / manipulate netlink messages.
  #
  # We don't care about performance here, so this may be a good candidate for size reduction compiler flags like -Os.
  #
  # That said, we don't currently have infrastructure to pass flags at a per package level and building that is more
  # trouble than a minor reduction in binary size / instruction cache pressure is likely worth. Also, lto doesn't
  # currently love size optimizations.  The better option is likely to use PGO + BOLT to put these functions far away
  # from the hot path in the final ELF file's layout and just ignore that this stuff is compiled with -O3 and friends.
  #
  # More, this is a very low level library designed to send messages between a privileged process and the kernel.
  # The simple fact that this appears in our toolchain justifies sanitizers like safe-stack and cfi and/or flags like
  # -fcf-protection=full.
  libnl = dataplane-dep prev.libnl;

  # This is needed by DPDK in order to determine which pinned core runs on which numa node and which NIC is most
  # efficiently connected to which NUMA node.  You can disable the need for this library entirely by editing dpdk's
  # build to specify `-Dmax_numa_nodes=1`.
  #
  # While we don't currently hide NUMA mechanics from DPDK, there is something to be said for eliminating this library
  # from our toolchain as a fair level of permissions and a lot of different low level trickery is required to make it
  # function.  In "the glorious future" we should bump all of this logic up to the dataplane's init process, compute
  # what we need to, pre-mmap _all_ of our heap memory, configure our cgroups and CPU affinities, and then pin our cores
  # and use memory pools local to the numa node of the pinned core.  That would be a fair amount of work, but it would
  # liminate a fairly large dependency and likely increase the performance and security of the dataplane.
  #
  # For now, we leave this on so DPDK can do some of that for us.  That said, this logic is quite cold and would ideally
  # be size optimized and punted far from all hot paths.  BOLT should be helpful here.
  numactl = (dataplane-dep prev.numactl).overrideAttrs (orig: {
    outputs = (prev.lib.lists.remove "man" orig.outputs) ++ [ "static" ];
    # we need to enable shared (in addition to static) to build dpdk.
    # See the note on libmd for reasoning.
    configureFlags = (orig.configureFlags or [ ]) ++ [
      "--enable-shared" # dpdk does not like to build its .so files if we don't build numa.so as well
    ];
    postInstall = (orig.postInstall or "") + ''
      mkdir -p "$static/lib";
      mv $out/lib/*.a $static/lib;
    '';
  });

  # This is one of the two most important to optimize components of the whole build (along with dpdk itself).
  #
  # RDMA-core is the low level building block for many of the PMDs within DPDK including the mlx5 PMD.  It is a
  # performance and security critical library which we will likely never be able to remove from our dependencies.
  #
  # Some of this library is almost always called in a very tight loop, especially as used by DPDK PMDs.  It is happy to
  # link dynamically or statically, and we should make a strong effort to make sure that we always pick static linking
  # to enable inlining (wherever the compiler decides it makes sense).  You very likely want to enable lto here in any
  # release build.
  rdma-core = (dataplane-dep prev.rdma-core).overrideAttrs (orig: {
    version = sources.rdma-core.branch;
    src = sources.rdma-core.outPath;
    outputs = [
      "dev"
      "out"
      "static"
    ];
    cmakeFlags = orig.cmakeFlags ++ [
      "-DENABLE_STATIC=1"
      # we don't need pyverbs, and turning it off reduces build time / complexity.
      "-DNO_PYVERBS=1"
      # no need for docs in container images.
      "-DNO_MAN_PAGES=1"
      # we don't care about this lib's exported symbols / compat situation _at all_ because we static link (which
      # doesn't even have symbol versioning / compatibility in the first place).  Turning this off just reduces the
      # build's internal complexity and makes lto easier.
      "-DNO_COMPAT_SYMS=1"
    ];
    postInstall = (orig.postInstall or "") + ''
      mkdir -p $static/lib;
      mv $out/lib/*.a $static/lib/
    '';
  });

  # Compiling DPDK is the primary objective of this overlay.
  #
  # We care _a lot_ about how this is compiled and should always use flags which are either optimized for performance
  # or debugging.  After all, if you aren't doing something performance critical then I don't know why you want DPDK at
  # all :)
  #
  # Also, while this library has a respectable security track record, this is also a super strong candidate for
  # cfi, safe-stack, and cf-protection.
  dpdk = dataplane-dep (final.callPackage ../pkgs/dpdk { src = sources.dpdk; });

  # DPDK is largely composed of static-inline functions.
  # We need to wrap those functions with "_w" variants so that we can actually call them from rust.
  #
  # This wrapping process does not really cause any performance issue due to lto; the compiler is going to "unwrap"
  # these methods anyway.
  dpdk-wrapper = dataplane-dep (final.callPackage ../pkgs/dpdk-wrapper { });
}
