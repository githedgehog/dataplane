# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  sanitizers,
  ...
}:
final: prev:
let
  dataplane-dep = pkg: pkg.override { stdenv = final.stdenv'; };
in
{
  # libmd is used by libbsd (et al) which is an optional dependency of dpdk.
  #
  # We _might_ actually care about perf here, so we lto this package.
  # At minimum, the provided functions are generally quite small and likely to benefit from inlining, so static linking
  # is a solid plan.
  fancy.libmd = (dataplane-dep prev.libmd).overrideAttrs (orig: {
    outputs = (orig.outputs or [ "out" ]) ++ [
      "man"
      "dev"
      "static"
    ];
    # we need to enable shared libs (in addition to static) to make dpdk's build happy. Basically, DPDK's build has no
    # means of disabling shared libraries, and it doesn't really make any sense to static link this into each .so
    # file.  Ideally we would just _not_ build those .so files, but that would require doing brain surgery on dpdk's
    # meson build, and maintaining such a change set is not worth it to avoid building some .so files.
    configureFlags = (orig.configureFlags or [ ]) ++ [
      "--enable-static"
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
  fancy.libbsd =
    ((dataplane-dep prev.libbsd).override { libmd = final.fancy.libmd; }).overrideAttrs
      (orig: {
        outputs = (orig.outputs or [ "out" ]) ++ [ "static" ];
        # we need to enable shared (in addition to static) to build dpdk.
        # See the note on libmd for reasoning.
        configureFlags = orig.configureFlags ++ [
          "--enable-static"
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
  fancy.libnl = (dataplane-dep prev.libnl).overrideAttrs (orig: {
    outputs = (orig.outputs or [ "out" ]) ++ [ "static" ];
    configureFlags = (orig.configureFlags or [ ]) ++ [
      "--enable-static"
    ];
    postInstall = (orig.postInstall or "") + ''
      mkdir -p $static/lib
      find $out/lib -name '*.la' -exec rm {} \;
      mv $out/lib/*.a $static/lib/
    '';
  });

  # This is needed by DPDK in order to determine which pinned core runs on which numa node and which NIC is most
  # efficiently connected to which NUMA node.  You can disable the need for this library entirely by editing dpdk's
  # build to specify `-Dmax_numa_nodes=1`.
  #
  # While we don't currently hide NUMA mechanics from DPDK, there is something to be said for eliminating this library
  # from our toolchain as a fair level of permissions and a lot of different low level trickery is required to make it
  # function.  In "the glorious future" we should bump all of this logic up to the dataplane's init process, compute
  # what we need to, pre-mmap _all_ of our heap memory, configure our cgroups and CPU affinities, and then pin our cores
  # and use memory pools local to the numa node of the pinned core.  That would be a fair amount of work, but it would
  # eliminate a dependency and likely increase the performance and security of the dataplane.
  #
  # For now, we leave this on so DPDK can do some of that for us.  That said, this logic is quite cold and would ideally
  # be size optimized and punted far from all hot paths.  BOLT should be helpful here.
  fancy.numactl = (dataplane-dep prev.numactl).overrideAttrs (orig: {
    outputs = (prev.lib.lists.remove "man" orig.outputs) ++ [ "static" ];
    configureFlags = (orig.configureFlags or [ ]) ++ [
      "--enable-static"
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
  fancy.rdma-core =
    ((dataplane-dep prev.rdma-core).override {
      docutils = null;
      ethtool = null;
      iproute2 = null;
      libnl = final.fancy.libnl;
      pandoc = null;
      udev = null;
      udevCheckHook = null;
    }).overrideAttrs
      (orig: {
        version = sources.rdma-core.branch;
        src = sources.rdma-core.outPath;

        # Patching the shebang lines in the perl scripts causes nixgraph to (incorrectly) think we depend on perl at
        # runtime.  We absolutely do not (we don't even ship a perl interpreter), so don't patch these shebang lines.
        # In fact, we don't use any of the scripts from this package.
        dontPatchShebangs = true;

        # The upstream postFixup is broken by dontPatchShebangs = true
        # It's whole function was to further mutate the shebang lines in perl scripts, so we don't care.
        # Just null it.
        postFixup = null;

        outputs = (orig.outputs or [ ]) ++ [
          "static"
        ];
        # CMake depends on -Werror to function, but the test program it uses to confirm that -Werror works "always
        # produces warnings."  The reason for this is that we have injected our own CFLAGS and they have nothing to do
        # with the trivial program.  This causes the unused-command-line-argument warning to trigger.
        # We disable that warning here to make sure rdma-core can build (more specifically, to make sure that it can
        # build with debug symbols).
        CFLAGS = "-Wno-unused-command-line-argument";
        cmakeFlags =
          orig.cmakeFlags
          ++ [
            "-DENABLE_STATIC=1"
            # we don't need pyverbs, and turning it off reduces build time / complexity.
            "-DNO_PYVERBS=1"
            # no need for docs in container images.
            "-DNO_MAN_PAGES=1"
            # we don't care about this lib's exported symbols / compat situation _at all_ because we static link (which
            # doesn't have symbol versioning in the first place).  Turning this off just reduces the build's internal
            # complexity and makes lto easier.
            "-DNO_COMPAT_SYMS=1"
            # IOCTL_MODE can be "write" or "ioctl" or "both" (default).
            # Very old versions of rdma-core used what they call the "legacy write path" to support rdma-operations.
            # These have (long since) been superseded by the ioctl mode, but the library generates both code paths by
            # default due to rdma-core's fairly aggressive backwards compatibility stance.
            # We have absolutely no need or desire to support the legacy mode, and we can potentially save ourselves
            # some instruction cache pressure by disabling that old code at compile time.
            "-DIOCTL_MODE=ioctl"
          ]
          ++
            final.lib.optionals
              (
                (builtins.elem "thread" sanitizers)
                || (builtins.elem "address" sanitizers)
                || (builtins.elem "safe-stack" sanitizers)
              )
              [
                # This allows address / thread sanitizer to build (some sanitizers do not like -Wl,-z,defs or
                # -Wl,--no-undefined).
                # This isn't a hack: undefined symbols from sanitizers is a known issue and is not unique to us.
                "-DSUPPORTS_NO_UNDEFINED=0"
              ];
        postInstall = (orig.postInstall or "") + ''
          mkdir -p $static/lib $man;
          mv $out/lib/*.a $static/lib/
          mv $out/share $man/
        '';
      });

  # Compiling DPDK is the primary objective of this overlay.
  #
  # We care _a lot_ about how this is compiled and should always use flags which are either optimized for performance
  # or debugging.  After all, if you aren't doing something performance critical then I don't know why you want DPDK at
  # all :)
  #
  # Also, while this library has a respectable security track record, this is also a very strong candidate for
  # cfi, safe-stack, and cf-protection.
  fancy.dpdk = dataplane-dep (
    final.callPackage ../pkgs/dpdk (
      final.fancy
      // {
        inherit platform profile;
        src = sources.dpdk;
      }
    )
  );

  # DPDK is largely composed of static-inline functions.
  # We need to wrap those functions with "_w" variants so that we can actually call them from rust.
  #
  # This wrapping process does not really cause any performance issue due to lto; the compiler is going to "unwrap"
  # these methods anyway.
  fancy.dpdk-wrapper = dataplane-dep (final.callPackage ../pkgs/dpdk-wrapper final.fancy);

  # TODO: consistent packages
  fancy.pciutils = dataplane-dep (
    final.pciutils.override {
      static = true;
      kmod = null;
      zlib = null;
    }
  );

  fancy.libunwind = (dataplane-dep final.llvmPackages.libunwind).override { enableShared = false; };

  # TODO: consistent packages, min deps
  fancy.hwloc =
    ((dataplane-dep prev.hwloc).override {
      inherit (final.fancy) numactl;
      cairo = null;
      cudaPackages = null;
      enableCuda = false;
      expat = null;
      libX11 = null;
      ncurses = null;
      x11Support = false;
    }).overrideAttrs
      (orig: {
        outputs = (orig.outputs or [ ]) ++ [ "static" ];
        configureFlags = (orig.configureFlags or [ ]) ++ [
          "--enable-static"
        ];
        postInstall = (orig.postInstall or "") + ''
          mkdir -p $static/lib
          mv $lib/lib/*.a $static/lib/
        '';
      });

  # This isn't directly required by dataplane,
  fancy.perftest = dataplane-dep (
    final.callPackage ../pkgs/perftest final.fancy // { src = sources.perftest; }
  );
}
