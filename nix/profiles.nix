# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  arch,
  # The rustc spelling of the platform's C `-march=`/`-mcpu=`, or null where the
  # platform passes neither. See `nix/platforms.nix`, where the two are set side
  # by side.
  target-cpu ? null,
  host-arch,
  profile,
  sanitizers,
  instrumentations,
  cargo-features ? [ ],
  for-tests ? false,
}:
let
  # The `loom` and `shuttle` features compile in concurrency model
  # checkers that use `std::panic::catch_unwind` internally to recover
  # from per-schedule assertion failures.  `catch_unwind` is a no-op
  # under `-Cpanic=abort` (the panic just aborts the process), so
  # builds with either feature must keep the cargo default of
  # `panic = "unwind"`.
  #
  # Test builds also need unwinding so fixture cleanup (the
  # `catch_unwind` calls in `test-utils`) runs on panic; without it, a
  # failing test aborts the runner and leaks state (netns / caps).
  needs-unwind =
    for-tests || builtins.elem "loom" cargo-features || builtins.elem "shuttle" cargo-features;
  # Test archives are loaded back onto the build host and executed
  # there; when the target arch differs, that means qemu-user.
  is-emulated-test = for-tests && (arch != host-arch);
  common.NIX_CFLAGS_COMPILE = [
    "-g3"
    "-gdwarf-5"
    # odr or strict-aliasing violations are indicative of LTO incompatibility, so check for that
    "-Werror=odr"
    "-Werror=strict-aliasing"
    "-Wno-error=unused-command-line-argument"
  ];
  common.NIX_CXXFLAGS_COMPILE = common.NIX_CFLAGS_COMPILE;
  common.NIX_CFLAGS_LINK = [
    # getting proper LTO from LLVM compiled objects is best done with lld rather than ld, mold, or wild (at least at the
    # time of writing)
    "-fuse-ld=lld"
    "-Wl,--build-id"
  ];
  common.RUSTFLAGS = [
    "--cfg=tokio_unstable"
    # Register `emulated` so `#[cfg_attr(emulated, ...)]` never trips
    # `unexpected_cfgs`; only *set* for is-emulated-test and miri.
    "--check-cfg=cfg(emulated)"
    # Only coverage lowers counter-heavy loop counts; sanitizers retain the
    # iterations that help expose races.
    "--check-cfg=cfg(instrumented)"
    # Separate from `instrumented` on purpose. That one means "this build runs
    # fewer iterations"; this one means "this build runs them slowly". A
    # sanitizer keeps every iteration -- which is the point, races need them --
    # but bolero stops on wall-clock, so the *sample* is small either way and a
    # coverage guard reading it is judging the sanitizer, not the code.
    "--check-cfg=cfg(sanitized)"
    # Set only by `instrumentation=pgo`, so the on-demand counter dump cannot be compiled
    # without the profiling runtime that provides the symbol it calls.
    "--check-cfg=cfg(profile_generate)"
    "-Cdebuginfo=full"
    "-Cdwarf-version=5"
    "-Csymbol-mangling-version=v0"
    "-Clink-arg=-Wl,--as-needed,--gc-sections" # FRR builds don't like this, but rust does fine
    "-Clink-arg=-Wl,--thinlto-jobs=4" # setting this parameter too high causes massive memory load on the linking step
  ]
  ++ (
    # Must match the machine flags the C compiler gets, or cross-language LTO
    # silently degrades to no inlining at all: LLVM refuses to inline a callee
    # whose target features are not a subset of the caller's, and C compiled at
    # `-march=x86-64-v3` has a large superset of what rustc assumes by default.
    # The result links and runs, and every DPDK `static inline` stays an
    # out-of-line call.
    if target-cpu == null then [ ] else [ "-Ctarget-cpu=${target-cpu}" ]
  )
  ++ (
    if needs-unwind then
      [ ]
    else
      [
        "-Zpanic_abort_tests"
        "-Cpanic=abort"
      ]
  )
  ++ (if is-emulated-test then [ "--cfg=emulated" ] else [ ])
  ++ (if builtins.elem "coverage" instrumentations then [ "--cfg=instrumented" ] else [ ])
  ++ (if sanitizers != [ ] then [ "--cfg=sanitized" ] else [ ])
  ++ (if builtins.elem "pgo" instrumentations then [ "--cfg=profile_generate" ] else [ ])
  ++ (map (flag: "-Clink-arg=${flag}") common.NIX_CFLAGS_LINK);
  optimize-for.debug.NIX_CFLAGS_COMPILE = [
    "-fno-inline"
    "-fno-omit-frame-pointer"
  ];
  optimize-for.debug.NIX_CXXFLAGS_COMPILE = optimize-for.debug.NIX_CFLAGS_COMPILE;
  optimize-for.debug.NIX_CFLAGS_LINK = [ ];
  optimize-for.debug.RUSTFLAGS = [
    "-Copt-level=0"
    "-Cdebug-assertions=on"
    "-Coverflow-checks=on"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") optimize-for.debug.NIX_CFLAGS_LINK);
  optimize-for.performance.NIX_CFLAGS_COMPILE = [
    "-O3"
    "-flto=thin"
    # Kept so a release build can be profiled. Without it `perf record -g` walks
    # nothing -- a release binary had 0 of 33481 prologues setting up `%rbp` -- and
    # the alternative, `--call-graph dwarf`, copies the stack per sample and starts
    # dropping samples exactly where a busy-poll datapath is hottest.
    #
    # Costs a register and a two-instruction prologue. That is a real cost on a
    # datapath, and it is accepted deliberately: the bottlenecks we are chasing are
    # contention on shared lines, which spilling does not move.
    #
    # As with the `-m` flags below, this only works if both halves agree. The rustc
    # counterpart is `-Cforce-frame-pointers=yes` in the RUSTFLAGS just below; drop
    # either one and the stack walk breaks at the first frame from that language.
    "-fno-omit-frame-pointer"
  ];
  optimize-for.performance.NIX_CXXFLAGS_COMPILE = optimize-for.performance.NIX_CFLAGS_COMPILE ++ [
    "-fwhole-program-vtables"
  ];
  optimize-for.performance.NIX_CFLAGS_LINK = optimize-for.performance.NIX_CXXFLAGS_COMPILE ++ [
    "-Wl,--lto-whole-program-visibility"
  ];
  optimize-for.performance.RUSTFLAGS = [
    "-Clinker-plugin-lto"
    "-Cembed-bitcode=yes"
    # The counterpart to `-fno-omit-frame-pointer` above. See the note there.
    "-Cforce-frame-pointers=yes"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") optimize-for.performance.NIX_CFLAGS_LINK);
  secure.NIX_CFLAGS_COMPILE = [
    "-fstack-protector-strong"
    "-fstack-clash-protection"
    # we always want pic/pie and GOT offsets should be computed at compile time whenever possible
    "-Wl,-z,relro,-z,now"
  ];
  secure.NIX_CXXFLAGS_COMPILE = secure.NIX_CFLAGS_COMPILE;
  # handing the CFLAGS back to clang/lld is basically required for -fsanitize
  secure.NIX_CFLAGS_LINK = secure.NIX_CFLAGS_COMPILE;
  secure.RUSTFLAGS = [
    "-Crelro-level=full"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") secure.NIX_CFLAGS_LINK);
  march.x86_64.NIX_CFLAGS_COMPILE = [
    # DPDK functionally requires rtm on x86_64: `rte_rtm.h` calls `_xbegin`, and
    # `rte_spinlock.h` pulls it in, so the headers do not compile without this.
    # Every x86_64 platform we build for is x86-64-v3 or better, which already
    # implies ssse3 and crc32 (SSE4.2) -- naming them again here would only add
    # features rustc has to be told about separately, for nothing.
    #
    # Anything added here MUST get its counterpart in `march.x86_64.RUSTFLAGS`
    # below, or cross-language inlining stops. See the note there.
    "-mrtm" # TODO: try to convince DPDK not to rely on rtm
    "-fcf-protection=full"
  ];
  march.x86_64.NIX_CXXFLAGS_COMPILE = march.x86_64.NIX_CFLAGS_COMPILE;
  march.x86_64.NIX_CFLAGS_LINK = march.x86_64.NIX_CXXFLAGS_COMPILE;
  march.x86_64.RUSTFLAGS = [
    # In 1:1 alignment with `march.x86_64.NIX_CFLAGS_COMPILE` above, and it has
    # to stay that way. LLVM will not inline a callee whose target features are
    # not a subset of the caller's, so a single unmatched `-m` flag on the C side
    # is enough to stop *every* DPDK `static inline` from inlining into Rust.
    # Nothing fails when that happens; the calls just stay out of line.
    #
    # rustc warns that `rtm` is unstable, once per invocation. That is the price
    # of DPDK requiring it. We are certainly not issuing hardware transactions
    # ourselves -- Intel's implementation proved broken and AMD never shipped one
    # -- so the feature only ever has to be *permitted*, never used. Dropping
    # `-mrtm` on the C side is the real fix, and would let this line go too.
    "-Ctarget-feature=+rtm"
    "-Zcf-protection=full"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") march.x86_64.NIX_CFLAGS_LINK);
  march.aarch64.NIX_CFLAGS_COMPILE = [ ];
  march.aarch64.NIX_CXXFLAGS_COMPILE = march.aarch64.NIX_CFLAGS_COMPILE;
  march.aarch64.NIX_CFLAGS_LINK = [ ];
  march.aarch64.RUSTFLAGS = [ ] ++ (map (flag: "-Clink-arg=${flag}") march.aarch64.NIX_CFLAGS_LINK);
  march.wasm32 = { };
  sanitize.address.NIX_CFLAGS_COMPILE = [
    "-fsanitize=address,local-bounds"
  ];
  sanitize.address.NIX_CXXFLAGS_COMPILE = sanitize.address.NIX_CFLAGS_COMPILE;
  sanitize.address.NIX_CFLAGS_LINK = sanitize.address.NIX_CFLAGS_COMPILE ++ [
    "-static-libasan"
  ];
  sanitize.address.RUSTFLAGS = [
    "-Zsanitizer=address"
    "-Zexternal-clangrt"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.address.NIX_CFLAGS_LINK);
  sanitize.leak.NIX_CFLAGS_COMPILE = [
    "-fsanitize=leak"
  ];
  sanitize.leak.NIX_CXXFLAGS_COMPILE = sanitize.leak.NIX_CFLAGS_COMPILE;
  sanitize.leak.NIX_CFLAGS_LINK = sanitize.leak.NIX_CFLAGS_COMPILE;
  sanitize.leak.RUSTFLAGS = [
    "-Zsanitizer=leak"
    "-Zexternal-clangrt"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.leak.NIX_CFLAGS_LINK);
  sanitize.thread.NIX_CFLAGS_COMPILE = [
    "-fsanitize=thread"
  ];
  sanitize.thread.NIX_CXXFLAGS_COMPILE = sanitize.thread.NIX_CFLAGS_COMPILE;
  sanitize.thread.NIX_CFLAGS_LINK = sanitize.thread.NIX_CFLAGS_COMPILE ++ [
    "-Wl,--allow-shlib-undefined"
  ];
  sanitize.thread.RUSTFLAGS = [
    "-Zsanitizer=thread"
    "-Zexternal-clangrt"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.thread.NIX_CFLAGS_LINK);
  # note: cfi _requires_ LTO and is fundamentally ill suited to debug builds
  sanitize.cfi.NIX_CFLAGS_COMPILE = [
    "-fsanitize=cfi"
    # visibility=default is functionally required if you use basically any cfi higher than icall.
    # In theory we could set -fvisibility=hidden, but in practice that doesn't work because too many dependencies
    # fail to build with that setting enabled.
    # NOTE: you also want to enable -Wl,--lto-whole-program-visibility in the linker flags if visibility=default so that
    # symbols can be refined to hidden visibility at link time.
    # This "whole-program-visibility" flag is already enabled by the optimize profile, and
    # given that the optimize profile is required for cfi to even build, we don't explicitly enable it again here.
    "-fvisibility=default"
    # required to properly link with rust
    "-fsanitize-cfi-icall-experimental-normalize-integers"
    # required in cases where perfect type strictness is not maintained but you still want to use CFI.
    # Type fudging is common in C code, especially in cases where function pointers are used with lax const correctness.
    # Ideally we wouldn't enable this, but we can't really re-write all of the C code in the world.
    "-fsanitize-cfi-icall-generalize-pointers"
    # "-fsanitize-cfi-cross-dso"
    "-fsplit-lto-unit" # important for compatibility with rust's LTO
  ];
  sanitize.cfi.NIX_CXXFLAGS_COMPILE = sanitize.cfi.NIX_CFLAGS_COMPILE;
  sanitize.cfi.NIX_CFLAGS_LINK = sanitize.cfi.NIX_CFLAGS_COMPILE;
  sanitize.cfi.RUSTFLAGS = [
    "-Zsanitizer=cfi"
    "-Zsanitizer-cfi-normalize-integers"
    "-Zsanitizer-cfi-generalize-pointers"
    # "-Zsanitizer-cfi-cross-dso"
    "-Zsplit-lto-unit"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.cfi.NIX_CFLAGS_LINK);
  sanitize.safe-stack.NIX_CFLAGS_COMPILE = [
    "-fsanitize=safe-stack"
  ];
  sanitize.safe-stack.NIX_CXXFLAGS_COMPILE = sanitize.safe-stack.NIX_CFLAGS_COMPILE;
  sanitize.safe-stack.NIX_CFLAGS_LINK = sanitize.safe-stack.NIX_CFLAGS_COMPILE ++ [
    "-Wl,--allow-shlib-undefined"
  ];
  sanitize.safe-stack.RUSTFLAGS = [
    "-Zsanitizer=safestack"
    "-Zexternal-clangrt"
    # gimli doesn't like thread sanitizer, but it shouldn't be an issue since that is all build time logic
    "-Cunsafe-allow-abi-mismatch=sanitizer"
    "-Ctarget-feature=-crt-static" # safe-stack doesn't work with any static libc of any kind
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.safe-stack.NIX_CFLAGS_LINK);
  sanitize.shadow-stack.NIX_CFLAGS_COMPILE = [
    "-ffixed-x18"
    "-fsanitize=shadow-call-stack"
  ];
  sanitize.shadow-stack.NIX_CXXFLAGS_COMPILE = sanitize.shadow-stack.NIX_CFLAGS_COMPILE;
  sanitize.shadow-stack.NIX_CFLAGS_LINK = sanitize.shadow-stack.NIX_CFLAGS_COMPILE ++ [
    # "-Wl,--allow-shlib-undefined"
  ];
  sanitize.shadow-stack.RUSTFLAGS = [
    "-Zfixed-x18"
    "-Zsanitizer=shadow-call-stack"
    "-Zexternal-clangrt"
    # gimli doesn't like shadow-stack sanitizer, but it shouldn't be an issue since that is all build time logic
    "-Cunsafe-allow-abi-mismatch=sanitizer,fixed-x18"
    "-Ctarget-feature=-crt-static" # shadow-stack doesn't work with static libc
  ]
  ++ (map (flag: "-Clink-arg=${flag}") sanitize.shadow-stack.NIX_CFLAGS_LINK);
  instrument.fuzz.NIX_CFLAGS_COMPILE = [
    "-fsanitize=fuzzer-no-link"
    "-fno-lto"
  ];
  instrument.fuzz.NIX_CXXFLAGS_COMPILE = instrument.fuzz.NIX_CFLAGS_COMPILE;
  instrument.fuzz.NIX_CFLAGS_LINK = [ ];
  instrument.fuzz.RUSTFLAGS = [
    "--cfg=fuzzing"
    "-Cpasses=sancov-module"
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters"
    "-Cllvm-args=-sanitizer-coverage-level=4"
    "-Cllvm-args=-sanitizer-coverage-pc-table"
    "-Cllvm-args=-sanitizer-coverage-trace-compares"
    "-Cllvm-args=-sanitizer-coverage-stack-depth"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") instrument.fuzz.NIX_CFLAGS_LINK);
  instrument.none.NIX_CFLAGS_COMPILE = [ ];
  instrument.none.NIX_CXXFLAGS_COMPILE = instrument.none.NIX_CFLAGS_COMPILE;
  instrument.none.NIX_CFLAGS_LINK = instrument.none.NIX_CFLAGS_COMPILE;
  instrument.none.RUSTFLAGS =
    [ ] ++ (map (flag: "-Clink-arg=${flag}") instrument.none.NIX_CFLAGS_LINK);
  instrument.coverage.NIX_CFLAGS_COMPILE = [
    "-fprofile-instr-generate"
    "-fcoverage-mapping"
  ];
  instrument.coverage.NIX_CXXFLAGS_COMPILE = instrument.coverage.NIX_CFLAGS_COMPILE;
  instrument.coverage.NIX_CFLAGS_LINK = instrument.coverage.NIX_CFLAGS_COMPILE;
  instrument.coverage.RUSTFLAGS = [
    "-Cinstrument-coverage"
    "-Zcoverage-options=branch"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") instrument.coverage.NIX_CFLAGS_LINK);
  # Instrumented PGO: collect a profile from a real run, to be fed back with `-Cprofile-use`.
  #
  # The directory is only a default: `LLVM_PROFILE_FILE` overrides it at runtime, and that is how
  # the profile actually gets placed, because the useful profile comes off the test bench and not
  # off the build machine. It still has to be written -- rustc rejects a bare `-Cprofile-generate`
  # with "must have a value" -- so it names the same place `dataplane-init` puts a perf profile,
  # which is the one directory in the container that outlives the container.
  instrument.pgo.NIX_CFLAGS_COMPILE = [ "-fprofile-generate" ];
  instrument.pgo.NIX_CXXFLAGS_COMPILE = instrument.pgo.NIX_CFLAGS_COMPILE;
  instrument.pgo.NIX_CFLAGS_LINK = instrument.pgo.NIX_CFLAGS_COMPILE;
  instrument.pgo.RUSTFLAGS = [
    "-Cprofile-generate=/var/run/dataplane"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") instrument.pgo.NIX_CFLAGS_LINK);
  combine-profiles =
    features:
    builtins.foldl' (
      acc: element: acc // (builtins.mapAttrs (var: val: (acc.${var} or [ ]) ++ val) element)
    ) { } features;
  profile-map = rec {
    debug = combine-profiles [
      common
      optimize-for.debug
    ];
    release = combine-profiles [
      common
      optimize-for.performance
      secure
    ];
    checked = release;
  };
in
combine-profiles (
  [
    profile-map."${profile}"
    march."${arch}"
  ]
  ++ (map (i: instrument.${i}) instrumentations)
  ++ (map (s: sanitize.${s}) sanitizers)
)
