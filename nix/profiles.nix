# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  arch,
  target-cpu,
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
  # Line tables only (`debug-info.line-tables`) where full debug info costs more than it is worth:
  #
  # - Release test binaries: line tables are enough for backtraces, and much less for rustc and the
  #   ThinLTO links to hold. The debug and checked test archives do not link with ThinLTO, so they
  #   keep full debug info for a debugger.
  # - The builds of the sanitizers that find bugs (address, leak, thread), which never ship: line
  #   tables are enough to symbolize their reports. The hardening sanitizers (cfi, safe-stack,
  #   shadow-stack) are meant to ship, so their builds keep full debug info.
  #
  # Everything that ships keeps full debug info.
  line-tables-only =
    (for-tests && profile == "release")
    || builtins.any (
      sanitizer:
      builtins.elem sanitizer [
        "address"
        "leak"
        "thread"
      ]
    ) sanitizers;
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
    # Sanitizers keep full iteration limits, but Bolero's time budget may yield fewer samples.
    # Use `sanitized` to skip coverage assertions that require larger samples.
    "--check-cfg=cfg(sanitized)"
    "-Cdebuginfo=full"
    "-Cdwarf-version=5"
    "-Csymbol-mangling-version=v0"
    "-Clink-arg=-Wl,--as-needed,--gc-sections" # FRR builds don't like this, but rust does fine
    # The backend threads of one ThinLTO link, each holding modules of its own, for links nothing
    # bounds: up to `lto_cores` of them can overlap in CI's 20 GiB cgroup. A test archive bounds its
    # links instead and gives each more (`LINK_SLOTS` and `LINK_THINLTO_JOBS` in default.nix).
    "-Clink-arg=-Wl,--thinlto-jobs=2"
  ]
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
  ];
  optimize-for.performance.NIX_CXXFLAGS_COMPILE = optimize-for.performance.NIX_CFLAGS_COMPILE;
  optimize-for.performance.NIX_CFLAGS_LINK = optimize-for.performance.NIX_CXXFLAGS_COMPILE;
  optimize-for.performance.RUSTFLAGS =
    [ ] ++ (map (flag: "-Clink-arg=${flag}") optimize-for.performance.NIX_CFLAGS_LINK);
  # Cross-language ThinLTO: Rust and the C dependencies (DPDK among them) optimized as one program.
  # Only `release` carries it; see `profile-map`.
  link-time.thin.NIX_CFLAGS_COMPILE = [
    "-flto=thin"
  ];
  link-time.thin.NIX_CXXFLAGS_COMPILE = link-time.thin.NIX_CFLAGS_COMPILE ++ [
    "-fwhole-program-vtables"
  ];
  link-time.thin.NIX_CFLAGS_LINK = link-time.thin.NIX_CXXFLAGS_COMPILE ++ [
    "-Wl,--lto-whole-program-visibility"
  ];
  link-time.thin.RUSTFLAGS = [
    "-Clinker-plugin-lto"
    "-Cembed-bitcode=yes"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") link-time.thin.NIX_CFLAGS_LINK);
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
    # DPDK functionally requires some -m flags on x86_64.
    # These features have been available for a long time and can be found on any reasonably recent machine, so just
    # enable them here for all x86_64 builds.
    # In the (very) unlikely event that you need to edit these flags, also edit the associated RUSTFLAGS to match.
    "-mrtm" # TODO: try to convince DPDK not to rely on rtm
    "-mcrc32"
    "-mssse3"
    "-fcf-protection=full"
  ];
  march.x86_64.NIX_CXXFLAGS_COMPILE = march.x86_64.NIX_CFLAGS_COMPILE;
  march.x86_64.NIX_CFLAGS_LINK = march.x86_64.NIX_CXXFLAGS_COMPILE;
  march.x86_64.RUSTFLAGS = [
    # Ideally these should be kept in 1:1 alignment with the x86_64 NIX_CFLAGS_COMPILE settings.
    # That said, rtm and crc32 are only kinda supported by rust, and rtm is functionally deprecated anyway, so we should
    # try to remove DPDK's insistence on it.  We are absolutely not using hardware memory transactions anyway; they
    # proved to be broken in Intel's implementation, and AMD never built them in the first place.
    # "-Ctarget-feature=+rtm,+crc32,+ssse3"
    "-Ctarget-feature=+ssse3"
    # The platform's CPU, as the C code gets from `-march` (the platform's override).
    "-Ctarget-cpu=${target-cpu}"
    "-Zcf-protection=full"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") march.x86_64.NIX_CFLAGS_LINK);
  march.aarch64.NIX_CFLAGS_COMPILE = [ ];
  march.aarch64.NIX_CXXFLAGS_COMPILE = march.aarch64.NIX_CFLAGS_COMPILE;
  march.aarch64.NIX_CFLAGS_LINK = [ ];
  march.aarch64.RUSTFLAGS = [
    # The platform's CPU, as the C code gets from `-mcpu` (the platform's override).
    "-Ctarget-cpu=${target-cpu}"
  ]
  ++ (map (flag: "-Clink-arg=${flag}") march.aarch64.NIX_CFLAGS_LINK);
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
    # DPDK's x86 spinlocks and atomics are inline asm, which TSan cannot see, so every critical
    # section they guard (e.g. the EAL interrupt thread's callback list) reports as a race.
    # This switches them to the __atomic builtins TSan instruments.
    "-DRTE_FORCE_INTRINSICS"
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
  # Comes last where `line-tables-only` is set, overriding `common`'s `-Cdebuginfo=full`: rustc
  # takes the last one it is given. Overriding rather than replacing also means that taking
  # `sanitizer-rustflags` (default.nix) back out of a sanitizer build's RUSTFLAGS leaves an
  # unsanitized build's, `-Cdebuginfo=full` included.
  debug-info.line-tables.RUSTFLAGS = [
    # A release test archive's ThinLTO links peaked about 27% lower this way.
    "-Cdebuginfo=line-tables-only"
  ];
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
      link-time.thin
      secure
    ];
    # The test profile: optimized, with Rust's debug assertions and overflow checks (see
    # `[profile.checked]` in `Cargo.toml`), and without LTO. Coverage, the sanitizers, shuttle and
    # loom build with it, and an instrumented ThinLTO link of the whole program is the heaviest
    # thing CI builds: `coverage/checked` kept losing its 20 GiB runner (see `lto_cores` in
    # `ci.just`). The binaries run somewhat slower without cross-crate inlining, so tests on a time
    # budget explore a little less. `release` still builds and tests the ThinLTO binary we ship.
    # CFI requires LTO, so a CFI build has to use `release`.
    checked = combine-profiles [
      common
      optimize-for.performance
      secure
    ];
  };
in
combine-profiles (
  [
    profile-map."${profile}"
    march."${arch}"
  ]
  ++ (map (i: instrument.${i}) instrumentations)
  ++ (map (s: sanitize.${s}) sanitizers)
  ++ (if line-tables-only then [ debug-info.line-tables ] else [ ])
)
