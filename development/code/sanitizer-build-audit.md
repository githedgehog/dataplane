# What the sanitizer builds actually instrument

Status: **audit, 2026-08-23. Nothing changed.** Written because a claim about the sanitizer
builds turned out to be wrong in one direction and right in another, and the difference decides
whether a green run means anything.

The intent is that a sanitizer build rebuilds everything except glibc against one sanitizer. The
Nix build path does that. Two other paths that look like sanitizer builds do not, and nothing
tells you which one you are in.

## Three paths, three answers

| path | C dependencies | Rust `std` | workspace crates |
| --- | --- | --- | --- |
| `nix-build --argstr sanitize thread` | **instrumented** | **rebuilt from source, instrumented** | instrumented |
| `just fuzz <target> sanitize=thread` | whatever the _shell_'s sysroot was built with | rebuilt by cargo-bolero `--build-std` | instrumented |
| dev shell, plain `cargo test` | not instrumented | prebuilt, not instrumented | not instrumented |

The first row is the intent, and it holds. `nix/overlays/dataplane.nix` builds every C dependency
-- dpdk, dpdk-wrapper, libbsd, libmd, libnl, numactl, hwloc, rdma-core -- through `stdenv'`, and
`nix/overlays/llvm.nix` folds the profile's `NIX_CFLAGS_COMPILE` into `stdenv'`. `default.nix`
passes `-Zbuild-std=std,panic_unwind` unconditionally, so `std` is compiled from source under
whatever `RUSTFLAGS` the profile sets. There is no uninstrumented C and no uninstrumented `std`.

**The second row is the hazard.** There are two independent knobs both spelled `sanitize`: the one
`default.nix`/`shell.nix` take, which decides how the sysroot is built, and the `just` variable,
which decides what `--sanitizer` cargo-bolero passes. Nothing ties them together. Running
`just fuzz <target> sanitize=thread` inside a shell entered _without_ `--argstr sanitize thread`
produces instrumented Rust linked against an uninstrumented DPDK, and it does so **silently**.

## `-Cunsafe-allow-abi-mismatch=sanitizer` is what makes that silent

`nix/profiles.nix` sets it in `sanitize.thread.RUSTFLAGS`. It disables rustc's check that every
crate in the graph agrees about sanitizer flags -- which is precisely the check that would
otherwise refuse a half-instrumented link. It is global, so it excuses _any_ crate, and there is
no way afterwards to tell which ones it excused.

Its comment says gimli does not like thread sanitizer, "but it shouldn't be an issue since that is
all build time logic". That reasoning does not hold: `-Zbuild-std-features=backtrace` pulls gimli
into `std`'s backtrace machinery, which symbolises at **runtime**, not at build time. So whatever
gap the flag is covering is a runtime gap, and it is being covered everywhere rather than for the
one crate that needed it.

Since `std` _is_ rebuilt with the sanitizer on the Nix path, there should be no ABI mismatch to
allow there. So one of two things is true, and which one matters:

- the flag is left over from a build failure that no longer happens, and can go; or
- something in the graph is genuinely not instrumented, in which case that is the blind spot and
  the flag is hiding it.

## What to do, when someone picks this up

1. Remove `-Cunsafe-allow-abi-mismatch=sanitizer` and build `--argstr sanitize thread`. If it
   builds, delete it. If it fails, the failure names the crate that is not instrumented, which is
   the answer.
2. If gimli is the crate, scope the exception to it rather than to everything, or drop `backtrace`
   from `-Zbuild-std-features` for sanitizer builds and record the loss.
3. Make the two `sanitize` knobs impossible to disagree. A `just fuzz` that is asked for a
   sanitizer while the sysroot was built without one should refuse rather than link.

## Why this is worth the trouble

A sanitizer that is quietly not instrumenting half the program is worse than no sanitizer: a green
run reads as evidence and is not. This campaign has already spent several turns on findings that
were the test harness rather than the dataplane, and every one of them looked like a real defect
until the harness was checked. An uninstrumented dependency is the same failure mode with the
polarity reversed -- it produces false confidence instead of false alarms, and nothing prompts you
to go looking.

`-fsanitize=thread` also only sees what it is compiled into plus its libc interceptors, so glibc
being excluded is fine and deliberate; DPDK being excluded is not.
