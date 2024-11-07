# Sterile builds

The trouble with calling something like `cargo build` is that the compile isn't sterile.

That is to say, that the build doesn't have a precise, know, portable, and deterministic (pure) version of all dependencies between developer machines.

For example, we don't know exactly what version of rust you compiled with.
Nor exactly what version of libc that rust came with.

The sterile environment builds the project in a _very_ minimal container so we can be sure what are actual dependencies are.

Running

```bash
just sterile-build
```

will build the project in a container which (by design) is missing anything that might "contaminate" the build (i.e. introduce an undocumented dependency).

Sterile builds are slower and more hostile to normal development flows.
On the other hand, they better approximate the CI environment and are a good thing to run before submitting a PR.

Likewise, you can run

```bash
just test
```

to run the tests in a minimal (sterile) environment.
