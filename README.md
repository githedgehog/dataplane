# Hedgehog Dataplane

This repository contains the Dataplane for [Hedgehog's Open Network
Fabric][fabric-docs]. This component acts as a gateway between different VPCs
managed by the Fabric, or to communicate with endpoints outside of the Fabric.

> [!WARNING]
> This project is under development, and is not yet functional.

[fabric-docs]: https://docs.githedgehog.com

## Build instructions

### Prerequisites

- A recent `x86_64` linux machine is required for development
- Bash (you very likely have this)
- [Docker][docker] (install through your package manager)
- Cargo / Rust (install via [`rustup`][rustup])

  * :warning: You need a recent version of rust (1.85.0 or better) to build the project.

    ```bash
    rustup update
    ```
  * :warning: You need to install (at least) the glibc target to use the default builds.

    ```bash
    rustup target add x86_64-unknown-linux-gnu
    ```

- [just][just] (install through your package manager or cargo)

[docker]: https://www.docker.com/
[rustup]: https://rustup.rs/
[just]: https://github.com/casey/just

### Step 0. Clone the repository

```bash
git clone git@github.com:githedgehog/dataplane.git
cd dataplane
```

### Step 1. Get the sysroot

In the source directory, run

```bash
just refresh-compile-env
```

You should now have a directory called `compile-env` which contains the tools needed to build `dpdk-sys` such as `clang` and `lld`.
You should also have `./compile-env/sysroot` which contains the libraries that `dpdk-sys` needs to link against.
Only the `x86_64-unknown-linux-gnu` target is currently supported.

### Step 2. Fake nix

The sysroot is currently built using nix, but you don't need nix to build the project.
The idea is to symlink `/nix` to `./compile-env/nix` so that the build scripts can find the libraries they need.
This is a compromise between requiring the developer to understand nix (which can be non-trivial) and requiring the developer to have a bunch of libraries installed on their system.

> [!WARNING]
> This is a hack!
> It works fine but the plan won't work if you already have /nix.
> If you already have /nix talk to me, and we will make it work.
> It should be pretty easy (we will just need to export some stuff
> from `dpdk-sys`)

```bash
just fake-nix
```

> [!NOTE]
> If you move your project directory, you will need to run `just fake-nix refake` to update the symlinks.

### Step 3. Build the project

At this point you should be able to run

```bash
cargo build
```

to build default workspace members (dpdk-sysroot-helper, errno, and net), or

```bash
just cargo build --package="$package"
```

to build workspace members which are not compiled by default (dataplane, dpdk, dpdk-sys).

These members are not enabled by default to help developers which develop on ARM machines, and which can't run (or even compile) packages reliant on the sysroot.

After running

```bash
just cargo build --package=dataplane
```

You should now have an ELF executable in `target/x86_64-unknown-linux-gnu/debug/dataplane`.

You can build in release mode with

```bash
just cargo build --package=dataplane --profile=release
```

at which point you should have an executable in `target/x86_64-unknown-linux-gnu/release/dataplane`.

### Step 4. Run the tests (debug mode)

To run the test suite, you can run

```bash
just cargo test
```

To run the test suite under release mode

```bash
just cargo test --profile=release
```

> [!WARNING]
> Release builds may not work on your development machine!
>
> The release build's dependencies are compiled with `-march=x86-64-v4` because we expect to release with a very new processor.
> As a result, getting `SIGILL` on an older chip is no surprise.
> We test release builds in CI, but they may not work on your dev box ¯\\\_(ツ)\_\/¯

> [!NOTE]
> Why the `just` in `just cargo build ...`?
>
> `just` is computing the correct `RUSTFLAGS` for us depending on the profile.
> After that it simply calls `cargo build`.
> Normally we would include those kinds of setting in `Cargo.toml` but `cargo` can not currently express all the `RUSTFLAGS` we are using (thus the `just` wrapper).

## VSCode Setup

Because this repository uses a custom sysroot with custom libraries and binaries, you need to make sure rust-analyzer is aware of the sysroot and runs the correct cargo binary.
To do this, add the following to your `.vscode/settings.json` file:

```json
"rust-analyzer.server.extraEnv": {
  "RUSTC": "<absolute path to dataplane directory>/compile-env/bin/rustc",
  "CARGO": "<absolute path to dataplane directory>/compile-env/bin/cargo"
}
```

You'll also want to run `cargo clippy` on save.
To do this, add the following to your `.vscode/settings.json` file:

```json
"rust-analyzer.check.command": "clippy"
```

> [!NOTE]
> Please submit a PR if you have a way to avoid the absolute path.
> `${workspaceRoot}` and `${workspaceFolder}` won't work since rust-analyzer has a custom function that implements env var substitution in `extraEnv`.
> `${env:xxx}` susbstitutions only work if the variable is set in `extraEnv` itself.

Finally, you want to format code using rust analyzer, and to format on save to make sure your code is always formatted.
To do this, add the following to your `.vscode/settings.json` file:
```json
"[rust]": {
    "editor.defaultFormatter": "rust-lang.rust-analyzer",
    "editor.formatOnSave": true
},
```
## License

The Dataplane of the Hedgehog Open Fabric Network is licensed under the
[Apache License, Version 2.0](LICENSE).
