# Hedgehog Dataplane

## Build instructions

### Prerequisites

- Recent `x86_64` linux machine of some kind required for development
- Bash (you very likely have this)
- [Docker](https://www.docker.com/) (install through your package manager)
- Cargo / Rust (install via [`rustup`](https://rustup.rs/))

  * :warning: You need a recent version of rust (1.82.0 or better) to build the project.

    ```bash
    rustup update
    ```
  * :warning: You need to install both the glibc and musl targets to use the default builds.

    ```bash
    rustup target add x86_64-unknown-linux-gnu
    rustup target add x86_64-unknown-linux-musl
    ```
  
- [just](https://github.com/casey/just) (install through your package manager or cargo)

## Step 0. Clone the repository

```bash
git clone git@github.com:githedgehog/dataplane.git
cd dataplane
```

## Step 1. Get the sysroot

In the source directory, run

```bash
just refresh-compile-env
```

You should now have a directory called `compile-env` which contains the tools needed to build `dpdk-sys` such as `clang` and `lld`.
You should also have `./compile-env/sysroot` which contains the libraries that `dpdk-sys` needs to link against.
Both `x86_64-unknown-linux-gnu` and `x86_64-unknown-linux-musl` targets are currently supported.

## Step 2. Fake nix

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

## Step 3. Build the project

At this point you should be able to run

```bash
just cargo build
```

You should now have statically linked ELF executables in `target/x86_64-unknown-linux-gnu/debug/scratch` and `target/x86_64-unknown-linux-musl/debug/scratch`.

You can build in release mode with

```bash
just cargo build --profile=release
```

at which point the executables will be in `target/x86_64-unknown-linux-gnu/release/scratch` and `target/x86_64-unknown-linux-musl/release/scratch`.

## Step 4. Run the tests (debug mode)

To run the test suite, you can run 

```bash
just cargo test
```

By default, this will run just the glibc tests.
To run the test suite under musl, try

```bash
just cargo test --target x86_64-unknown-linux-musl
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

## License

The Dataplane of the Hedgehog Open Fabric Network is licensed under the
[Apache License, Version 2.0](LICENSE).
