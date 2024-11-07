# `just` cargo

Now we can simply run 

```bash
cargo build
```

or

```bash
just cargo build
```

to compile to the (dev) version of the project.


You can also run

```bash
just cargo build --release
```

> [!WARNING]
> [^release-mode]: Release builds may not work on your development machine!
>
> The release build's dependencies are compiled with `-march=x86-64-v4` because we expect to release with a very new processor.
> As a result, getting `SIGILL` on an older chip is no surprise.
> We test release builds in CI, but they may not work on your dev box ¯\\\_(ツ)\_\/¯


## The tests

Running the tests should be easy.

```bash
cargo test
```

or 

```bash
just cargo test
```

should take care of it for normal development flows.

But there is a second level to this story.

Sterile builds!
