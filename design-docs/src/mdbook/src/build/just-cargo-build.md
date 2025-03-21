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
