## Prerequisites

You will need the following before we can begin.

- A recent `x86_64` linux machine of some kind required for development.
- Bash (you very likely have this, but if not you will need to install it).
- [Docker](https://www.docker.com/) (install through your package manager)
- Cargo / Rust (I recommend installing via [`rustup`](https://rustup.rs/))

  * :warning: You need a recent version of rust (1.82.0 or better) to build the project.
    Run 

    ```bash
    rustup update
    ```
    
    from time to time to stay up to date.

- [just](https://github.com/casey/just) 

  You can install `just` via your package manager, but I recommend installing it via `cargo` as it will likely be more up to date.

  ```
  cargo install just
  ```
  
  or, if you have [cargo-binstall], run


  ```
  cargo binstall just
  ```


[cargo-binstall]: https://github.com/cargo-bins/cargo-binstall
