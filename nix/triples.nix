# just information to navigate the various targets and the ways they are labeled on different systems
{
  x86_64 = {
    linux = {
      gnu = {
        target = "x86_64-unknown-linux-gnu";
        machine = "x86_64";
        nixarch = "gnu64";
        libc = "gnu";
      };
      musl = {
        target = "x86_64-unknown-linux-musl";
        machine = "x86_64";
        nixarch = "musl64";
        libc = "musl";
      };
    };
  };
  aarch64 = {
    linux = {
      gnu = {
        target = "aarch64-unknown-linux-gnu";
        machine = "aarch64";
        nixarch = "aarch64-multiplatform";
        libc = "gnu";
      };
      musl = {
        target = "aarch64-unknown-linux-musl";
        machine = "aarch64";
        nixarch = "aarch64-multiplatform-musl";
        libc = "musl";
      };
    };
  };
  wasm32 = {
    wasip1 = {
      none = {
        target = "wasm32-wasip1";
        machine = "wasm32";
        nixarch = "wasi32";
      };
    };
  };
}
