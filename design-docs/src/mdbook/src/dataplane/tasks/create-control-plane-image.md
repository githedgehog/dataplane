# Create a control-plane container image

We need to generate a docker image to run our control plane.

## Goals:

1. **REQUIRE**: [`zebra`] plugin support
2. **REQUIRE**: [`bgpd`] support
3. **REQUIRE**: [`bfdd`] support
4. **REQUIRE**: CI builds and container
5. **REQUIRE**: [Lua scripting] should be disabled in build
6. **IDEALLY**: disable as much functionality as we can get away with
7. **IDEALLY**: supply a debug build and release build

## Note:

Both [@Fredi-raspall] and [@daniel-noland] have made some progress on this task and should sync up to get it over the line.

## Likely dispatch

- [@Fredi-raspall]

[Lua scripting]: https://docs.frrouting.org/en/latest/scripting.html

{{#include ../../links.md}}

