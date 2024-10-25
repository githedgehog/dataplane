# The build system

If you consider the whole process, the `dataplane` (by necessity) has a fairly complex build.
Thus, much effort has gone into creating the illusion of simplicity and ease for the developer.

<figure title="Build-system data-flow">

```puml
@startuml
!pragma toez true
box "hedgehog stuff" #e0eeee
participant dataplane
participant "dpdk-sys" as dpdk_sys
end box
participant nixpkgs
participant "container\nregistry" as container_registry
participant "external\nsource repos" as external
dpdk_sys -> nixpkgs : build instructions plz
nixpkgs -> dpdk_sys : here ya go
dpdk_sys -> external: fetch code
external -> dpdk_sys: here ya go
dpdk_sys -> dpdk_sys : follow build instructions 
note left
This is a **long** build
end note
dpdk_sys -> container_registry : push compile-env
container_registry -> dpdk_sys : got it
dataplane -> container_registry : compile-env plz
container_registry -> dataplane : here ya go
dataplane -> dataplane : put compile-env\nin a dir named "compile-env"
dataplane -> dataplane : ""just sterile-build""
note right
""cargo build"" (called by ""just sterile-build"") now has 
access to the many "".a"" files required to compile 
and link the dataplane.
It also has a consistent version of LLVM and clang to 
work with.
end note
dataplane -> container_registry : push container
container_registry -> dataplane : got it
@enduml
```
> Sequence diagram for dpdk-sys / dataplane interaction.
</figure>
