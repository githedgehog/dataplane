{ }:
final: prev:
let
  helpers.addToEnv =
    add: orig:
    orig
    // (
      with builtins; (mapAttrs (var: val: (toString (orig.${var} or "")) + " " + (toString val)) add)
    );
  adapt = final.stdenvAdapters;
  stdenv-llvm = adapt.makeStaticLibraries final.buildPackages.llvmPackages.stdenv;
in
{ }
