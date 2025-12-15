{
  env ? { },
}:
final: prev:
let
  helpers.addToEnv =
    add: orig:
    orig
    // (
      with builtins; (mapAttrs (var: val: (toString (orig.${var} or "")) + " " + (toString val)) add)
    );
  adapt = final.stdenvAdapters;
  bintools = final.buildPackages.llvmPackages.bintools;
  lld = final.buildPackages.llvmPackages.lld;
  stdenv-llvm = adapt.addAttrsToDerivation (orig: {
    doCheck = false;
    nativeBuildInputs = (orig.nativeBuildInputs or [ ]) ++ [
      bintools
      lld
    ];
  }) (adapt.makeStaticLibraries final.buildPackages.llvmPackages.stdenv);
  stdenv-llvm-with-flags = adapt.addAttrsToDerivation (orig: {
    env = helpers.addToEnv env (orig.env or { });
  }) stdenv-llvm;
  dataplane-dep = pkg: pkg.override { stdenv = stdenv-llvm-with-flags; };
in
{ }
