{ }:
final: prev:
let
  helpers.addToEnv =
    add: orig:
    orig
    // (
      with builtins; (mapAttrs (var: val: (toString (orig.${var} or "")) + " " + (toString val)) add)
    );
in
{ }
