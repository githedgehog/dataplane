# Unsafe code guidelines

## Unsafe is not unsound

_Unsound_ code, defined as code which may exhibit [undefined behavior] is **never** acceptable.
However, `unsafe` code is _not_ the same as _unsound_ code.

The `unsafe` scope is better thought of as a marker which indicates two things:

1. The compiler may invoke methods which are marked as `unsafe` within the scope of the `unsafe` block.
2. It is the programmer's responsibility to ensure that the code within the `unsafe` block is sound as the compiler
   and type system do not (or can not) guarantee soundness within this context.

`unsafe` code is not wrong per se.
However, it is rarely needed in our code base and is best avoided.

Where `unsafe` code _is_ needed, it should only be used in the construction of a safe abstraction which does ensure
soundness (see [avoiding global reasoning]).

## `unsafe` vs unsound by analogy

The arch is a famously stable shape frequently used in architecture.
However, when constructing an arch, scaffolding is necessary to stabilize the arch until the keystone is placed.
After the keystone is placed, the scaffolding may be safely removed.

- The arch is analogous to safe code.
- An incomplete arch which has such scaffolding is analogous to correctly used `unsafe` code.
- An incomplete arch which lacks such scaffolding is analogous to unsound code.

**Key point**: components which are both safe and sound may be (and regularly are) constructed from components which
lack one or both properties _on their own_.
The fact that the components of an arch are individually unsafe is not valid criticism of an arch.
By analogy, the presence of `unsafe` code is not a proof of a flaw in the code.
However, `unsafe` code, requiring an analog to this "scaffolding", is considerably less ergonomic to use than safe
code, and its use is therefore best minimized.

[avoiding global reasoning]: avoid-global-reasoning.md
[undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
