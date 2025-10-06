# Avoid Global Reasoning

## Code should be modular

Well-designed code should be organized into self-contained modules that can be understood and reasoned about in
isolation.
Each module should have a clear interface and well-defined responsibilities, minimizing the need to understand the
entire system to work with any single part.

Modular code reduces cognitive load by allowing developers to focus on one piece at a time.
When changes are needed, they can be made locally without fear of breaking unrelated parts of the system.
This locality of reasoning makes code easier to test, debug, and maintain over time.

## Don't expect the programmer to know everything

APIs and interfaces should be designed to guide users toward correct usage without requiring deep knowledge of
implementation details or system-wide invariants.
Good design makes the easy path the correct path.

Rather than relying on documentation or tribal knowledge to prevent misuse, encode constraints and requirements
directly into the interface.
_Make illegal states unrepresentable_ and invalid operations impossible to express (where possible and practical).
This design approach prevents entire classes of bugs and reduces the burden on both API consumers and maintainers.

## Use static typing to enforce validity constraints where possible

Static type systems allow us to catch errors at compile time rather than runtime.
By encoding invariants and constraints into the type system itself, we can eliminate entire categories of bugs before
code ever runs.
This also greatly simplifies testing

- tests can be much more modular
- correctness can be verified incrementally

Types serve as documentation!
They communicate intent, prevent misuse, and enable confident refactoring.
When used effectively, types transform runtime errors into compile-time errors, shifting the discovery of problems
earlier in the development cycle where they're cheaper and less stressful to fix (for both programmers and users).

## Types as "units"

Even "simple" values like numbers and strings can benefit from semantic typing.
Wrapping primitives in domain-specific types prevents unit confusion, enforces validation rules, and makes interfaces
self-documenting.

This technique, sometimes called the "newtype pattern," creates zero-cost abstractions that add meaning and safety to
otherwise ambiguous primitive values.
By distinguishing between conceptually different uses of the same primitive type, we prevent mixing incompatible values
and make our code's intent clearer.

### Example: using types as units

Imagine you have a function that computes the volume of a box given its length, width, and height.

```rust
fn compute_volume(length: f64, width: f64, height: f64) -> f64 {
    // implementation details
}
```

This function is vulnerable to errors in that

1. The units of the measurements are not clear. Does it accept feet, meters, light-years?
2. The function does not statically exclude invalid input. What if you give it negative values for length?

This function can be more clearly and safely expressed as

```rust
fn compute_volume(length: Meters, width: Meters, height: Meters) -> CubicMeters {
    // implementation details
}
```

where the type `Meters` is defined as follows:

```rust
/// A unit of length measured in meters.
#[repr(transparent)]
struct Meters(f64);

/// An error indicating an invalid length measurement.
#[derive(Debug, thiserror::Error)]
#[error("Length cannot be negative: {0}")]
pub struct NegativeLength(f64);

impl Meters {
    /// Creates a new `Meters` instance from a floating-point value.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied value is negative.
    pub fn new(value: f64) -> Result<Meters, NegativeLength> {
        if value < 0.0 {
            Err(NegativeLength(value))
        } else {
            Ok(Meters(value))
        }
    }

    /// Get the raw `f64` value
    #[must_use]
    pub fn raw(&self) -> f64 {
        self.0
    }
}

impl std::fmt::Display for Meters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} meters", self.0)
    }
}
```

This implementation pattern (sometimes called the "newtype pattern") ensures properties we would otherwise need to
enforce by inspection.

1. The programmer can't forget to handle negative lengths.
2. The function won't be passed values in the wrong units.

More, this pattern does not require constant defensive coding or require the programmer to understand and account for
all possible code paths which might invoke the compute volume function.
