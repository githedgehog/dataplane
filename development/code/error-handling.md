# Error handling guidelines

## Primary rule

**Undefined behavior is absolutely never acceptable.**

- Methods such as `panic` / `abort` / `unwrap` / `expect` are **not** undefined behavior.
- Such methods are still best to avoid where reasonable error handling is possible.

## Guidelines

- **Use error types**
  - **Prefer returning a [`Result`] type rather than panicking**.
    - This rule is especially true in library code.
    - This rule is less strictly required for application code but still typically recommended.

  - More generally, **use dedicated error types**.

    `enums` or `structs` decorated with the `#[derive(Debug, thiserror::Error )]` attribute are extremely helpful for
    error handling.
    They allow the compiler to enforce exhaustive matching on error types, and massively assist in downstream
    refactoring when the number or type of possible errors changes.

    Any deviation from this pattern should be
    - carefully considered,
    - explicitly justified in documentation,
    - and treated with skepticism and prejudice on later review.

  - **Option** is not a good error

    Avoid using `Option` as an error type.
    Instead, use a dedicated error type that indicates the absence of a value is an error.
    Even using `Result<T, ()>` is preferable to `Option` as it suggests an error rather than a missing, but optional
    value.

  - **String errors**

    Arbitrary `String` or "string like" errors are **strongly discouraged** and must only be used where absolutely
    necessary (such as when they are imposed on us by an external framework).
    Such errors are _actively hostile_ to correct and sustainable error handling.
    Matching on string contents to determine how to handle an error is extremely fragile and should almost always be
    rejected as hazardous.
    Because naked string errors functionally can't be handled reliably, they are basically just a `panic` in disguise.

    Note: if an error description string is needed or helpful then use one!
    Include the error string as a field in a strongly typed error.
    This is an enormously superior option to simply returning a `String`.

  - **Numeric error codes**

    Numeric error codes are an edge case we regrettably need to deal with.
    Some interactions (especially low level hardware interactions) have limited ability to communicate errors.
    Such systems typically set values like [errno] or DPDK's [`rte_errno`].
    This pattern can not be avoided altogether.
    In these cases, we should use a translation type to construct a strongly typed error from these numeric codes.

- **Handle errors at the periphery.**
  - The primary logic of your application should be principally concerned with manipulating data structures
    which are statically proven to be valid and adhere to documented invariants.
    The general flow of a library should be

    ```mermaid
    ---
    title: desired data flow
    ---
    graph LR
      entry["untrusted input"] --> parsing["parsing"]
      parsing --> validated["validated type"]
      parsing --> rejected["rejected data<br/>wrapped in error type"]
      validated --> logic["business logic"]
      logic --> output["output"]
    ```

    One advantage of this pattern is that it isolates the business logic of your library from other mechanisms such as
    error reporting.

    See the [typestate pattern] for expanded discussion on this theme (as well as generally great programming advice).

## Exceptions

Some errors are simply not recoverable.

- **Programmer error is never recoverable.**
  If your program's logic is incorrect, you need to fix it.
  Attempting to work around broken logic at runtime will only magnify the problem; you end up introducing needless
  complexity in the form of unnecessary defensive logic.

  It **is** sometimes reasonable to write checks against programmer errors, but if they are found then the best you
  can do is panic with a descriptive message.

  If you write a check against a programmer error, avoid calling `panic!` in the error case.
  Instead, call `unreachable!()` to indicate that the code should never be reached.
  This is a useful signal to
  1. code reviewers,
  2. future readers of your code,
  3. users reporting that your program is broken.

- **Memory integrity errors are never recoverable.**
  - All forms of memory corruption and illegal memory access are categorically fatal.
  - Do not attempt to recover from these errors.
    Panic or abort the program instead.
    Since most forms of memory corruption are the result of programmer errors, it is best to exit the program with
    `unreachable!()` instead of `panic!()` in such cases.

**More rarely**: error handling logic can be so damaging to programmer ergonomics that it is preferable to panic
rather than handle the error.

Examples include memory allocation failure, or (sometimes) floating point exceptions such as NaN.

[typestate pattern]: https://cliffle.com/blog/rust-typestate/
[errno]: https://www.man7.org/linux/man-pages/man3/errno.3.html
[`rte_errno`]: https://doc.dpdk.org/api/rte__errno_8h.html
