// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/// Macro to conditionally compile code if the `shuttle` feature is enabled for the *concurrency* crate.
///
/// This macro uses the feature flag as set for the *concurrency* crate itself,
/// not the crate in which the macro is imported.
///
/// # Example
/// ```
/// # use dataplane_concurrency::with_shuttle;
/// with_shuttle! {
///     fn only_compiled_with_shuttle() {
///         // code here
///     }
/// }
/// ```
#[cfg(all(feature = "shuttle", not(feature = "silence_clippy")))]
#[macro_export]
macro_rules! with_shuttle {
    ($($item:item)*) => {
        $(
            $item
        )*
    };
}

/// Macro to conditionally compile code if the `shuttle` feature is enabled for the *concurrency* crate.
///
/// This macro uses the feature flag as set for the *concurrency* crate itself,
/// not the crate in which the macro is imported.
///
/// # Example
/// ```
/// # use dataplane_concurrency::with_shuttle;
/// with_shuttle! {
///     fn only_compiled_with_shuttle() {
///         // code here
///     }
/// }
/// ```
#[cfg(not(feature = "shuttle"))]
#[macro_export]
macro_rules! with_shuttle {
    ($($item:item)*) => {};
}

/// Macro to conditionally compile code if the `loom` feature is enabled for the *concurrency* crate.
///
/// This macro uses the feature flag as set for the *concurrency* crate itself,
/// not the crate in which the macro is imported.
///
/// # Example
/// ```
/// # use dataplane_concurrency::with_loom;
/// with_loom! {
///     fn only_compiled_with_loom() {
///         // code here
///     }
/// }
/// ```
#[cfg(all(feature = "loom", not(feature = "silence_clippy")))]
#[macro_export]
macro_rules! with_loom {
    ($($item:item)*) => {
        $(
            $item
        )*
    };
}

/// Macro to conditionally compile code if the `loom` feature is enabled for the *concurrency* crate.
///
/// This macro uses the feature flag as set for the *concurrency* crate itself,
/// not the crate in which the macro is imported.
///
/// # Example
/// ```
/// # use dataplane_concurrency::with_loom;
/// with_loom! {
///     fn only_compiled_with_std() {
///         // code here
///     }
/// }
/// ```
#[cfg(not(feature = "loom"))]
#[macro_export]
macro_rules! with_loom {
    ($($item:item)*) => {};
}

/// Macro to conditionally compile code if the `std` feature is enabled for the *concurrency* crate.
///
/// This macro uses the feature flag as set for the *concurrency* crate itself,
/// not the crate in which the macro is imported.
///
/// # Example
/// ```
/// # use dataplane_concurrency::with_std;
/// with_std! {
///     fn only_compiled_with_std() {
///         // code here
///     }
/// }
/// ```
#[cfg(not(any(feature = "loom", feature = "shuttle")))]
#[macro_export]
macro_rules! with_std {
    ($($item:item)*) => {
        $(
            $item
        )*
    };
}

/// Macro to conditionally compile code if the `std` feature is enabled for the *concurrency* crate.
///
/// This macro uses the feature flag as set for the *concurrency* crate itself,
/// not the crate in which the macro is imported.
///
/// # Example
/// ```
/// # use dataplane_concurrency::with_std;
/// with_std! {
///     fn only_compiled_with_std() {
///         // code here
///     }
/// }
/// ```
#[cfg(all(feature = "loom", feature = "shuttle", feature = "silence_clippy"))]
#[macro_export]
macro_rules! with_std {
    ($($item:item)*) => {
        $(
            $item
        )*
    };
}

/// Macro to conditionally compile code if the `std` feature is enabled for the *concurrency* crate.
///
/// This macro uses the feature flag as set for the *concurrency* crate itself,
/// not the crate in which the macro is imported.
///
/// # Example
/// ```
/// # use dataplane_concurrency::with_std;
/// with_std! {
///     fn only_compiled_with_std() {
///         // code here
///     }
/// }
/// ```
#[cfg(all(
    not(feature = "silence_clippy"),
    any(feature = "loom", feature = "shuttle")
))]
#[macro_export]
macro_rules! with_std {
    ($($item:item)*) => {};
}

pub use concurrency_macros::concurrency_mode;
