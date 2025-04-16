// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `fixin` is a very simple test fixture tool.
//!
//! The idea is to wrap arbitrary tests in other functions (which are responsible for setup and
//! tear down).
//!
//! For example, imagine you have the test
//!
//! ```
//! #[test]
//! fn test_which_needs_some_setup() {
//!     // ... test logic ...
//! }
//! ```
//!
//! You could write something like
//!
//! ```
//! # fn do_setup() {}
//! # fn do_teardown() {}
//! #[test]
//! fn test_which_needs_some_setup() {
//!     do_setup();
//!     // ... test logic ...
//!     do_teardown();
//! }
//! ```
//!
//! but now you have a problem: what if the test fails before you call `do_teardown`?
//!
//! You could try to rig your test to always call the teardown.
//! But this will require messing with what would otherwise be very direct test logic.
//! Tests themselves need to be as simple as possible, so this is fairly undesirable.
//!
//! The simplest method I know of to address this problem is a decorator strategy.
//!
//! That is where this crate comes in.

extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{ExprCall, ItemFn, parse_macro_input};

/// `wrap` is a decorator method aimed at making test fixtures (or function decorators in general)
/// easier to use.
/// Somewhat formally, `wrap` accepts an `impl FnOnce(F) -> T where F: FnOnce() -> T` and produces
/// a test function wrapped in the supplied function.
///
/// That is a somewhat dense explanation, so an example is in order.
///
/// Imagine you have
///
/// ```
/// # struct SetupParms;
/// # struct TeardownParams;
/// # fn do_setup(_: SetupParms) {}
/// # fn do_teardown(_: TeardownParams) {}
/// #[test]
/// fn test_which_needs_setup_and_teardown() {
///     do_setup(SetupParms);
///     // ... test logic ...
///     do_teardown(TeardownParams);
/// }
/// ```
///
/// but what you want is something
///
/// ```nocompile
/// #[test]
/// #[with_setup_and_teardown]
/// fn test_which_needs_setup_and_teardown() {
///     // ... test logic ...
/// }
/// ```
/// Then you can write
///
/// ```
/// # struct SetupParms;
/// # struct TeardownParams;
/// # fn do_setup(_: SetupParms) {}
/// # fn do_teardown(_: TeardownParams) {}
/// # use std::panic::{catch_unwind, RefUnwindSafe, UnwindSafe};
///
/// fn with_setup_and_teardown<F: UnwindSafe + FnOnce() -> T, T>(
///     setup_params: SetupParms,
///     teardown_params: TeardownParams,
/// ) -> impl FnOnce(F) -> T {
///     move |f: F| {
///         do_setup(setup_params);
///         let ret = catch_unwind(f);
///         do_teardown(teardown_params);
///         ret.unwrap() // could match here as well
///     }
/// }
///
/// #[test]
/// #[fixin::wrap(with_setup_and_teardown(SetupParams, TeardownParams))]
/// fn my_test() {
///     // regular test logic
/// }
///
/// #[test]
/// #[fixin::wrap(with_setup_and_teardown(SetupParams, TeardownParams))]
/// fn my_other_test() {
///     // regular test logic
/// }
/// ```
#[proc_macro_attribute]
#[proc_macro_error2::proc_macro_error]
pub fn wrap(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as ExprCall);

    let parsed = parse_macro_input!(input as ItemFn);

    let attrs = &parsed.attrs;
    let sig = &parsed.sig;
    let func_name = &parsed.sig.ident;

    let mut parsed = parsed.clone();
    parsed.attrs = vec![];

    let tokens = quote! {
        #(#attrs)*
        #sig {
            #parsed
            #args(#func_name)
        }
    };

    tokens.into()
}
