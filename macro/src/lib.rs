extern crate proc_macro;
use proc_macro::TokenStream;

use syn::{parse_macro_input, DeriveInput};
use quote::quote;

#[proc_macro_derive(Error)]
pub fn pretend_to_derive_thiserror_error(input: TokenStream) -> TokenStream {
    input
}
