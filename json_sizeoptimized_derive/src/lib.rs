/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

mod attrs;
mod container;
mod field;
mod variant;
mod deserialize;
mod serialize;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(Serialize, attributes(serde))]
pub fn serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    serialize::process(&input)
        .unwrap_or_else(|error| error.into_compile_error())
        .into()
}

#[proc_macro_derive(Deserialize, attributes(serde))]
pub fn deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    deserialize::process(&input)
        .unwrap_or_else(|error| error.into_compile_error())
        .into()
}
