/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::attrs::get_attrs;
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{Fields, Ident};

pub struct Variant {
    pub ident: Ident,
    pub rename: Option<TokenStream>,
}

impl TryFrom<&syn::Variant> for Variant {
    type Error = syn::Error;

    fn try_from(value: &syn::Variant) -> Result<Self, Self::Error> {
        if let Fields::Unnamed(fields) = &value.fields {
            if fields.unnamed.len() != 1 {
                return Err(syn::Error::new_spanned(
                    fields,
                    format!(
                        "Expected exactly 1 field for the variant, got {}",
                        fields.unnamed.len()
                    ),
                ));
            }
        } else {
            return Err(syn::Error::new_spanned(
                &value.fields,
                "Expected variant with unnamed fields",
            ));
        }

        let mut rename = None;
        for attr in get_attrs(&value.attrs)? {
            if attr.name.is_ident("rename") {
                if let Some(value) = &attr.value {
                    rename = Some(value.to_token_stream());
                } else {
                    return Err(syn::Error::new_spanned(attr.token, "rename attribute should have a value"));
                }
            } else {
                return Err(syn::Error::new_spanned(attr.token, "Unsupported attribute"));
            }
        }

        Ok(Self {
            ident: value.ident.clone(),
            rename: rename,
        })
    }
}
