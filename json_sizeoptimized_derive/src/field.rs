/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::attrs::get_attrs;
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{spanned::Spanned, ExprPath, Ident, Lit, LitStr};

fn parse_path(lit: &Lit) -> Result<ExprPath, syn::Error> {
    match lit {
        Lit::Str(lit) => lit.parse(),
        _ => Err(syn::Error::new_spanned(lit, "Expected string literal")),
    }
}

pub struct Field {
    pub ident: Ident,
    pub skip: bool,
    pub flatten: bool,
    pub default: Option<ExprPath>,
    pub rename: Option<TokenStream>,
    pub skip_if: Option<ExprPath>,
    pub with: Option<ExprPath>,
}

impl TryFrom<&syn::Field> for Field {
    type Error = syn::Error;

    fn try_from(value: &syn::Field) -> Result<Self, Self::Error> {
        let ident = value
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new_spanned(value, "Field has no name"))?;
        let mut skip = false;
        let mut flatten = false;
        let mut default = None;
        let mut rename = None;
        let mut skip_if = None;
        let mut with = None;

        for attr in get_attrs(&value.attrs)? {
            if attr.name.is_ident("rename") {
                if let Some(value) = &attr.value {
                    rename = Some(value.to_token_stream());
                } else {
                    return Err(syn::Error::new_spanned(
                        attr.token,
                        "rename attribute should have a value",
                    ));
                }
            } else if attr.name.is_ident("skip_serializing_if") {
                if let Some(value) = &attr.value {
                    skip_if = Some(parse_path(value)?);
                } else {
                    return Err(syn::Error::new_spanned(
                        attr.token,
                        "rename attribute should have a value",
                    ));
                }
            } else if attr.name.is_ident("with") {
                if let Some(value) = &attr.value {
                    with = Some(parse_path(value)?);
                } else {
                    return Err(syn::Error::new_spanned(
                        attr.token,
                        "with attribute should have a value",
                    ));
                }
            } else if attr.name.is_ident("skip") {
                skip = true;
            } else if attr.name.is_ident("flatten") {
                flatten = true;
            } else if attr.name.is_ident("default") {
                if let Some(value) = &attr.value {
                    default = Some(parse_path(value)?);
                } else {
                    default = Some(LitStr::new("Default::default", attr.token.span()).parse()?);
                }
            } else {
                return Err(syn::Error::new_spanned(attr.token, "Unsupported attribute"));
            }
        }

        Ok(Self {
            ident: ident.clone(),
            skip,
            flatten,
            default,
            rename,
            skip_if,
            with,
        })
    }
}
