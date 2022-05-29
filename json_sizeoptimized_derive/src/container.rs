/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::attrs::get_attrs;
use crate::field::Field;
use crate::variant::Variant;
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{Attribute, Data, DataEnum, DataStruct, DeriveInput, Ident};

pub enum Container {
    Struct(StructContainer),
    Enum(EnumContainer),
}

impl TryFrom<&DeriveInput> for Container {
    type Error = syn::Error;

    fn try_from(input: &DeriveInput) -> Result<Self, Self::Error> {
        match &input.data {
            Data::Struct(value) => Ok(Self::Struct(StructContainer::new(
                value,
                &input.ident,
                &input.attrs,
            )?)),
            Data::Enum(value) => Ok(Self::Enum(EnumContainer::new(
                value,
                &input.ident,
                &input.attrs,
            )?)),
            Data::Union(_) => Err(syn::Error::new_spanned(input, "Unions aren't supported")),
        }
    }
}

pub struct StructContainer {
    pub ident: Ident,
    pub fields: Vec<Field>,
}

impl StructContainer {
    pub fn new(value: &DataStruct, ident: &Ident, attrs: &[Attribute]) -> Result<Self, syn::Error> {
        for attr in get_attrs(attrs)? {
            if attr.name.is_ident("crate") {
                // Ignore, irrelevant here
            } else if attr.name.is_ident("deny_unknown_fields") {
                // TODO: Check for unknown fields?
            } else {
                return Err(syn::Error::new_spanned(attr.token, "Unsupported attribute"));
            }
        }

        Ok(Self {
            ident: ident.clone(),
            fields: value
                .fields
                .iter()
                .map(Field::try_from)
                .collect::<Result<Vec<Field>, syn::Error>>()?,
        })
    }
}

pub struct EnumContainer {
    pub ident: Ident,
    pub tag: TokenStream,
    pub variants: Vec<Variant>,
}

impl EnumContainer {
    pub fn new(value: &DataEnum, ident: &Ident, attrs: &[Attribute]) -> Result<Self, syn::Error> {
        let mut tag = None;

        for attr in get_attrs(attrs)? {
            if attr.name.is_ident("crate") {
                // Ignore, irrelevant here
            } else if attr.name.is_ident("tag") {
                if let Some(value) = attr.value {
                    tag = Some(value.to_token_stream());
                } else {
                    return Err(syn::Error::new_spanned(
                        attr.token,
                        "tag attribute should have a value",
                    ));
                }
            } else {
                return Err(syn::Error::new_spanned(attr.token, "Unsupported attribute"));
            }
        }

        if let Some(tag) = tag {
            Ok(Self {
                ident: ident.clone(),
                tag,
                variants: value
                    .variants
                    .iter()
                    .map(Variant::try_from)
                    .collect::<Result<Vec<Variant>, syn::Error>>()?,
            })
        } else {
            Err(syn::Error::new_spanned(
                value.enum_token,
                "Only internally tagged enums are supported",
            ))
        }
    }
}
