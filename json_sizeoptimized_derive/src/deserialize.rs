/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::container::{Container, StructContainer, EnumContainer};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::DeriveInput;

fn process_struct(container: StructContainer) -> Result<TokenStream, syn::Error> {
    let mut field_deserializers = Vec::new();

    for field in &container.fields {
        let ident = &field.ident;
        if field.skip {
            field_deserializers.push(quote! {
                #ident: Default::default(),
            });
            continue;
        }

        let source_value = if field.flatten {
            quote! { value }
        } else {
            let key = match &field.rename {
                Some(literal) => literal.clone(),
                None => {
                    quote! {
                        stringify!(#ident)
                    }
                }
            };

            if field.skip_if.is_some() {
                quote! {
                    obj.get(#key).unwrap_or_else(|| &json::Value::Null)
                }
            } else {
                quote! {
                    obj.get(#key).ok_or_else(|| json::key_missing(#key))?
                }
            }
        };

        let path = if let Some(module) = &field.with {
            module.to_token_stream()
        } else {
            quote! { json }
        };

        let deserializer = if field.skip_if.is_some() {
            quote! {
                #ident: match #source_value {
                    json::Value::Null => Default::default(),
                    other => #path::deserialize(other)?,
                },
            }
        } else {
            quote! {
                #ident: #path::deserialize(#source_value)?,
            }
        };

        field_deserializers.push(deserializer);
    }

    let ident = &container.ident;
    Ok(quote! {
        const _: () = {
            use json::Deserializable;

            impl<'de> json::Deserializable<'de> for #ident {
                fn deserialize(value: &json::Value) -> Result<Self, json::Error> {
                    let obj = value.as_object().ok_or_else(|| json::invalid_type(value, "object"))?;

                    Ok(Self {
                        #(#field_deserializers)*
                    })
                }
            }
        };
    })
}

fn process_enum(container: EnumContainer) -> Result<TokenStream, syn::Error> {
    let tag = container.tag;

    let mut variant_deserializers = Vec::new();
    for variant in &container.variants {
        let variant_ident = &variant.ident;
        let tag_value = match &variant.rename {
            Some(literal) => literal.clone(),
            None => {
                quote! {
                    stringify!(#variant_ident)
                }
            }
        };

        variant_deserializers.push(quote! {
            #tag_value => Self::#variant_ident(json::deserialize(value)?),
        });
    }

    let ident = &container.ident;
    Ok(quote! {
        use json::Deserializable;

        impl<'de> json::Deserializable<'de> for #ident {
            fn deserialize(value: &json::Value) -> Result<Self, json::Error> {
                let obj = value.as_object().ok_or_else(|| json::invalid_type(value, "object"))?;
                let tag_value = obj.get(#tag).ok_or_else(|| json::key_missing(#tag))?;
                let tag = tag_value.as_str().ok_or_else(|| json::invalid_type(tag_value, "string"))?;

                Ok(match tag {
                    #(#variant_deserializers)*
                    other => return Err(json::invalid_value(tag_value, "enum tag")),
                })
            }
        }
    })
}

pub fn process(input: &DeriveInput) -> Result<TokenStream, syn::Error> {
    match Container::try_from(input)? {
        Container::Struct(value) => process_struct(value),
        Container::Enum(value) => process_enum(value),
    }
}
