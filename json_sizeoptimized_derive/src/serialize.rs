/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::container::{Container, StructContainer, EnumContainer};
use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;

fn process_struct(container: StructContainer) -> Result<TokenStream, syn::Error> {
    let mut field_serializers = Vec::new();

    for field in &container.fields {
        if field.skip {
            continue;
        }

        let ident = &field.ident;
        let mut serializer = if field.flatten {
            if let Some(module) = &field.with {
                quote! {
                    #module::serialize_flatly(&self.#ident, obj)?;
                }
            } else {
                quote! {
                    self.#ident.serialize_flatly(obj)?;
                }
            }
        } else {
            let key = match &field.rename {
                Some(literal) => literal.clone(),
                None => {
                    quote! {
                        stringify!(#ident)
                    }
                }
            };

            let value = if let Some(module) = &field.with {
                quote! {
                    #module.serialize(self.#ident)
                }
            } else {
                quote! {
                    self.#ident.serialize()
                }
            };

            quote! {
                obj.insert(#key.to_string(), #value?);
            }
        };

        if let Some(condition) = &field.skip_if {
            serializer = quote! {
                if !#condition(&self.#ident) {
                    #serializer
                }
            };
        }

        field_serializers.push(serializer);
    }

    let ident = &container.ident;
    Ok(quote! {
        const _: () = {
            use json::{Serializable, FlatlySerializable};

            impl json::Serializable for #ident {
                fn serialize(&self) -> Result<json::Value, json::Error> {
                    let mut _obj = json::Map::new();

                    let obj = &mut _obj;
                    #(#field_serializers)*

                    Ok(json::Value::Object(_obj))
                }
            }

            impl json::FlatlySerializable for #ident {
                fn serialize_flatly(&self, obj: &mut json::Map<String, json::Value>) -> Result<(), json::Error> {
                    #(#field_serializers)*

                    Ok(())
                }
            }
        };
    })
}

fn process_enum(container: EnumContainer) -> Result<TokenStream, syn::Error> {
    let mut variant_serializers = Vec::new();
    let tag = container.tag;
    let ident = &container.ident;

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

        let serializer = quote! {
            #ident::#variant_ident(value) => {
                obj.insert(#tag.to_string(), #tag_value.into());
                value.serialize_flatly(obj)?;
            }
        };
        variant_serializers.push(serializer);
    }

    Ok(quote! {
        const _: () = {
            use json::{Serializable, FlatlySerializable};

            impl json::Serializable for #ident {
                fn serialize(&self) -> Result<json::Value, json::Error> {
                    let mut _obj = json::Map::new();
                    let obj = &mut _obj;

                    match self {
                        #(#variant_serializers)*
                    }

                    Ok(json::Value::Object(_obj))
                }
            }

            impl json::FlatlySerializable for #ident {
                fn serialize_flatly(&self, obj: &mut json::Map<String, json::Value>) -> Result<(), json::Error> {
                    match self {
                        #(#variant_serializers)*
                    }

                    Ok(())
                }
            }
        };
    })
}

pub fn process(input: &DeriveInput) -> Result<TokenStream, syn::Error> {
    match Container::try_from(input)? {
        Container::Struct(value) => process_struct(value),
        Container::Enum(value) => process_enum(value),
    }
}
