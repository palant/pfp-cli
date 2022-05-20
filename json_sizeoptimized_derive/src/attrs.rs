/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use syn::{Attribute, Lit, Meta, NestedMeta, Path};

pub struct Attr {
    pub name: Path,
    pub value: Option<Lit>,
    pub token: NestedMeta,
}

pub fn get_attrs(attrs: &[Attribute]) -> Result<Vec<Attr>, syn::Error> {
    let mut result = Vec::new();

    for attr in attrs {
        if !attr.path.is_ident("serde") {
            continue;
        }

        if let Meta::List(list) = attr.parse_meta()? {
            for nested in list.nested {
                match &nested {
                    NestedMeta::Meta(Meta::NameValue(name_value)) => {
                        result.push(Attr {
                            name: name_value.path.clone(),
                            value: Some(name_value.lit.clone()),
                            token: nested.clone(),
                        });
                    }
                    NestedMeta::Meta(Meta::Path(path)) => {
                        result.push(Attr {
                            name: path.clone(),
                            value: None,
                            token: nested.clone(),
                        });
                    }
                    _ => {
                        return Err(syn::Error::new_spanned(nested, "Unexpected attribute"));
                    }
                }
            }
        } else {
            return Err(syn::Error::new_spanned(attr, "Unexpected attribute"));
        }
    }

    Ok(result)
}
