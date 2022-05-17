/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use serde::ser::{Serializer, SerializeMap};
use serde::de::{Deserializer, Visitor, MapAccess};

#[derive(enumset::EnumSetType, Debug)]
/// Possible character types that a password is generated from.
pub enum CharacterType
{
    /// Lower-case letters
    Lower,
    /// Upper-case letters
    Upper,
    /// Digits
    Digit,
    /// Various non-alphanumeric characters
    Symbol,
}

/// A set of character types to generate a password from.
pub type CharacterSet = enumset::EnumSet<CharacterType>;

pub fn serialize<S: Serializer>(charset: &CharacterSet, serializer: S) -> Result<S::Ok, S::Error>
{
    let mut map = serializer.serialize_map(None)?;
    map.serialize_entry("lower", &charset.contains(CharacterType::Lower))?;
    map.serialize_entry("upper", &charset.contains(CharacterType::Upper))?;
    map.serialize_entry("number", &charset.contains(CharacterType::Digit))?;
    map.serialize_entry("symbol", &charset.contains(CharacterType::Symbol))?;
    map.end()
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<CharacterSet, D::Error>
{
    struct CharacterSetVisitor;

    impl<'de> Visitor<'de> for CharacterSetVisitor
    {
        type Value = CharacterSet;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result
        {
            formatter.write_str("character set definition")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error>
        {
            let mut charset = CharacterSet::empty();

            loop
            {
                match map.next_key::<&str>()?
                {
                    None => break,
                    Some("lower") =>
                    {
                        if map.next_value::<bool>()?
                        {
                            charset.insert(CharacterType::Lower);
                        }
                    },
                    Some("upper") =>
                    {
                        if map.next_value::<bool>()?
                        {
                            charset.insert(CharacterType::Upper);
                        }
                    },
                    Some("number") =>
                    {
                        if map.next_value::<bool>()?
                        {
                            charset.insert(CharacterType::Digit);
                        }
                    },
                    Some("symbol") =>
                    {
                        if map.next_value::<bool>()?
                        {
                            charset.insert(CharacterType::Symbol);
                        }
                    },
                    Some(_key) => continue,
                }
            }
            Ok(charset)
        }
    }

    deserializer.deserialize_map(CharacterSetVisitor {})
}
