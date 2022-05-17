/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use serde::ser::{Serializer, SerializeMap};
use serde::de::{Deserializer, Visitor, Deserialize, MapAccess, Unexpected, Error};
use super::{Password, StoredPassword, GeneratedPassword, CharacterSet, CharacterType};

pub fn serialize_charset<S: Serializer>(charset: &CharacterSet, serializer: S) -> Result<S::Ok, S::Error>
{
    let mut map = serializer.serialize_map(None)?;
    map.serialize_entry("lower", &charset.contains(CharacterType::Lower))?;
    map.serialize_entry("upper", &charset.contains(CharacterType::Upper))?;
    map.serialize_entry("number", &charset.contains(CharacterType::Digit))?;
    map.serialize_entry("symbol", &charset.contains(CharacterType::Symbol))?;
    map.end()
}

impl<'de> Deserialize<'de> for Password
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
    {
        deserializer.deserialize_map(PasswordVisitor {})
    }
}

struct PasswordVisitor;

impl<'de> Visitor<'de> for PasswordVisitor
{
    type Value = Password;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        formatter.write_str("PfP password data")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error>
    {
        let mut pwdtype = 0;
        let mut site = None;
        let mut name = None;
        let mut revision = None;
        let mut length = None;
        let mut charset = CharacterSet::empty();
        let mut password = None;
        let mut notes = None;

        loop
        {
            match map.next_key::<&str>()?
            {
                None => break,
                Some("type") =>
                {
                    let value = map.next_value::<String>()?;
                    if value == "generated2"
                    {
                        pwdtype = 1;
                    }
                    else if value == "stored"
                    {
                        pwdtype = 2;
                    }
                    else
                    {
                        return Err(Error::invalid_value(Unexpected::Str(&value), &"generated2 or stored"));
                    }
                },
                Some("site") =>
                {
                    site = Some(map.next_value::<String>()?);
                },
                Some("name") =>
                {
                    name = Some(map.next_value::<String>()?);
                },
                Some("revision") =>
                {
                    revision = Some(map.next_value::<String>()?);
                },
                Some("length") =>
                {
                    length = Some(map.next_value::<usize>()?);
                },
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
                Some("password") =>
                {
                    password = Some(map.next_value::<String>()?);
                },
                Some("notes") =>
                {
                    notes = Some(map.next_value::<String>()?);
                },
                Some(key) =>
                {
                    return Err(Error::unknown_field(key, &[]));
                },
            }
        }

        if pwdtype == 1
        {
            if password.is_some()
            {
                return Err(Error::unknown_field("password", &[]));
            }
            if charset.is_empty()
            {
                return Err(Error::missing_field("lower/upper/number/symbol"));
            }
            let mut result = GeneratedPassword::new(
                &site.ok_or_else(|| Error::missing_field("site"))?,
                &name.ok_or_else(|| Error::missing_field("name"))?,
                &revision.ok_or_else(|| Error::missing_field("revision"))?,
                length.ok_or_else(|| Error::missing_field("length"))?,
                charset,
            );
            if let Some(value) = notes
            {
                result.set_notes(&value);
            }
            Ok(Password::Generated { password: result })
        }
        else if pwdtype == 2
        {
            if length.is_some()
            {
                return Err(Error::unknown_field("length", &[]));
            }
            if !charset.is_empty()
            {
                return Err(Error::unknown_field("lower/upper/number/symbol", &[]));
            }
            let mut result = StoredPassword::new(
                &site.ok_or_else(|| Error::missing_field("site"))?,
                &name.ok_or_else(|| Error::missing_field("name"))?,
                &revision.ok_or_else(|| Error::missing_field("revision"))?,
                &password.ok_or_else(|| Error::missing_field("password"))?,
            );
            if let Some(value) = notes
            {
                result.set_notes(&value);
            }
            Ok(Password::Stored { password: result })
        }
        else
        {
            Err(Error::missing_field("type"))
        }
    }
}
