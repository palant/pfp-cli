/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::{Deserializable, Error, Serializable, Value};

macro_rules! impl_serialize {
    ($type:ident, $conversion:ident) => {
        impl Serializable for $type {
            fn serialize(&self) -> Result<Value, Error> {
                Ok($conversion(self))
            }
        }
    };
}

macro_rules! impl_deserialize {
    ($type:ident, $conversion:ident, $expect:literal) => {
        impl<'de> Deserializable<'de> for $type {
            fn deserialize(value: &Value) -> Result<Self, Error> {
                $conversion(value).ok_or_else(|| crate::invalid_type(value, stringify!($type)))
            }
        }
    };
}

macro_rules! impl_convertible {
    ($type:ident, $conversion:ident, $expect:literal) => {
        const _: () = {
            fn __conf_from(value: &$type) -> Value {
                Value::from(*value)
            }
            impl_serialize!($type, __conf_from);

            fn __conv_to(value: &Value) -> Option<$type> {
                value.$conversion().map(|value| value as $type)
            }
            impl_deserialize!($type, __conv_to, $expect);
        };
    };
}

macro_rules! impl_number {
    ($type:ident, $conversion:ident) => {
        impl_convertible!($type, $conversion, "number");
    };
}

fn string_to_value(value: &str) -> Value {
    Value::from(value)
}

fn string_from_value(value: &Value) -> Option<String> {
    value.as_str().map(|str| str.to_string())
}

impl_number!(u8, as_u64);
impl_number!(u16, as_u64);
impl_number!(u32, as_u64);
impl_number!(u64, as_u64);
impl_number!(usize, as_u64);
impl_number!(i8, as_i64);
impl_number!(i16, as_i64);
impl_number!(i32, as_i64);
impl_number!(i64, as_i64);
impl_number!(isize, as_i64);
impl_number!(f32, as_f64);
impl_number!(f64, as_f64);
impl_convertible!(bool, as_bool, "boolean");
impl_serialize!(str, string_to_value);
impl_serialize!(String, string_to_value);
impl_deserialize!(String, string_from_value, "string");

impl<T> Serializable for std::collections::HashMap<String, T>
where
    T: Serializable,
{
    fn serialize(&self) -> Result<Value, Error> {
        let mut result = serde_json::Map::new();
        for (key, value) in self.iter() {
            result.insert(key.to_string(), value.serialize()?);
        }
        Ok(Value::Object(result))
    }
}

impl<'de, T> Deserializable<'de> for std::collections::HashMap<String, T>
where
    T: Deserializable<'de>,
{
    fn deserialize(value: &Value) -> Result<Self, Error> {
        let mut result = std::collections::HashMap::new();
        let obj = value
            .as_object()
            .ok_or_else(|| crate::invalid_type(value, "object"))?;
        for (key, value) in obj.iter() {
            result.insert(key.to_owned(), T::deserialize(value)?);
        }
        Ok(result)
    }
}

impl<T> Serializable for Option<T>
where
    T: Serializable,
{
    fn serialize(&self) -> Result<Value, Error> {
        match self {
            Some(value) => value.serialize(),
            None => Ok(Value::Null),
        }
    }
}

impl<'de, T> Deserializable<'de> for Option<T>
where
    T: Deserializable<'de>,
{
    fn deserialize(value: &Value) -> Result<Self, Error> {
        Ok(match value {
            Value::Null => None,
            _ => Some(T::deserialize(value)?),
        })
    }
}

impl<'de> Deserializable<'de> for Value {
    fn deserialize(value: &Value) -> Result<Self, Error> {
        Ok(value.clone())
    }
}
