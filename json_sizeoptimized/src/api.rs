/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::{Error, Map, Value};

pub trait Serializable {
    fn serialize(&self) -> Result<Value, Error>;
}

pub trait FlatlySerializable {
    fn serialize_flatly(&self, obj: &mut Map<String, Value>) -> Result<(), Error>;
}

pub trait Deserializable<'de> {
    fn deserialize(value: &Value) -> Result<Self, Error>
    where
        Self: Sized;
}

pub fn from_str<'de, T: Deserializable<'de>>(string: &str) -> Result<T, Error> {
    T::deserialize(&serde_json::from_str(string)?)
}

pub fn to_string<T: Serializable>(value: &T) -> Result<String, Error> {
    serde_json::to_string(&value.serialize()?)
}

pub fn to_vec<T: Serializable>(value: &T) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&value.serialize()?)
}
