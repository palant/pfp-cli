/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

#[macro_export]
macro_rules! const_serializable {
    ($name:ident: $type:ident = $value:literal) => {
        #[derive(Debug)]
        struct $name;

        impl json::Serializable for $name {
            fn serialize(&self) -> Result<json::Value, json::Error> {
                $value.serialize()
            }
        }

        impl<'de> json::Deserializable<'de> for $name {
            fn deserialize(json_value: &json::Value) -> Result<Self, json::Error> {
                let value = $type::deserialize(json_value)?;
                if value == $value {
                    Ok(Self {})
                } else {
                    Err(json::invalid_value(json_value, &format!("{}", $value)))
                }
            }
        }
    };
}

#[macro_export]
macro_rules! enumset_serialization {
    ($name:ident : $($variant:ident = $key:literal),+) => {
        pub fn serialize(value: &enumset::EnumSet<$name>) -> Result<json::Value, json::Error>
        {
            let mut obj = json::Map::new();
            $(obj.insert($key.to_string(), value.contains($name::$variant).into());)*
            Ok(json::Value::Object(obj))
        }

        pub fn serialize_flatly(value: &enumset::EnumSet<$name>, obj: &mut json::Map<String, json::Value>) -> Result<(), json::Error>
        {
            $(obj.insert($key.to_string(), value.contains($name::$variant).into());)*
            Ok(())
        }

        pub fn deserialize(value: &json::Value) -> Result<enumset::EnumSet<$name>, json::Error>
        {
            let mut result = enumset::EnumSet::<$name>::empty();
            let obj = value
                .as_object()
                .ok_or_else(|| json::invalid_type(value, "object"))?;

            for (key, value) in obj {
                match key.as_str() {
                    $(
                        $key => {
                            let exists = value.as_bool().ok_or_else(|| json::invalid_type(value, "boolean"))?;
                            if exists {
                                result.insert($name::$variant);
                            }
                        }
                    )*
                    _key => continue,
                }
            }

            Ok(result)
        }
    }
}
