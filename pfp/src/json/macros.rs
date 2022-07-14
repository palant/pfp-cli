/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

macro_rules! const_serializable {
    ($name:ident: $type:ident = $value:literal) => {
        #[derive(Debug)]
        struct $name;

        impl crate::json::Serializable for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: crate::json::ser::Serializer,
            {
                $value.serialize(serializer)
            }
        }

        impl<'de> crate::json::Deserializable<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: crate::json::de::Deserializer<'de>,
            {
                let value = $type::deserialize(deserializer)?;
                if value == $value {
                    Ok(Self {})
                } else {
                    Err(crate::json::de::Error::custom(format!(
                        "Unexpected value {}, expected {}",
                        value, $value
                    )))
                }
            }
        }
    };
}

pub(crate) use const_serializable;

macro_rules! enumset_serialization {
    ($name:ident : $($variant:ident = $key:literal),+) => {
        pub fn serialize<S>(value: &enumset::EnumSet<$name>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: crate::json::ser::Serializer
        {
            use crate::json::ser::SerializeMap;

            let mut map = serializer.serialize_map(None)?;
            $(map.serialize_entry($key, &value.contains($name::$variant))?;)*
            map.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<enumset::EnumSet<$name>, D::Error>
            where
                D: crate::json::de::Deserializer<'de>
        {
            struct Visitor;

            impl<'de> crate::json::de::Visitor<'de> for Visitor {
                type Value = enumset::EnumSet<$name>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str(concat!("set of ", stringify!($name), " values"))
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: crate::json::de::MapAccess<'de>
                {
                    let mut result = Self::Value::empty();

                    loop {
                        match map.next_key::<&str>()? {
                            None => break,
                            $(
                                Some($key) => {
                                    if map.next_value::<bool>()? {
                                        result.insert($name::$variant);
                                    }
                                }
                            )*
                            Some(_key) => continue,
                        }
                    }
                    Ok(result)
                }
            }

            deserializer.deserialize_map(Visitor {})
        }
    }
}

pub(crate) use enumset_serialization;
