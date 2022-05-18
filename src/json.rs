/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

macro_rules! const_serializable {
    ($name:ident: $type:ident = $value:literal) => {
        #[derive(Debug)]
        struct $name;

        impl serde::ser::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                $value.serialize(serializer)
            }
        }

        impl<'de> serde::de::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                let value = $type::deserialize(deserializer)?;
                if value == $value {
                    Ok(Self {})
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Unexpected value {}, expected {}",
                        value, $value
                    )))
                }
            }
        }
    };
}

pub(crate) use const_serializable;
