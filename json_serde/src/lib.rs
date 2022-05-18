/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

pub use serde::ser::Serialize as Serializable;
pub use serde::de::Deserialize as Deserializable;
pub use serde::*;
pub use serde_json::{from_str, to_string, to_vec, Value, Error, json};

mod macros;
pub use macros::*;
