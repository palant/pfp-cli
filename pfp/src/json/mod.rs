/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

pub use serde::de::Deserialize as Deserializable;
pub use serde::ser::Serialize as Serializable;
pub use serde::*;
pub use serde_json::{from_slice, from_str, json, to_string, to_vec, Error, Value};

mod macros;

// This seems to be a Rust bug, this import is considered unused.
#[allow(unused_imports)]
pub use macros::*;

pub mod secret_serialization;
