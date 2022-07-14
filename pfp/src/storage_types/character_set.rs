/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use json_streamed as json;

use json::enumset_serialization;

#[derive(enumset::EnumSetType, Debug)]
/// Possible character types that a password is generated from.
pub enum CharacterType {
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

enumset_serialization!(
    CharacterType: Lower = "lower",
    Upper = "upper",
    Digit = "number",
    Symbol = "symbol"
);
