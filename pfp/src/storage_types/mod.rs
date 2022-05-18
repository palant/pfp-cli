/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Various types processed by storage functions.

mod character_set;
pub use character_set::{CharacterSet, CharacterType};

mod password;
pub use password::{GeneratedPassword, Password, PasswordId, StoredPassword};

mod site;
pub use site::Site;
