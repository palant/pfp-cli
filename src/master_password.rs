/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::crypto;
use crate::storage;

use rand::Rng;
use std::path;

pub fn change_password(storage_path: &path::PathBuf, master_password: &String)
{
    let salt = rand::thread_rng().gen::<[u8; 16]>();

    // Replicate salt being converted to UTF-8 as done by JS code
    let mut salt_str = String::new();
    for byte in salt
    {
        salt_str.push(byte as char);
    }

    let key = crypto::derive_key(master_password, salt_str.as_bytes());
    let hmac_secret = rand::thread_rng().gen::<[u8; 32]>();
    storage::init(storage_path, &key, &salt, &hmac_secret);
}
