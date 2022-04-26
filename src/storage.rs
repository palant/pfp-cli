/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::crypto;
use json::object;
use std::fs;
use std::path;

const APPLICATION_KEY: &str = "application";
const APPLICATION_VALUE: &str = "pfp";
const FORMAT_KEY: &str = "format";
const CURRENT_FORMAT: u32 = 3;
const SALT_KEY: &str = "salt";
const HMAC_SECRET_KEY: &str = "hmac-secret";
const DATA_KEY: &str = "data";

fn insert_encrypted(obj: &mut json::JsonValue, key: &String, value: &json::JsonValue, encryption_key: &[u8])
{
    obj.insert(key, crypto::encrypt_data(value.dump().as_bytes(), encryption_key)).unwrap();
}

pub fn init(path: &path::PathBuf, encryption_key: &[u8], salt: &[u8], hmac_secret: &[u8])
{
    let mut root = object!{};
    root.insert(APPLICATION_KEY, APPLICATION_VALUE).unwrap();
    root.insert(FORMAT_KEY, CURRENT_FORMAT).unwrap();

    let mut data = object!{};
    data.insert(SALT_KEY, base64::encode(salt)).unwrap();
    insert_encrypted(&mut data, &HMAC_SECRET_KEY.to_string(), &base64::encode(hmac_secret).into(), encryption_key);
    root.insert(DATA_KEY, data).unwrap();

    let parent = path.parent();
    if parent.is_some()
    {
        fs::create_dir_all(parent.unwrap()).unwrap();
    }
    fs::write(path, json::stringify(root)).unwrap();
}
