/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use aes_gcm::aead::{Aead, NewAead};
use enumset;
use rand::Rng;
use scrypt::scrypt;

const AES_KEY_SIZE: usize = 256;
const AES_NONCE_SIZE: usize = 96;

// I, l, O, 0, 1 excluded because of potential confusion. ", ', \ excluded
// because of common bugs in web interfaces (magic quotes).
const CHARS_LOWER: &str = "abcdefghjkmnpqrstuvwxyz";
const CHARS_UPPER: &str = "ABCDEFGHJKMNPQRSTUVWXYZ";
const CHARS_DIGIT: &str = "23456789";
const CHARS_SYMBOL: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

#[derive(enumset::EnumSetType)]
pub enum CharacterType
{
    LOWER,
    UPPER,
    DIGIT,
    SYMBOL
}

const CHARS_MAPPING: [(CharacterType, &str); 4] = [
    (CharacterType::LOWER, CHARS_LOWER),
    (CharacterType::UPPER, CHARS_UPPER),
    (CharacterType::DIGIT, CHARS_DIGIT),
    (CharacterType::SYMBOL, CHARS_SYMBOL),
];

pub fn new_charset() -> enumset::EnumSet<CharacterType>
{
    return enumset::EnumSet::empty();
}

pub fn derive_bits(password: &[u8], salt: &[u8], size: usize) -> Vec<u8>
{
    let params = scrypt::Params::new(15, 8, 1).unwrap();
    let mut bytes: Vec<u8> = Vec::new();
    bytes.resize(size, 0);
    println!("{:?} {:?} {:?}", password, salt, size);
    scrypt(password, salt, &params, bytes.as_mut_slice()).unwrap();
    return bytes;
}

pub fn derive_password(master_password: &String, domain: &String, name: &String, revision: &String, length: usize, charset: enumset::EnumSet<CharacterType>) -> String
{
    let mut salt = domain.to_owned();
    salt.push_str("\0");
    salt.push_str(&name);
    if revision != "" && revision != "1"
    {
        salt.push_str("\0");
        salt.push_str(&revision);
    }

    let mut bytes = derive_bits(master_password.as_bytes(), salt.as_bytes(), length);
    return to_password(bytes.as_mut_slice(), charset);
}

fn to_password(bytes: &mut [u8], charset: enumset::EnumSet<CharacterType>) -> String
{
    let mut seen : enumset::EnumSet<CharacterType> = new_charset();
    for i in 0 .. bytes.len()
    {
        let allowed = if charset.len() - seen.len() >= bytes.len() - i { charset - seen } else { charset };

        let mut num_chars = 0;
        for j in CHARS_MAPPING
        {
            let chartype = j.0;
            if allowed.contains(chartype)
            {
                let chars = j.1;
                num_chars += chars.len();
            }
        }

        let mut index = usize::from(bytes[i]) % num_chars;
        for j in CHARS_MAPPING
        {
            let chartype = j.0;
            if allowed.contains(chartype)
            {
                let chars = j.1;
                if index < chars.len()
                {
                    bytes[i] = chars.as_bytes()[index];
                    seen.insert(chartype);
                    break;
                }
                index -= chars.len();
            }
        }
    }
    return String::from_utf8_lossy(bytes).into_owned();
}

pub fn derive_key(master_password: &String, salt: &[u8]) -> Vec<u8>
{
    return derive_bits(master_password.as_bytes(), salt, AES_KEY_SIZE / 8);
}

pub fn encrypt_data(value: &[u8], encryption_key: &[u8]) -> String
{
    let key = aes_gcm::Key::from_slice(encryption_key);
    let cipher = aes_gcm::Aes256Gcm::new(key);
    let nonce_data = rand::thread_rng().gen::<[u8; AES_NONCE_SIZE / 8]>();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_data);
    let mut result = base64::encode(nonce_data);
    result.push_str("_");
    result.push_str(&base64::encode(cipher.encrypt(nonce, value).unwrap()));
    return result;
}
