/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use aes_gcm::aead::{Aead, NewAead};
use enumset;
use hmac::Mac;
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
    scrypt(password, salt, &params, bytes.as_mut_slice()).unwrap();
    return bytes;
}

pub fn derive_password(master_password: &str, salt: &str, length: usize, charset: enumset::EnumSet<CharacterType>) -> String
{
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

pub fn derive_key(master_password: &str, salt: &[u8]) -> Vec<u8>
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

pub fn decrypt_data(value: &str, encryption_key: &[u8]) -> Option<String>
{
    let key = aes_gcm::Key::from_slice(encryption_key);
    let cipher = aes_gcm::Aes256Gcm::new(key);

    let parts: Vec<&str> = value.split('_').collect();
    if parts.len() != 2
    {
        return None;
    }

    let nonce_data = base64::decode(&parts[0]).ok()?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_data);
    let ciphertext = base64::decode(&parts[1]).ok()?;
    let decrypted = cipher.decrypt(&nonce, ciphertext.as_slice()).ok()?;
    return String::from_utf8(decrypted).ok();
}

pub fn get_digest(hmac_secret: &[u8], data: &str) -> String
{
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(hmac_secret).unwrap();
    mac.update(data.as_bytes());
    let result = mac.finalize().into_bytes();
    return base64::encode(result);
}
