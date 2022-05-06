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
use super::error::Error;

const AES_KEY_SIZE: usize = 256;
const AES_NONCE_SIZE: usize = 96;

// I, l, O, 0, 1 excluded because of potential confusion. ", ', \ excluded
// because of common bugs in web interfaces (magic quotes).
const CHARS_LOWER: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
const CHARS_UPPER: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ";
const CHARS_DIGIT: &[u8] = b"23456789";
const CHARS_SYMBOL: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

#[derive(enumset::EnumSetType, Debug)]
pub enum CharacterType
{
    LOWER,
    UPPER,
    DIGIT,
    SYMBOL
}

const CHARS_MAPPING: [(CharacterType, &[u8]); 4] = [
    (CharacterType::LOWER, CHARS_LOWER),
    (CharacterType::UPPER, CHARS_UPPER),
    (CharacterType::DIGIT, CHARS_DIGIT),
    (CharacterType::SYMBOL, CHARS_SYMBOL),
];

// Our Base32 variant follows RFC 4648 but uses a custom alphabet to remove
// ambiguous characters: 0, 1, O, I.
pub const BASE32_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

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
    let bytes = derive_bits(master_password.as_bytes(), salt.as_bytes(), length);
    return to_password(&bytes, charset);
}

fn to_password(bytes: &[u8], charset: enumset::EnumSet<CharacterType>) -> String
{
    let mut result = String::with_capacity(bytes.len());
    let mut seen = new_charset();
    for (i, byte) in bytes.iter().enumerate()
    {
        let allowed = if charset.len() - seen.len() >= bytes.len() - i { charset - seen } else { charset };
        let num_chars = CHARS_MAPPING.iter().fold(0, |acc, (chartype, chars)| if allowed.contains(*chartype) { acc + chars.len() } else { acc });

        let mut index = usize::from(*byte) % num_chars;
        for (chartype, chars) in CHARS_MAPPING
        {
            if allowed.contains(chartype)
            {
                if index < chars.len()
                {
                    result.push(chars[index] as char);
                    seen.insert(chartype);
                    break;
                }
                index -= chars.len();
            }
        }
    }
    return result;
}

pub fn derive_key(master_password: &str, salt: &[u8]) -> Vec<u8>
{
    return derive_bits(master_password.as_bytes(), salt, AES_KEY_SIZE / 8);
}

#[cfg(not(test))]
pub fn get_rng() -> rand::rngs::ThreadRng
{
    return rand::thread_rng();
}

#[cfg(test)]
pub fn get_rng() -> rand::rngs::mock::StepRng
{
    return rand::rngs::mock::StepRng::new(97, 1);
}

pub fn encrypt_data(value: &[u8], encryption_key: &[u8]) -> String
{
    let key = aes_gcm::Key::from_slice(encryption_key);
    let cipher = aes_gcm::Aes256Gcm::new(key);
    let nonce_data = get_rng().gen::<[u8; AES_NONCE_SIZE / 8]>();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_data);
    let mut result = base64::encode(nonce_data);
    result.push_str("_");
    result.push_str(&base64::encode(cipher.encrypt(nonce, value).unwrap()));
    return result;
}

pub fn decrypt_data(value: &str, encryption_key: &[u8]) -> Result<String, Error>
{
    let key = aes_gcm::Key::from_slice(encryption_key);
    let cipher = aes_gcm::Aes256Gcm::new(key);

    let parts: Vec<&str> = value.split('_').collect();
    if parts.len() != 2
    {
        return Err(Error::InvalidCiphertext);
    }

    let nonce_data = base64::decode(&parts[0]).or_else(|error| Err(Error::InvalidBase64 { error }))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_data);
    let ciphertext = base64::decode(&parts[1]).or_else(|error| Err(Error::InvalidBase64 { error }))?;
    let decrypted = cipher.decrypt(&nonce, ciphertext.as_slice()).or(Err(Error::DecryptionFailure))?;
    return String::from_utf8(decrypted).or_else(|error| Err(Error::InvalidUtf8 { error }));
}

pub fn get_digest(hmac_secret: &[u8], data: &str) -> String
{
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(hmac_secret).unwrap();
    mac.update(data.as_bytes());
    let result = mac.finalize().into_bytes();
    return base64::encode(result);
}

pub fn base32_encode(input: &[u8]) -> Vec<u8>
{
    let mut encoded = Vec::with_capacity((input.len() + 3) / 4 * 5);

    for chunk in input.chunks(5)
    {
        let extended =
        {
            let mut result = [0u8; 5];
            result[..chunk.len()].copy_from_slice(chunk);
            result
        };

        encoded.push(BASE32_ALPHABET[(extended[0] >> 3) as usize]);
        encoded.push(BASE32_ALPHABET[((extended[0] & 0x07) << 2 | extended[1] >> 6) as usize]);
        encoded.push(BASE32_ALPHABET[(extended[1] >> 1 & 0x1F) as usize]);
        encoded.push(BASE32_ALPHABET[((extended[1] & 0x01) << 4 | extended[2] >> 4) as usize]);
        encoded.push(BASE32_ALPHABET[((extended[2] & 0x0F) << 1 | extended[3] >> 7) as usize]);
        encoded.push(BASE32_ALPHABET[(extended[3] >> 2 & 0x1F) as usize]);
        encoded.push(BASE32_ALPHABET[((extended[3] & 0x03) << 3 | extended[4] >> 5) as usize]);
        encoded.push(BASE32_ALPHABET[(extended[4] & 0x1F) as usize]);
    }
    return encoded;
}

pub fn pearson_hash(input: &[u8], virtual_byte: u8) -> u8
{
    static PERMUTATIONS: [u8; 256] =
    {
        let mut array = [0u8; 256];
        let mut i = 0;
        while i < array.len()
        {
            array[i] = ((i + 379) * 467) as u8;
            i += 1;
        }
        array
    };

    let mut hash = PERMUTATIONS[virtual_byte as usize];
    for byte in input
    {
        hash = PERMUTATIONS[(hash ^ byte) as usize];
    }
    return hash;
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn encode(value: &str) -> String
    {
        let bytes = value.chars()
                         .collect::<Vec<char>>()
                         .chunks(2)
                         .map(|chunk| u8::from_str_radix(&chunk.iter().collect::<String>(), 16).expect("Should be a valid hex string"))
                         .collect::<Vec<u8>>();
        return String::from_utf8(base32_encode(&bytes)).expect("Base32 result should decode to UTF-8");
    }

    #[test]
    fn base32()
    {
        assert_eq!(encode("0000000000"), "AAAAAAAA");
        assert_eq!(encode("0842108421"), "BBBBBBBB");
        assert_eq!(encode("ffffffffff"), "99999999");
        assert_eq!(encode("0000000000ffffffffff"), "AAAAAAAA99999999");
        assert_eq!(encode("00443214C74254B635CF84653A56D7C675BE77DF"), "ABCDEFGHJKLMNPQRSTUVWXYZ23456789");
    }
}
