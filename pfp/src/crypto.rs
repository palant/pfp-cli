/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::error::Error;
use crate::storage_types::{CharacterSet, CharacterType};
use aes_gcm::aead::{Aead, NewAead};
use hmac::Mac;
use rand::Rng;
use scrypt::scrypt;
use secrecy::{ExposeSecret, SecretString, SecretVec};

const AES_KEY_SIZE: usize = 256;
const AES_NONCE_SIZE: usize = 96;

// I, l, O, 0, 1 excluded because of potential confusion. ", ', \ excluded
// because of common bugs in web interfaces (magic quotes).
const CHARS_LOWER: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
const CHARS_UPPER: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ";
const CHARS_DIGIT: &[u8] = b"23456789";
const CHARS_SYMBOL: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

const CHARS_MAPPING: [(CharacterType, &[u8]); 4] = [
    (CharacterType::Lower, CHARS_LOWER),
    (CharacterType::Upper, CHARS_UPPER),
    (CharacterType::Digit, CHARS_DIGIT),
    (CharacterType::Symbol, CHARS_SYMBOL),
];

// Our Base32 variant follows RFC 4648 but uses a custom alphabet to remove
// ambiguous characters: 0, 1, O, I.
pub const BASE32_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn derive_bits(password: &SecretString, salt: &[u8], size: usize) -> SecretVec<u8> {
    let params = scrypt::Params::new(15, 8, 1).unwrap();
    let mut bytes: Vec<u8> = Vec::new();
    bytes.resize(size, 0);
    scrypt(
        password.expose_secret().as_bytes(),
        salt,
        &params,
        bytes.as_mut_slice(),
    )
    .unwrap();
    SecretVec::new(bytes)
}

pub fn derive_password(
    primary_password: &SecretString,
    salt: &str,
    length: usize,
    charset: CharacterSet,
) -> SecretString {
    let bytes = derive_bits(primary_password, salt.as_bytes(), length);
    to_password(bytes, charset)
}

fn to_password(bytes: SecretVec<u8>, charset: CharacterSet) -> SecretString {
    let len = bytes.expose_secret().len();
    let mut result = String::with_capacity(len);
    let mut seen = CharacterSet::empty();
    for (i, &byte) in bytes.expose_secret().iter().enumerate() {
        let allowed = if charset.len() - seen.len() >= len - i {
            charset - seen
        } else {
            charset
        };
        let num_chars = CHARS_MAPPING.iter().fold(0, |acc, (chartype, chars)| {
            if allowed.contains(*chartype) {
                acc + chars.len()
            } else {
                acc
            }
        });

        let mut index = usize::from(byte) % num_chars;
        for (chartype, chars) in CHARS_MAPPING {
            if allowed.contains(chartype) {
                if index < chars.len() {
                    result.push(chars[index] as char);
                    seen.insert(chartype);
                    break;
                }
                index -= chars.len();
            }
        }
    }
    SecretString::new(result)
}

pub fn derive_key(primary_password: &SecretString, salt: &[u8]) -> SecretVec<u8> {
    derive_bits(primary_password, salt, AES_KEY_SIZE / 8)
}

#[cfg(not(test))]
pub fn get_rng() -> rand::rngs::ThreadRng {
    rand::thread_rng()
}

#[cfg(test)]
pub fn get_rng() -> rand::rngs::mock::StepRng {
    rand::rngs::mock::StepRng::new(97, 1)
}

pub fn encrypt_data(value: &SecretVec<u8>, encryption_key: &SecretVec<u8>) -> String {
    let key = aes_gcm::Key::from_slice(encryption_key.expose_secret());
    let cipher = aes_gcm::Aes256Gcm::new(key);
    let nonce_data = get_rng().gen::<[u8; AES_NONCE_SIZE / 8]>();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_data);
    let mut result = base64::encode(nonce_data);
    result.push('_');
    result.push_str(&base64::encode(
        cipher
            .encrypt(nonce, value.expose_secret().as_slice())
            .unwrap(),
    ));
    result
}

pub fn decrypt_data(value: &str, encryption_key: &SecretVec<u8>) -> Result<SecretVec<u8>, Error> {
    let key = aes_gcm::Key::from_slice(encryption_key.expose_secret());
    let cipher = aes_gcm::Aes256Gcm::new(key);

    let (nonce_base64, ciphertext_base64) =
        value.split_once('_').ok_or(Error::InvalidCiphertext)?;
    let nonce_data =
        base64::decode(nonce_base64).map_err(|error| Error::InvalidBase64 { error })?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_data);
    let ciphertext =
        base64::decode(ciphertext_base64).map_err(|error| Error::InvalidBase64 { error })?;
    Ok(SecretVec::new(
        cipher
            .decrypt(nonce, ciphertext.as_slice())
            .or(Err(Error::DecryptionFailure))?,
    ))
}

pub fn get_digest(hmac_secret: &SecretVec<u8>, data: &str) -> String {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(hmac_secret.expose_secret()).unwrap();
    mac.update(data.as_bytes());
    let result = mac.finalize().into_bytes();
    base64::encode(result)
}

pub fn base32_encode(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() % 5 != 0 {
        return Err(Error::UnexpectedData);
    }

    let mut encoded = Vec::with_capacity(input.len() / 5 * 8);

    for chunk in input.chunks(5) {
        encoded.push(BASE32_ALPHABET[(chunk[0] >> 3) as usize]);
        encoded.push(BASE32_ALPHABET[((chunk[0] & 0x07) << 2 | chunk[1] >> 6) as usize]);
        encoded.push(BASE32_ALPHABET[(chunk[1] >> 1 & 0x1F) as usize]);
        encoded.push(BASE32_ALPHABET[((chunk[1] & 0x01) << 4 | chunk[2] >> 4) as usize]);
        encoded.push(BASE32_ALPHABET[((chunk[2] & 0x0F) << 1 | chunk[3] >> 7) as usize]);
        encoded.push(BASE32_ALPHABET[(chunk[3] >> 2 & 0x1F) as usize]);
        encoded.push(BASE32_ALPHABET[((chunk[3] & 0x03) << 3 | chunk[4] >> 5) as usize]);
        encoded.push(BASE32_ALPHABET[(chunk[4] & 0x1F) as usize]);
    }
    Ok(encoded)
}

pub fn base32_decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    static LOOKUP: [u8; 256] = {
        let mut array = [255u8; 256];
        let mut i = 0;
        while i < BASE32_ALPHABET.len() {
            array[BASE32_ALPHABET[i] as usize] = i as u8;
            i += 1;
        }
        array
    };

    if input.len() % 8 != 0 {
        return Err(Error::UnexpectedData);
    }

    let mut encoded = Vec::with_capacity(input.len() / 8 * 5);

    let mut invalid_bytes = false;
    let input_converted = input
        .iter()
        .map(|&byte| {
            if LOOKUP[byte as usize] >= 32 {
                invalid_bytes = true;
            }
            LOOKUP[byte as usize]
        })
        .collect::<Vec<u8>>();
    if invalid_bytes {
        return Err(Error::UnexpectedData);
    }

    for chunk in input_converted.chunks(8) {
        encoded.push(chunk[0] << 3 | chunk[1] >> 2);
        encoded.push((chunk[1] & 0x03) << 6 | chunk[2] << 1 | chunk[3] >> 4);
        encoded.push((chunk[3] & 0x0F) << 4 | chunk[4] >> 1);
        encoded.push((chunk[4] & 0x01) << 7 | chunk[5] << 2 | chunk[6] >> 3);
        encoded.push((chunk[6] & 0x07) << 5 | chunk[7]);
    }
    Ok(encoded)
}

pub fn pearson_hash(input: &[u8], virtual_byte: u8) -> u8 {
    static PERMUTATIONS: [u8; 256] = {
        let mut array = [0u8; 256];
        let mut i = 0;
        while i < array.len() {
            array[i] = ((i + 379) * 467) as u8;
            i += 1;
        }
        array
    };

    let mut hash = PERMUTATIONS[virtual_byte as usize];
    for byte in input {
        hash = PERMUTATIONS[(hash ^ byte) as usize];
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    fn encode(value: &str) -> String {
        let bytes = value
            .chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|chunk| {
                u8::from_str_radix(&chunk.iter().collect::<String>(), 16)
                    .expect("Should be a valid hex string")
            })
            .collect::<Vec<u8>>();
        return String::from_utf8(base32_encode(&bytes).expect("Base32 encoding should succeed"))
            .expect("Base32 result should decode to UTF-8");
    }

    fn decode(value: &str) -> String {
        let mut result = String::new();
        for byte in base32_decode(value.as_bytes()).expect("Base32 decoding should succeed") {
            write!(&mut result, "{:02x}", byte).expect("Converting bytes to hex should succeed");
        }
        return result;
    }

    #[test]
    fn test_base32_encode() {
        assert_eq!(encode("0000000000"), "AAAAAAAA");
        assert_eq!(encode("0842108421"), "BBBBBBBB");
        assert_eq!(encode("ffffffffff"), "99999999");
        assert_eq!(encode("0000000000ffffffffff"), "AAAAAAAA99999999");
        assert_eq!(
            encode("00443214c74254b635cf84653a56d7c675be77df"),
            "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        );
    }

    #[test]
    fn test_base32_decode() {
        assert_eq!(decode("AAAAAAAA"), "0000000000");
        assert_eq!(decode("BBBBBBBB"), "0842108421");
        assert_eq!(decode("99999999"), "ffffffffff");
        assert_eq!(decode("AAAAAAAA99999999"), "0000000000ffffffffff");
        assert_eq!(
            decode("ABCDEFGHJKLMNPQRSTUVWXYZ23456789"),
            "00443214c74254b635cf84653a56d7c675be77df"
        );
    }

    #[test]
    fn test_pearson_hash() {
        assert_eq!(pearson_hash(b"", b'\x00'), b'\x61');
        assert_eq!(pearson_hash(b"", b'\x61'), b'\x54');
        assert_eq!(pearson_hash(b"", b'\x54'), b'\x9D');
        assert_eq!(pearson_hash(b"", b'\x9D'), b'\xC8');
        assert_eq!(pearson_hash(b"", b'\xC8'), b'\x39');
        assert_eq!(
            pearson_hash(&[b'\x61' ^ b'\x54', b'\x9D' ^ b'\xC8'], b'\x00'),
            b'\x39'
        );
        assert_eq!(pearson_hash(b"0123456789", 123), 43);
    }
}
