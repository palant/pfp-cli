/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use enumset;
use scrypt::scrypt;

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

pub fn derive_password(master_password: &String, domain: &String, name: &String, revision: &String, length: u8, charset: enumset::EnumSet<CharacterType>) -> String
{
    let mut salt = domain.to_owned();
    salt.push_str("\0");
    salt.push_str(&name);
    if revision != "" && revision != "1"
    {
        salt.push_str("\0");
        salt.push_str(&revision);
    }

    let params = scrypt::Params::new(15, 8, 1).unwrap();
    let mut bytes: Vec<u8> = Vec::new();
    bytes.resize(usize::from(length), 0);
    scrypt(master_password.as_bytes(), salt.as_bytes(), &params, bytes.as_mut_slice()).unwrap();
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
