/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::crypto;
use super::error::Error;

const BLOCK_SIZE: usize = 14;
const VERSION: u8 = 1;
const VERSION_SIZE: usize = 1;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

pub fn generate(password: &str, salt: &[u8], encryption_key: &[u8]) -> Result<String, Error>
{
    if salt.len() != SALT_SIZE
    {
        return Err(Error::UnexpectedData);
    }

    // Zero-pad passwords to fill up the row (don't allow deducing password
    // length from size of encrypted data)
    let mut password_vec = password.as_bytes().to_vec();
    while (VERSION_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE + password_vec.len()) % BLOCK_SIZE != 0
    {
        password_vec.push(b'\0');
    }

    let encrypted = crypto::encrypt_data(&password_vec, encryption_key);
    let (nonce_base64, ciphertext_base64) = encrypted.split_once('_').ok_or(Error::InvalidCiphertext)?;

    let nonce = base64::decode(nonce_base64).map_err(|error| Error::InvalidBase64 { error })?;
    if nonce.len() != NONCE_SIZE
    {
        return Err(Error::UnexpectedData);
    }

    let ciphertext = base64::decode(ciphertext_base64).map_err(|error| Error::InvalidBase64 { error })?;
    if ciphertext.len() != password_vec.len() + TAG_SIZE
    {
        return Err(Error::UnexpectedData);
    }

    let mut input = Vec::with_capacity(VERSION_SIZE + salt.len() + nonce.len() + ciphertext.len());
    input.push(VERSION);
    input.extend_from_slice(salt);
    input.extend_from_slice(&nonce);
    input.extend_from_slice(&ciphertext);

    // We add one checksum byte to each block (output row)
    let blocks = input.len() / BLOCK_SIZE;
    let mut output = Vec::with_capacity(input.len() + blocks);
    for (pos, &byte) in input.iter().enumerate()
    {
        output.push(byte);
        if pos % BLOCK_SIZE == BLOCK_SIZE - 1
        {
            let block_index = pos / BLOCK_SIZE;
            let final_block = block_index == blocks - 1;
            let virtual_byte = if final_block { 255 - block_index } else { block_index } as u8;
            output.push(crypto::pearson_hash(&output[output.len() - BLOCK_SIZE ..], virtual_byte));
        }
    }

    format_code(&crypto::base32_encode(&output))
}

fn format_code(code: &[u8]) -> Result<String, Error>
{
    if code.len() % 24 != 0
    {
        return Err(Error::UnexpectedData);
    }

    let mut result = String::new();

    let mut pos = 0;
    for &byte in code
    {
        if !crypto::BASE32_ALPHABET.contains(&byte)
        {
            continue;
        }

        result.push(byte as char);
        pos += 1;
        if pos % 24 == 0
        {
            result.push('\n');
        }
        else if pos % 12 == 0
        {
            result.push(':');
        }
        else if pos % 4 == 0
        {
            result.push('-');
        }
    }
    result.pop();
    Ok(result)
}

#[cfg(test)]
mod tests
{
    use super::*;

    const SALT: &[u8] = b"abcdefghijklmnop";
    const ENCRYPTION_KEY: &[u8] = b"abcdefghijklmnopqrstuvwxyz123456";

    #[test]
    fn generation()
    {
        assert_eq!(
            generate("asdf", SALT, ENCRYPTION_KEY).expect("Generating code should succeed"),
            "AFSY-E25E-NXVG:Q4DK-PKXY-25KP\nP3ZZ-A2MC-NPUG:L3VH-PBWY-W48F\nPTST-72NZ-ENV2:8U57-4DJQ-XDFB\nGK6N-MXKF-GTMT:MKLU-CNZE-ES85"
        );

        assert_eq!(
            generate("01234567890", SALT, ENCRYPTION_KEY).expect("Generating code should succeed"),
            "AFSY-E25E-NXVG:Q4DK-PKXY-25KP\nP3ZZ-A2MC-NPUG:L3VH-PBWY-W48F\nPS2F-3P8C-C6KM:U9CF-7HSN-A9HG\n8WLJ-UJFY-QF3W:36EF-7TP2-H6RP"
        );

        assert_eq!(
            generate("012345678901", SALT, ENCRYPTION_KEY).expect("Generating code should succeed"),
            "AFSY-E25E-NXVG:Q4DK-PKXY-25KP\nP3ZZ-A2MC-NPUG:L3VH-PBWY-W48F\nPS2F-3P8C-C6KM:U9CF-7HSE-3E5P\nUSDD-W6XY-GW6H:MKQB-K35Z-ULUW\nW6KA-BV2P-W3TG:TUUJ-NJDD-R6KX"
        );
    }
}
