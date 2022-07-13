/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Contains some helper functions to work with password recovery codes.

use super::crypto;
use super::error::Error;
use super::passwords;
use secrecy::{ExposeSecret, SecretString, SecretVec};

const BLOCK_SIZE: usize = 14;
const LINE_SIZE: usize = (BLOCK_SIZE + 1) / 5 * 8;
const VERSION: u8 = 1;
const VERSION_SIZE: usize = 1;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

/// Generates a new recovery code for the password.
///
/// The password is encrypted and can only be decrypted if the right master password is known.
/// The ciphertext and auxiliary data are encoded via Base32 with additional characters added
/// to simplify human entry from printout or the like.
///
/// `password` is the password to be encoded in the recovery code. `salt` is a random salt used to
/// derive `encryption_key` from the secret master password using
/// [get_encryption_key() function](../passwords/fn.get_encryption_key.html).
///
/// ```
/// use pfp::recovery_codes;
/// use secrecy::{SecretString, SecretVec};
///
/// let password = SecretString::new("asdf".to_owned());
/// let encryption_key = SecretVec::new(b"abcdefghijklmnopqrstuvwxyz123456".to_vec());
/// let code = recovery_codes::generate(
///     &password,
///     b"abcdefghijklmnop",
///     &encryption_key
/// ).unwrap();
///
/// // Will produce something like (actual output depends on a random nonce):
/// // AFSY-E25E-NXVG:Q4DK-PKXY-25KP
/// // P3ZZ-A2MC-NPUG:L3VH-PBWY-W48F
/// // PTST-72NZ-ENV2:8U57-4DJQ-XDFB
/// // GK6N-MXKF-GTMT:MKLU-CNZE-ES85
/// println!("{}", code);
/// ```
pub fn generate(
    password: &SecretString,
    salt: &[u8],
    encryption_key: &SecretVec<u8>,
) -> Result<String, Error> {
    if salt.len() != SALT_SIZE {
        return Err(Error::UnexpectedData);
    }

    // Zero-pad passwords to fill up the row (don't allow deducing password
    // length from size of encrypted data)
    let password_len = password.expose_secret().len();
    let fill_bytes =
        match (VERSION_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE + password_len) % BLOCK_SIZE {
            0 => 0,
            rest => BLOCK_SIZE - rest,
        };

    let password_vec = SecretVec::<u8>::new({
        let mut vec = Vec::<u8>::with_capacity(password_len + fill_bytes);
        vec.extend_from_slice(password.expose_secret().as_bytes());
        vec.resize(vec.capacity(), b'\0');
        vec
    });

    let encrypted = crypto::encrypt_data(&password_vec, encryption_key);
    let (nonce_base64, ciphertext_base64) =
        encrypted.split_once('_').ok_or(Error::InvalidCiphertext)?;

    let nonce = base64::decode(nonce_base64).map_err(|error| Error::InvalidBase64 { error })?;
    if nonce.len() != NONCE_SIZE {
        return Err(Error::UnexpectedData);
    }

    let ciphertext =
        base64::decode(ciphertext_base64).map_err(|error| Error::InvalidBase64 { error })?;
    if ciphertext.len() != password_len + fill_bytes + TAG_SIZE {
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
    for (pos, &byte) in input.iter().enumerate() {
        output.push(byte);
        if pos % BLOCK_SIZE == BLOCK_SIZE - 1 {
            let block_index = pos / BLOCK_SIZE;
            let final_block = block_index == blocks - 1;
            let virtual_byte = if final_block {
                255 - block_index
            } else {
                block_index
            } as u8;
            output.push(crypto::pearson_hash(
                &output[output.len() - BLOCK_SIZE..],
                virtual_byte,
            ));
        }
    }

    Ok(format_code(&crypto::base32_encode(&output)?, true))
}

/// Brings a recovery code into the canonical format.
///
/// Converts the data to uppercase letters and remove any invalid characters from it. Incomplete
/// recovery codes are supported. Punctuation and line breaks will only be inserted if the
/// `insert_punctuation` parameter is `true`.
///
/// ```
/// use pfp::recovery_codes;
///
/// assert_eq!(recovery_codes::format_code(b"<abcd+efgh>", false), "ABCDEFGH");
/// assert_eq!(recovery_codes::format_code(b"<abcd+efgh>", true), "ABCD-EFGH");
///
/// assert_eq!(recovery_codes::format_code(b"<abcd+efgh>123456789", false), "ABCDEFGH23456789");
/// assert_eq!(recovery_codes::format_code(b"<abcd+efgh>123456789", true), "ABCD-EFGH-2345:6789");
/// ```
pub fn format_code(code: &[u8], insert_punctuation: bool) -> String {
    let mut result = String::new();

    let mut pos = 0;
    for byte in code {
        let uppercased = byte.to_ascii_uppercase();
        if !crypto::BASE32_ALPHABET.contains(&uppercased) {
            continue;
        }

        result.push(uppercased as char);
        pos += 1;
        if insert_punctuation {
            if pos % LINE_SIZE == 0 {
                result.push('\n');
            } else if pos % (LINE_SIZE / 2) == 0 {
                result.push(':');
            } else if pos % (LINE_SIZE / 6) == 0 {
                result.push('-');
            }
        }
    }
    if result
        .as_bytes()
        .last()
        .filter(|&&byte| byte == b'\n' || byte == b':' || byte == b'-')
        .is_some()
    {
        result.pop();
    }
    result
}

/// Tries to decode a recovery code using the specified master password.
///
/// This might produce a number of errors, most importantly
/// [Error::RecoveryCodeIncomplete](../error/enum.Error.html#variant.RecoveryCodeIncomplete) for
/// recovery codes that are missing part of their data and
/// [Error::DecryptionFailure](../error/enum.Error.html#variant.DecryptionFailure) in case of a
/// wrong master password.
///
/// ```
/// use pfp::recovery_codes;
/// use pfp::error::Error;
/// use secrecy::SecretString;
///
/// let master_password = SecretString::new("my master password".to_owned());
/// let result = recovery_codes::decode("ABCD-EFGH", &master_password);
/// if let Err(Error::RecoveryCodeIncomplete) = result
/// {
///     eprintln!("Please enter more recovery code lines.");
/// }
/// ```
pub fn decode(code: &str, master_password: &SecretString) -> Result<SecretString, Error> {
    let decoded = validate(code)?;

    let without_checksums = decoded
        .iter()
        .enumerate()
        .filter_map(|(i, byte)| {
            if i % (BLOCK_SIZE + 1) == BLOCK_SIZE {
                None
            } else {
                Some(byte)
            }
        })
        .copied()
        .collect::<Vec<u8>>();
    if !without_checksums.is_empty() && without_checksums[0] != VERSION {
        return Err(Error::RecoveryCodeWrongVersion);
    }

    if without_checksums.len() < VERSION_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(Error::RecoveryCodeInsufficientData);
    }

    let salt = &without_checksums[VERSION_SIZE..VERSION_SIZE + SALT_SIZE];
    let nonce = &without_checksums[VERSION_SIZE + SALT_SIZE..VERSION_SIZE + SALT_SIZE + NONCE_SIZE];
    let ciphertext = &without_checksums[VERSION_SIZE + SALT_SIZE + NONCE_SIZE..];

    let mut encrypted = base64::encode(nonce);
    encrypted.push('_');
    encrypted.push_str(&base64::encode(ciphertext));

    let encryption_key = passwords::get_encryption_key(master_password, salt);
    let decrypted = crypto::decrypt_data(&encrypted, &encryption_key)?;
    let decrypted_len = decrypted.expose_secret().len();
    let mut end_pos = decrypted_len;
    while let Some(&byte) = decrypted.expose_secret().get(end_pos - 1) {
        if byte != 0 {
            break;
        }
        end_pos -= 1;
    }
    let stripped = if end_pos == decrypted_len {
        decrypted
    } else {
        SecretVec::<u8>::new(decrypted.expose_secret()[..end_pos].to_vec())
    };

    let decrypted_str = std::str::from_utf8(stripped.expose_secret())
        .map_err(|error| Error::InvalidUtf8 { error })?;
    Ok(SecretString::new(decrypted_str.to_owned()))
}

fn validate(code: &str) -> Result<Vec<u8>, Error> {
    let formatted = format_code(code.as_bytes(), false);
    let decoded =
        crypto::base32_decode(&formatted.as_bytes()[..formatted.len() / LINE_SIZE * LINE_SIZE])?;

    let extra_data = formatted.len() % LINE_SIZE != 0;
    let mut extra_row: Option<usize> = None;
    let mut seen_last = false;
    for (i, chunk) in decoded.chunks(BLOCK_SIZE + 1).enumerate() {
        if seen_last {
            extra_row = Some(i);
            break;
        }

        if chunk[BLOCK_SIZE] == crypto::pearson_hash(&chunk[..BLOCK_SIZE], (255 - i) as u8) {
            seen_last = true;
            extra_row = None;
        } else if chunk[BLOCK_SIZE] != crypto::pearson_hash(&chunk[..BLOCK_SIZE], i as u8) {
            return Err(Error::RecoveryCodeChecksumMismatch { line: i });
        }
    }

    if !seen_last {
        Err(Error::RecoveryCodeIncomplete)
    } else if extra_row.is_some() || extra_data {
        Err(Error::RecoveryCodeExtraData {
            line: if let Some(row) = extra_row {
                row
            } else {
                formatted.len() / LINE_SIZE
            },
        })
    } else {
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"abcdefghijklmnop";
    const ENCRYPTION_KEY: &[u8] = b"abcdefghijklmnopqrstuvwxyz123456";
    const MASTER_PASSWORD: &str = "foobar";

    fn enc_key() -> SecretVec<u8> {
        SecretVec::new(ENCRYPTION_KEY.to_vec())
    }

    fn master_pass() -> SecretString {
        SecretString::new(MASTER_PASSWORD.to_owned())
    }

    #[test]
    fn formatting() {
        assert_eq!(
            format_code(b"+.-abcdEFG%&/HJKLMNPQRSTUvWXYZ<>!", true),
            "ABCD-EFGH-JKLM:NPQR-STUV-WXYZ"
        );
        assert_eq!(
            format_code(b"+.-abcdEFG%&/HJKLMNPQRSTUvWXYZ<>!", false),
            "ABCDEFGHJKLMNPQRSTUVWXYZ"
        );
        assert_eq!(
            format_code(b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789", true),
            "ABCD-EFGH-JKLM:NPQR-STUV-WXYZ\n2345-6789"
        );
        assert_eq!(
            format_code(b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789ABCD", true),
            "ABCD-EFGH-JKLM:NPQR-STUV-WXYZ\n2345-6789-ABCD"
        );
        assert_eq!(
            format_code(b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789ABCDEFGHJKLMNPQR", true),
            "ABCD-EFGH-JKLM:NPQR-STUV-WXYZ\n2345-6789-ABCD:EFGH-JKLM-NPQR"
        );
    }

    #[test]
    fn generation() {
        assert_eq!(
            generate(&SecretString::new("asdf".to_owned()), SALT, &enc_key()).expect("Generating code should succeed"),
            "AFSY-E25E-NXVG:Q4DK-PKXY-25KP\nP3ZZ-A2MC-NPUG:L3VH-PBWY-W48F\nPTST-72NZ-ENV2:8U57-4DJQ-XDFB\nGK6N-MXKF-GTMT:MKLU-CNZE-ES85"
        );

        assert_eq!(
            generate(&SecretString::new("01234567890".to_owned()), SALT, &enc_key()).expect("Generating code should succeed"),
            "AFSY-E25E-NXVG:Q4DK-PKXY-25KP\nP3ZZ-A2MC-NPUG:L3VH-PBWY-W48F\nPS2F-3P8C-C6KM:U9CF-7HSN-A9HG\n8WLJ-UJFY-QF3W:36EF-7TP2-H6RP"
        );

        assert_eq!(
            generate(&SecretString::new("012345678901".to_owned()), SALT, &enc_key()).expect("Generating code should succeed"),
            "AFSY-E25E-NXVG:Q4DK-PKXY-25KP\nP3ZZ-A2MC-NPUG:L3VH-PBWY-W48F\nPS2F-3P8C-C6KM:U9CF-7HSE-3E5P\nUSDD-W6XY-GW6H:MKQB-K35Z-ULUW\nW6KA-BV2P-W3TG:TUUJ-NJDD-R6KX"
        );
    }

    #[test]
    fn recovery() {
        assert_eq!(
            decode(
                "
                    AHLL-QKN7-S2AW:BEZF-3EB7-R923
                    4ASW-WSGA-2YMR:TMB7-5WZ5-MRZJ
                    2VCY-FK9C-5BUX:NH86-RDC6-QYMY
                    ELVM-RQ44-VB8T:VGPW-AW6K-DUQD
                ",
                &master_pass()
            )
            .expect("Password recovery should succeed")
            .expose_secret(),
            "asdf"
        );

        assert_eq!(
            decode(
                "
                    ahll-QKN7-S2AW:BEZF-3EB7-R923+4ASW
                    WSGA-2YMRTMB7-5WZ5-MRZJ
                    2VCY-FK9C-5BUX:NH86-RDC6-QYMY
                    ELVM-RQ44-vb8t:VGPW-AW6K-DUQD
                ",
                &master_pass()
            )
            .expect("Password recovery should succeed")
            .expose_secret(),
            "asdf"
        );

        let err1 = decode(
            "
                AHLL-QKN7-S2AW:BEZF-3EB7-R923
                2VCY-FK9C-5BUX:NH86-RDC6-QYMY
                4ASW-WSGA-2YMR:TMB7-5WZ5-MRZJ
                ELVM-RQ44-VB8T:VGPW-AW6K-DUQD
            ",
            &master_pass(),
        )
        .expect_err("Password recovery should fail");
        if let Error::RecoveryCodeChecksumMismatch { line, .. } = err1 {
            assert_eq!(line, 1);
        } else {
            assert!(false, "Unexpected error type: {:?}", err1);
        }

        let err2 = decode(
            "
                AHLL-QKN7-S2AW:BEZF-3EB7-R923
                4ASW-WSGA-2YMR:TMB7-5WZ5-MRZJ
                2VCY-YK9C-5BUX:NH86-RDC6-QYMY
                ELVM-RQ44-VB8T:VGPW-AW6K-DUQD
            ",
            &master_pass(),
        )
        .expect_err("Password recovery should fail");
        if let Error::RecoveryCodeChecksumMismatch { line, .. } = err2 {
            assert_eq!(line, 2);
        } else {
            assert!(false, "Unexpected error type: {:?}", err2);
        }

        let err3 = decode(
            "
                AHLL-QKN7-S2AW:BEZF-3EB7-R923
                4ASW-WSGA-2YMR:TMB7-5WZ5-MRZJ
                2VCY-FK9C-5BUX:NH86-RDC6-QYMY
                ELVM-RQ44-VB8T:VGPW-AW6K-DUQD
                ELVM-RQ44-VB8T:VGPW-AW6K-DUQD
            ",
            &master_pass(),
        )
        .expect_err("Password recovery should fail");
        if let Error::RecoveryCodeExtraData { line, .. } = err3 {
            assert_eq!(line, 4);
        } else {
            assert!(false, "Unexpected error type: {:?}", err3);
        }

        assert!(matches!(
            decode(
                "
                    AHLL-QKN7-S2AW:BEZF-3EB7-R923
                    4ASW-WSGA-2YMR:TMB7-5WZ5-MRZJ
                    2VCY-FK9C-5BUX:NH86-RDC6-QYMY
                    ELVM-RQ44-VB8T:
                ",
                &master_pass()
            )
            .expect_err("Password recovery should fail"),
            Error::RecoveryCodeIncomplete { .. }
        ));

        assert!(matches!(
            decode(
                "
                    AHLL-QKN7-S2AW:BEZF-3EB7-R923
                    4ASW-WSGA-2YMR:TMB7-5WZ5-MRZJ
                    2VCY-FK9C-5BUX:NH86-RDC6-QYMY
                    ELVM-RQ44-
                ",
                &master_pass()
            )
            .expect_err("Password recovery should fail"),
            Error::RecoveryCodeIncomplete { .. }
        ));

        assert!(matches!(
            decode(
                "
                    AHLL-QKN7-S2AW:BEZF-3EB7-R923
                    4ASW-WSGA-2YMR:TMB7-5WZ5-MRZJ
                    2VCY-FK9C-5BUX:NH86-RDC6-QYMY
                ",
                &master_pass()
            )
            .expect_err("Password recovery should fail"),
            Error::RecoveryCodeIncomplete { .. }
        ));
    }
}
