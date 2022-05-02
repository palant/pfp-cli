/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

#[derive(Debug)]
pub enum Error
{
    CreateDirFailure  { error: std::io::Error },
    FileReadFailure { error: std::io::Error },
    FileWriteFailure  { error: std::io::Error },
    StorageNotInitialized,
    UnexpectedStorageFormat,
    PasswordsLocked,
    KeyMissing,
    UnexpectedData,
    InvalidCiphertext,
    InvalidBase64 { error: base64::DecodeError },
    InvalidJson { error: json::Error },
    InvalidUtf8 { error: std::string::FromUtf8Error },
    DecryptionFailure,
    PasswordMissingType,
    PasswordUnknownType,
    PasswordMissingSite,
    PasswordMissingName,
    PasswordMissingRevision,
    PasswordMissingLength,
    PasswordMissingValue,
    SiteMissingName,
    NoSuchAlias,
}
