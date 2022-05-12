/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Holds the error type returned by all of this crate's operations.

#[derive(Debug)]
/// A list of all error types returned by this crate's operations.
pub enum Error
{
    /// Directory for the storage file cannot be created.
    CreateDirFailure { error: std::io::Error },
    /// File cannot be read from disk.
    FileReadFailure { error: std::io::Error },
    /// File cannot be written to disk.
    FileWriteFailure { error: std::io::Error },
    /// Operation requires the storage to be initialized but it currently isn't.
    StorageNotInitialized,
    /// Storage file's format and version aren't supported.
    UnexpectedStorageFormat,
    /// Operation requires the passwords to be unlocked but they currently aren't.
    PasswordsLocked,
    /// The storage doesn't have the key (site or password) requested by the operation.
    KeyMissing,
    /// The operation was given unexpected data, e.g. JSON data that isn't an object.
    UnexpectedData,
    /// Ciphertext isn't stored in the expected format.
    InvalidCiphertext,
    /// Base64 decoding failed.
    InvalidBase64 { error: base64::DecodeError },
    /// JSON decoding failed.
    InvalidJson { error: json::Error },
    /// UTF-8 decoding failed.
    InvalidUtf8 { error: std::string::FromUtf8Error },
    /// Decryption failed, probably due to wrong master password.
    DecryptionFailure,
    /// Password entry in storage doesn't contain a password type.
    PasswordMissingType,
    /// Password entry in storage contains an unsupported password type.
    PasswordUnknownType,
    /// Password entry in storage is missing the associated site name.
    PasswordMissingSite,
    /// Password entry in storage is missing password name.
    PasswordMissingName,
    /// Password entry in storage is missing revision.
    PasswordMissingRevision,
    /// Entry for generated password is missing password length.
    PasswordMissingLength,
    /// Entry for stored password is missing password value.
    PasswordMissingValue,
    /// Site entry in storage is missing site name.
    SiteMissingName,
    /// The alias requested doesn't exist.
    NoSuchAlias,
    /// Cannot alias a site to itself.
    AliasToSelf,
    /// Cannot alias a site that already has passwords.
    SiteHasPasswords,
    /// Recovery code contains extra data starting with given line.
    RecoveryCodeExtraData { line: usize },
    /// Recovery code validation detected a checksum mismatch in given line.
    RecoveryCodeChecksumMismatch { line: usize },
    /// Recovery code is incomplete.
    RecoveryCodeIncomplete,
    /// Recovery code version is unsupported.
    RecoveryCodeWrongVersion,
    /// Recovery code encodes less data than expected.
    RecoveryCodeInsufficientData,
}
