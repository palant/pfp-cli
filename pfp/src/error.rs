/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Holds the error type returned by all of this crate's operations.

#[derive(Debug)]
/// A list of all error types returned by this crate's operations.
pub enum Error {
    /// Directory for the storage file cannot be created.
    CreateDirFailure {
        /// Underlying I/O error
        error: std::io::Error,
    },
    /// File cannot be read from disk.
    FileReadFailure {
        /// Underlying I/O error
        error: std::io::Error,
    },
    /// File cannot be written to disk.
    FileWriteFailure {
        /// Underlying I/O error
        error: std::io::Error,
    },
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
    InvalidBase64 {
        /// Underlying Base64 error
        error: base64::DecodeError,
    },
    /// JSON decoding failed.
    InvalidJson {
        /// Underlying JSON error
        error: json::Error,
    },
    /// UTF-8 decoding failed.
    InvalidUtf8 {
        /// Underlying UTF8 error
        error: std::string::FromUtf8Error,
    },
    /// Decryption failed, probably due to wrong master password.
    DecryptionFailure,
    /// The alias requested doesn't exist.
    NoSuchAlias,
    /// Cannot alias a site to itself.
    AliasToSelf,
    /// Cannot alias a site that already has passwords.
    SiteHasPasswords,
    /// Recovery code contains extra data.
    RecoveryCodeExtraData {
        /// First line to contain extra data
        line: usize,
    },
    /// Recovery code validation detected a checksum mismatch.
    RecoveryCodeChecksumMismatch {
        /// Line where the checksum mismatch was detected
        line: usize,
    },
    /// Recovery code is incomplete.
    RecoveryCodeIncomplete,
    /// Recovery code version is unsupported.
    RecoveryCodeWrongVersion,
    /// Recovery code encodes less data than expected.
    RecoveryCodeInsufficientData,
}
