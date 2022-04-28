/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

#[derive(Debug)]
pub enum Error
{
    CreateDirFailure,
    FileWriteFailure,
    StorageNotInitialized,
    PasswordsLocked,
    KeyMissing,
    InvalidCiphertext,
    InvalidBase64,
    InvalidJson,
    InvalidUtf8,
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
