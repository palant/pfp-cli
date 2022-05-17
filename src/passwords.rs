/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Holds the `Passwords` type encapsulating most of the crate's functionality.

use rand::Rng;
use crate::crypto;
use crate::error::Error;
use crate::recovery_codes;
use crate::storage;
use crate::storage_io;
use crate::storage_types::{PasswordId, GeneratedPassword, StoredPassword, Password, Site, CharacterSet};

/// Generates the storage data encryption key.
///
/// The encryption key is always derived from a particular secret master password. Salt should be a
/// random value to prevent rainbow table attacks. The salt is not considered a secret and is
/// stored as plain text in the storage file.
pub fn get_encryption_key(master_password: &str, salt: &[u8]) -> Vec<u8>
{
    // Replicate salt being converted to UTF-8 as done by JS code
    let salt_str = String::from_iter(salt.iter().map(|byte| *byte as char));
    crypto::derive_key(master_password, salt_str.as_bytes())
}

#[derive(Debug)]
/// The type providing access to the passwords storage, allowing to retrieve and manipulate its
/// data.
///
/// Typically, you will create a new `Passwords` instance using File I/O:
///
/// ```no_run
/// use pfp::passwords::Passwords;
/// use pfp::storage_io::FileIO;
/// use pfp::storage_types::CharacterSet;
/// use std::path::Path;
///
/// // Attempt to read passwords from a file
/// let io = FileIO::new(Path::new("test.json"));
/// Passwords::new(io).expect_err("Will error out with Error::FileReadFailure for missing file");
///
/// // Create an uninitialized Passwords instance
/// let io = FileIO::new(Path::new("test.json"));
/// let mut passwords = Passwords::uninitialized(io);
///
/// // Initialize password storage with a new master password
/// passwords.reset("my master password").unwrap();
///
/// // At this point test.json file should exist.
/// // Add a generated password for example.com
/// passwords.set_generated("example.com", "me", "1", 16, CharacterSet::all()).unwrap();
///
/// // Get generated password
/// assert_eq!(passwords.get("example.com", "me", "1").unwrap(), "sWEdAx<E<Gd_kaa2");
pub struct Passwords<IO>
{
    storage: storage::Storage<IO>,
    key: Option<Vec<u8>>,
    hmac_secret: Option<Vec<u8>>,
    master_password: Option<String>,
}

impl<IO: storage_io::StorageIO> Passwords<IO>
{
    /// Creates a new `Passwords` instance and loads data from `io`. Any errors produced by `io`
    /// when loading the data such as `Error::FileReadFailure` will be returned. Also, this will
    /// result in `Error::UnexpectedData` if salt or HMAC secret aren't present in the data.
    pub fn new(io: IO) -> Result<Self, Error>
    {
        Ok(Self {
            storage: storage::Storage::new(io)?,
            key: None,
            hmac_secret: None,
            master_password: None,
        })
    }

    /// Creates a new `Passwords` instance without initializing it by loading data from `io`.
    /// Calling [reset() method](#method.reset) will be necessary to use this instance.
    pub fn uninitialized(io: IO) -> Self
    {
        Self {
            storage: storage::Storage::uninitialized(io),
            key: None,
            hmac_secret: None,
            master_password: None,
        }
    }

    /// Checks whether storage data is present.
    ///
    /// This method returns `true` if the passwords storage is initialized: it was either read from
    /// disk successfully or reset using [reset() method](#method.reset).
    ///
    /// Note that this call returning `true` doesn't mean that passwords can be accessed. Password
    /// data also needs to be unlocked with the right master password.
    pub fn initialized(&self) -> bool
    {
        self.storage.initialized()
    }

    /// Checks whether storage data is unlocked.
    ///
    /// This method returns `true` if the master password is known and passwords can be accessed.
    ///
    /// Passwords can be unlocked through calling either [unlock()](#method.unlock) or
    /// [reset()](#method.reset).
    pub fn unlocked(&self) -> bool
    {
        self.key.is_some()
    }

    /// Clears the passwords storage and sets a new master password.
    ///
    /// This method will succeed on both initialized and uninitialized storage. If storage is
    /// already initialized, all existing data will be removed. On success, passwords storage will
    /// be unlocked implicitly, calling `unlock()` isn't required.
    ///
    /// This only produces errors related to writing out the storage data to disk.
    pub fn reset(&mut self, master_password: &str) -> Result<(), Error>
    {
        let salt = crypto::get_rng().gen::<[u8; 16]>();
        let key = get_encryption_key(master_password, &salt);
        let hmac_secret = crypto::get_rng().gen::<[u8; 32]>();

        self.storage.clear(&salt, &hmac_secret, &key)?;
        self.storage.flush()?;

        self.key = Some(key);
        self.hmac_secret = Some(hmac_secret.to_vec());
        self.master_password = Some(master_password.to_string());
        Ok(())
    }

    /// Unlocks the passwords storage with a given master password.
    ///
    /// If successful, it will be possible to access and manipulate passwords data after this call.
    /// Calling this method on uninitialized storage will result in
    /// [Error::StorageNotInitialized](../error/enum.Error.html#variant.StorageNotInitialized).
    /// Calling this method with a wrong master password will result in
    /// [Error::DecryptionFailure](../error/enum.Error.html#variant.DecryptionFailure).
    pub fn unlock(&mut self, master_password: &str) -> Result<(), Error>
    {
        let salt = self.storage.get_salt()?;
        let key = get_encryption_key(master_password, &salt);

        let hmac_secret = self.storage.get_hmac_secret(&key)?;
        self.key = Some(key);
        self.hmac_secret = Some(hmac_secret);
        self.master_password = Some(master_password.to_string());
        Ok(())
    }

    #[allow(dead_code)]
    /// Locks the passwords storage, forgetting anything it knows about the master password.
    ///
    /// After this call, passwords will no longer be accessible until [unlock()](#method.unlock)
    /// is called again.
    pub fn lock(&mut self)
    {
        self.key = None;
        self.hmac_secret = None;
        self.master_password = None;
    }

    /// Marks `site` and an alias for `alias`.
    ///
    /// This will normalize `site` parameter (remove `www.` prefix). If `alias` is itself marked as
    /// an alias for another site, `site` will become an alias for that site. Attempting to mark a
    /// site as an alias which already has passwords will result in
    /// [Error::SiteHasPasswords](../error/enum.Error.html#variant.SiteHasPasswords).
    pub fn set_alias(&mut self, site: &str, alias: &str) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_normalized = self.storage.normalize_site(site);
        let alias_resolved = self.storage.resolve_site(alias, hmac_secret, key);
        if self.storage.list_passwords(&site_normalized, hmac_secret, key).next().is_some()
        {
            return Err(Error::SiteHasPasswords);
        }

        self.storage.set_alias(&site_normalized, &alias_resolved, hmac_secret, key)?;
        self.storage.flush()
    }

    /// Turns `site` into a regular site, not an alias for another site any more.
    ///
    /// This will normalize `site` parameter (remove `www.` prefix). If `site` isn't marked as an
    /// alias, this call will result in
    /// [Error::NoSuchAlias](../error/enum.Error.html#variant.NoSuchAlias).
    pub fn remove_alias(&mut self, site: &str) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_normalized = self.storage.normalize_site(site);
        self.storage.remove_alias(&site_normalized, hmac_secret, key)?;
        self.storage.flush()
    }

    /// Removes a number of site entries.
    ///
    /// *Important*: This does not remove the passwords belonging to the sites, and this method
    /// will not check whether such passwords exist. It should only be called for sites known to
    /// have no passwords.
    pub fn remove_sites(&mut self, sites: &[String]) -> Result<(), Error>
    {
        if sites.is_empty()
        {
            return Ok(());
        }

        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        for site in sites
        {
            self.storage.remove_site(site, hmac_secret)?;
        }
        self.storage.flush()
    }

    /// Adds a generated password or replaces an existing password.
    ///
    /// The `site` (site name), `name` (password name) and `revision` (password revision)
    /// parameters identify a password, if a password with the same combination of these parameters
    /// exists it will be replaced. While revisions are usually numerical, any string can be used.
    /// The value `"1"` for revision is treated like an empty string.
    ///
    /// The `site` parameter will be normalized (`www.` prefix removed). If the site in question is
    /// an alias, the password will be associated with the site it is an alias for.
    ///
    /// When the password is generated, it will have the length `length` and use the character sets
    /// as determined by the `charset` parameter.
    pub fn set_generated(&mut self, site: &str, name: &str, revision: &str, length: usize, charset: CharacterSet) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        self.storage.ensure_site_data(&site_resolved, hmac_secret, key)?;

        self.storage.set_generated(
            GeneratedPassword::new(&site_resolved, name, revision, length, charset),
            hmac_secret, key
        )?;
        self.storage.flush()
    }

    /// Adds a stored password or replaces an existing password.
    ///
    /// The `site` (site name), `name` (password name) and `revision` (password revision)
    /// parameters identify a password, if a password with the same combination of these parameters
    /// exists it will be replaced. While revisions are usually numerical, any string can be used.
    /// The value `"1"` for revision is treated like an empty string.
    ///
    /// The `site` parameter will be normalized (`www.` prefix removed). If the site in question is
    /// an alias, the password will be associated with the site it is an alias for.
    ///
    /// The actual password value is supplied in the `password` parameter and will be encrypted
    /// along with all other data.
    pub fn set_stored(&mut self, site: &str, name: &str, revision: &str, password: &str) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        self.storage.ensure_site_data(&site_resolved, hmac_secret, key)?;

        self.storage.set_stored(
            StoredPassword::new(&site_resolved, name, revision, password),
            hmac_secret, key
        )?;
        self.storage.flush()
    }

    /// Checks whether the password storage has a password with the given `site`, `name` and
    /// `revision` combination. The value `"1"` for revision is treated like an empty string.
    ///
    /// The `site` parameter will be normalized (`www.` prefix removed). If the site in question is
    /// an alias, the password will be associated with the site it is an alias for.
    pub fn has(&self, site: &str, name: &str, revision: &str) -> Result<bool, Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        Ok(self.storage.has_password(
            &PasswordId::new(&site_resolved, name, revision),
            hmac_secret
        ))
    }

    /// Retrieves the value for the password with the given `site`, `name` and `revision`
    /// combination. The value `"1"` for revision is treated like an empty string.
    ///
    /// The `site` parameter will be normalized (`www.` prefix removed). If the site in question is
    /// an alias, the password will be associated with the site it is an alias for.
    ///
    /// If the password does not exist, the call will result in
    /// [Error::KeyMissing error](../error/enum.Error.html#variant.KeyMissing).
    pub fn get(&self, site: &str, name: &str, revision: &str) -> Result<String, Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;
        let master_password = self.master_password.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        let password = self.storage.get_password(
            &PasswordId::new(&site_resolved, name, revision),
            hmac_secret, key
        )?;

        match password
        {
            Password::Generated {password} =>
            {
                Ok(crypto::derive_password(master_password, &password.salt(), password.length(), password.charset()))
            }
            Password::Stored {password} =>
            {
                Ok(password.password().to_string())
            }
        }
    }

    /// Generates a human-readable recovery code for a stored password. With the correct master
    /// password, the password can be decoded back from the recovery code.
    pub fn get_recovery_code(&self, password: &StoredPassword) -> Result<String, Error>
    {
        let salt = self.storage.get_salt()?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;
        recovery_codes::generate(password.password(), &salt, key)
    }

    /// Decodes a recovery code into a password value. Any invalid characters in the recovery code
    /// will be ignored.
    ///
    /// This will produce the same errors as
    /// [recovery_codes::decode()](../recovery_codes/fn.decode.html).
    pub fn decode_recovery_code(&self, code: &str) -> Result<String, Error>
    {
        let master_password = self.master_password.as_ref().ok_or(Error::PasswordsLocked)?;
        recovery_codes::decode(code, master_password)
    }

    pub fn get_notes(&self, site: &str, name: &str, revision: &str) -> Result<String, Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        let password = self.storage.get_password(
            &PasswordId::new(&site_resolved, name, revision),
            hmac_secret, key
        )?;
        Ok(password.notes().to_string())
    }

    pub fn set_notes(&mut self, site: &str, name: &str, revision: &str, notes: &str) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        let mut password = self.storage.get_password(
            &PasswordId::new(&site_resolved, name, revision),
            hmac_secret, key
        )?;
        password.set_notes(notes);
        self.storage.set_password(password, hmac_secret, key)?;
        self.storage.flush()
    }

    /// Removes the password with the given `site`, `name` and `revision` combination. The value
    /// `"1"` for revision is treated like an empty string.
    ///
    /// The `site` parameter will be normalized (`www.` prefix removed). If the site in question is
    /// an alias, the password will be associated with the site it is an alias for.
    ///
    /// If the password does not exist, the call will result in
    /// [Error::KeyMissing error](../error/enum.Error.html#variant.KeyMissing).
    pub fn remove(&mut self, site: &str, name: &str, revision: &str) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        self.storage.remove_password(&PasswordId::new(&site_resolved, name, revision), hmac_secret)?;
        self.storage.flush()
    }

    /// Iterates over the passwords for a given site (site aliases will be resolved). The `name`
    /// parameter is a password name filter and can contain wildcards (see
    /// [wildmatch crate](https://docs.rs/wildmatch/latest/wildmatch/)). Passing `"*"` for `name`
    /// will list all passwords for the site.
    pub fn list(&self, site: &str, name: &str) -> impl Iterator<Item = Password> + '_
    {
        assert!(self.unlocked());

        let hmac_secret = self.hmac_secret.as_ref().unwrap();
        let key = self.key.as_ref().unwrap();
        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        let matcher = wildmatch::WildMatch::new(name);
        self.storage.list_passwords(&site_resolved, hmac_secret, key).filter(move |password|
        {
            return matcher.matches(password.id().name());
        })
    }

    /// Iterates over existing site entries. The `site` parameter is a site name filter and can
    /// contain wildcards (see [wildmatch crate](https://docs.rs/wildmatch/latest/wildmatch/)).
    /// Passing `"*"` for `site` will list all known sites.
    ///
    /// This function will also return aliased sites, both if the site name matches the filter and
    /// if the name of the site they are aliases for matches it.
    pub fn list_sites(&self, site: &str) -> impl Iterator<Item = Site> + '_
    {
        assert!(self.unlocked());

        let key = self.key.as_ref().unwrap();

        let matcher = wildmatch::WildMatch::new(site);
        self.storage.list_sites(key).filter(move |site|
        {
            return match site.alias()
            {
                Some(alias) => matcher.matches(alias),
                None => false,
            } || matcher.matches(site.name());
        })
    }
}

#[cfg(test)]
mod tests
{
    use std::collections::HashMap;
    use storage_io::MemoryIO;
    use super::*;

    const MASTER_PASSWORD: &str = "foobar";

    fn empty_data() -> HashMap<String, String>
    {
        HashMap::from([
            ("salt", "Y2Jh"),
            ("hmac-secret", "YWJjZGVmZ2hpamts_Nosk0g9vPYtLPn9QzyFXLQ/1ZuAHVw=="),
        ]).iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
    }

    fn default_data() -> HashMap<String, String>
    {
        HashMap::from([
            // cba as base64
            ("salt", "Y2Jh"),
            // abc encrypted (nonce abcdefghijkl, encryption key \x9b\x4f\x2d\x17\x37\xb6\xc2\x57\xf7\x50\x49\x51\x8c\x84\x49\x87\xb5\xde\x40\x1b\x3a\x87\x04\x8b\x26\x2d\x9b\x40\xae\xf8\xb0\xe2)
            ("hmac-secret", "YWJjZGVmZ2hpamts_Nosk0g9vPYtLPn9QzyFXLQ/1ZuAHVw=="),
            // example.com (hmac-sha256)
            ("site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=",
                // {"site":"example.com"} encrypted
                "YWJjZGVmZ2hpamts_b/AA8REorsFjuwlGDYB+KVw/fqoHPv2Ehc7sBIYqhR+ygcsd/t4="),
            // example.com\x00blubber\x00 (hmac-sha256)
            ("site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=:/uudghlPp4TDZPtfZFPj6nJs/zMDAE2AqVfz6Hu8N9I=",
                // {"type":"generated2","site":"example.com","name":"blubber","revision":"","length":16,"lower":true,"upper":true,"number":true,"symbol":true} encrypted
                "YWJjZGVmZ2hpamts_b/AH4RUorsFjuRRJBYJzOBc4I+UJYXWhqhFXbEC9Aw5pRRO/Q31d6d/+RQhdj8wH0SWpEXk/ZkVXSAjSqpbqKsEek2JzzOetQNutMR4tblZGzTsPxWZogaKazYGFvg+J43L9ugBf7PjDfk+Rx3QbGdWaScEdCdciXlv6z/drMjyK0b8+kKgrdjdaIT7NuJwpEiZxzMngRiqPqZI="),
            // example.com\x00blabber\x002 (hmac-sha256)
            ("site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=:h2pnx6RFyNbAUBLcuQYz9w79/vnf4fgJlY/c+EP44d8=",
                // {"type":"stored","site":"example.com","name":"blabber","revision":"2","password":"asdf","notes":"hi there!"} encrypted
                "YWJjZGVmZ2hpamts_b/AH4RUorsFjrQVIEpV2bl5+Yq5RJiTy/BENNw+oFwoqVhC3TzIQ6py/AkQGwMtJimWpGH5/KAJXD1KZq5rzLZBN3j5z2uf/DYqyIx84fhxe1WtKjSImwveR0NfauV/GpDa27wRH7PiEZRmeoJNQ8MV3Bopr61xNEWK0ew=="),
            // example.info (hmac-sha256)
            ("site:Gd2Cx/SbNs6BWf2KlmHZrOY7SNi5GnjBLG58eJdgqdc=",
                // {"site":"example.info"} encrypted
                "YWJjZGVmZ2hpamts_b/AA8REorsFjuwlGDYB+KVw1f6FKYXsPR37ZtYXddpCecTwncBIM"),
            // example.info\x00test\x00yet another (hmac-sha256)
            ("site:Gd2Cx/SbNs6BWf2KlmHZrOY7SNi5GnjBLG58eJdgqdc=:BSjLwWY3MLEPQdG1f/jwKOtJRKCxwXpRH5qkMrUnVsI=",
                // {"type":"generated2","site":"example.info","name":"test","revision":"yet another","length":8,"lower":true,"upper":false,"number":true,"symbol":false,"notes":"nothing here"} encrypted
                "YWJjZGVmZ2hpamts_b/AH4RUorsFjuRRJBYJzOBc4I+UJYXWhqhFXbEC9Aw5pRRO/Q3dc4pLwS0RSg8RAyT3pCWkucAIJSFaVrprvKt0Z3jZzj6D7TJivOwQif0xG2yhVjCpjmr3dhZuT6BGT8Tut7Upb+/+EaBmWwmFSSZnVQsIUCJA0CEf6x7ksM2fdx6In1759dztSPv4LAx+oMQrVG2lMD14TzIctWTOQysV+9JdUWXZRkyZDOtnHHTfVanjSaON/wEY2P5w="),
            // example.org (hmac-sha256)
            ("site:5IS/IdH3aaMwyzRv0fwy+2oh5OsXZ2emV8991dFWrko=",
                // {"site":"example.org","alias":"example.com"} encrypted
                "YWJjZGVmZ2hpamts_b/AA8REorsFjuwlGDYB+KVwzY6AHbySpsh0UJUDiWQp8VBKqAXsc55K/RRsY3NAIQzDdtK+4TrjLOu3X"),
        ]).iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
    }

    fn password_name(password: Password) -> String
    {
        password.id().name().to_string()
    }

    mod initialization
    {
        use super::*;

        #[test]
        fn read_empty_data()
        {
            let io = MemoryIO::new(HashMap::new());
            assert!(matches!(Passwords::new(io).expect_err("Creating Passwords instance from empty data should fail"), Error::InvalidJson { .. }));
        }

        #[test]
        fn read_success()
        {
            let io = MemoryIO::new(empty_data());
            let passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");

            assert_eq!(passwords.initialized(), true);
            assert_eq!(passwords.unlocked(), false);
        }

        #[test]
        fn unlock()
        {
            let io = MemoryIO::new(default_data());
            let mut passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");

            assert!(matches!(passwords.unlock("asdfyxcv").expect_err("Passwords shouldn't unlock"), Error::DecryptionFailure { .. }));
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");
        }
    }

    mod reset
    {
        use super::*;

        #[test]
        fn reset_uninitialized()
        {
            let io = MemoryIO::new(HashMap::new());
            let mut passwords = Passwords::uninitialized(io);
            assert_eq!(passwords.initialized(), false);

            passwords.reset(MASTER_PASSWORD).expect("Reset should succeed");
            assert_eq!(passwords.initialized(), true);
            assert_eq!(passwords.unlocked(), true);
            assert_eq!(passwords.list_sites("*").count(), 0);

            assert_eq!(passwords.storage.get_salt().expect("Salt should be present"), b"abcdefghijklmnop");
            assert_eq!(passwords.hmac_secret.as_ref().expect("HMAC secret should be present"), b"abcdefghijklmnopqrstuvwxyz{|}~\x7F\x80");
            assert_eq!(passwords.master_password.as_ref().expect("Master password should be present"), MASTER_PASSWORD);

            passwords.lock();
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");
            assert_eq!(passwords.storage.get_salt().expect("Salt should be present"), b"abcdefghijklmnop");
            assert_eq!(passwords.hmac_secret.as_ref().expect("HMAC secret should be present"), b"abcdefghijklmnopqrstuvwxyz{|}~\x7F\x80");
            assert_eq!(passwords.master_password.as_ref().expect("Master password should be present"), MASTER_PASSWORD);
        }

        #[test]
        fn reset_initialized()
        {
            let io = MemoryIO::new(default_data());
            let mut passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");
            passwords.reset(MASTER_PASSWORD).expect("Reset should succeed");

            assert_eq!(passwords.initialized(), true);
            assert_eq!(passwords.unlocked(), true);
            assert_eq!(passwords.list_sites("*").count(), 0);

            assert_eq!(passwords.storage.get_salt().expect("Salt should be present"), b"abcdefghijklmnop");
            assert_eq!(passwords.hmac_secret.as_ref().expect("HMAC secret should be present"), b"abcdefghijklmnopqrstuvwxyz{|}~\x7F\x80");
            assert_eq!(passwords.master_password.as_ref().expect("Master password should be present"), MASTER_PASSWORD);

            passwords.lock();
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");
            assert_eq!(passwords.storage.get_salt().expect("Salt should be present"), b"abcdefghijklmnop");
            assert_eq!(passwords.hmac_secret.as_ref().expect("HMAC secret should be present"), b"abcdefghijklmnopqrstuvwxyz{|}~\x7F\x80");
            assert_eq!(passwords.master_password.as_ref().expect("Master password should be present"), MASTER_PASSWORD);
        }
    }

    mod retrieval
    {
        use super::*;

        fn list_sites(passwords: &Passwords<MemoryIO>, site: &str) -> Vec<String>
        {
            let mut vec = passwords.list_sites(site).map(|site| site.name().to_string()).collect::<Vec<String>>();
            vec.sort();
            vec
        }

        fn list_passwords(passwords: &Passwords<MemoryIO>, site: &str, name: &str) -> Vec<String>
        {
            let mut vec = passwords.list(site, name).map(password_name).collect::<Vec<String>>();
            vec.sort();
            vec
        }

        #[test]
        fn list_sites_wildcards()
        {
            let io = MemoryIO::new(default_data());
            let mut passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");

            assert_eq!(list_sites(&passwords, "*"), vec!["example.com", "example.info", "example.org"]);
            assert_eq!(list_sites(&passwords, "ex*"), vec!["example.com", "example.info", "example.org"]);
            assert_eq!(list_sites(&passwords, "*.com"), vec!["example.com", "example.org"]);
            assert_eq!(list_sites(&passwords, "*am*i*"), vec!["example.info"]);
            assert_eq!(list_sites(&passwords, "example.info"), vec!["example.info"]);
            assert_eq!(list_sites(&passwords, "example.net").len(), 0);
            assert_eq!(list_sites(&passwords, "blub*").len(), 0);
        }

        #[test]
        fn list_passwords_wildcards()
        {
            let io = MemoryIO::new(default_data());
            let mut passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");

            assert_eq!(list_passwords(&passwords, "example.com", "*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.com", "*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "example.org", "*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.org", "*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "example.info", "*"), vec!["test"]);
            assert_eq!(list_passwords(&passwords, "www.example.info", "*"), vec!["test"]);

            assert_eq!(list_passwords(&passwords, "example.com", "b*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.com", "b*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "example.org", "b*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.org", "b*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "example.info", "b*").len(), 0);
            assert_eq!(list_passwords(&passwords, "www.example.info", "b*").len(), 0);

            assert_eq!(list_passwords(&passwords, "example.com", "blu*"), vec!["blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.com", "blu*"), vec!["blubber"]);
            assert_eq!(list_passwords(&passwords, "example.org", "blu*"), vec!["blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.org", "blu*"), vec!["blubber"]);
            assert_eq!(list_passwords(&passwords, "example.info", "blu*").len(), 0);
            assert_eq!(list_passwords(&passwords, "www.example.info", "blu*").len(), 0);

            assert_eq!(list_passwords(&passwords, "example.com", "*a*"), vec!["blabber"]);
            assert_eq!(list_passwords(&passwords, "www.example.com", "*a*"), vec!["blabber"]);
            assert_eq!(list_passwords(&passwords, "example.org", "*a*"), vec!["blabber"]);
            assert_eq!(list_passwords(&passwords, "www.example.org", "*a*"), vec!["blabber"]);
            assert_eq!(list_passwords(&passwords, "example.info", "t*t"), vec!["test"]);
            assert_eq!(list_passwords(&passwords, "www.example.info", "t*t"), vec!["test"]);
        }

        #[test]
        fn query_passwords()
        {
            let io = MemoryIO::new(default_data());
            let mut passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");

            assert!(passwords.has("example.com", "blubber", "").expect("Check should succeed"));
            assert_eq!(passwords.get("example.com", "blubber", "").expect("Retrieval should succeed"), "SUDJjn&%:nBe}cr8");
            assert!(passwords.has("www.example.com", "blubber", "").expect("Check should succeed"));
            assert_eq!(passwords.get("www.example.com", "blubber", "").expect("Retrieval should succeed"), "SUDJjn&%:nBe}cr8");
            assert!(passwords.has("example.org", "blubber", "").expect("Check should succeed"));
            assert_eq!(passwords.get("example.org", "blubber", "").expect("Retrieval should succeed"), "SUDJjn&%:nBe}cr8");
            assert!(passwords.has("www.example.org", "blubber", "").expect("Check should succeed"));
            assert_eq!(passwords.get("www.example.org", "blubber", "").expect("Retrieval should succeed"), "SUDJjn&%:nBe}cr8");

            assert!(passwords.has("example.com", "blabber", "2").expect("Check should succeed"));
            assert_eq!(passwords.get("example.com", "blabber", "2").expect("Retrieval should succeed"), "asdf");
            assert!(passwords.has("www.example.com", "blabber", "2").expect("Check should succeed"));
            assert_eq!(passwords.get("www.example.com", "blabber", "2").expect("Retrieval should succeed"), "asdf");
            assert!(passwords.has("example.org", "blabber", "2").expect("Check should succeed"));
            assert_eq!(passwords.get("example.org", "blabber", "2").expect("Retrieval should succeed"), "asdf");
            assert!(passwords.has("www.example.org", "blabber", "2").expect("Check should succeed"));
            assert_eq!(passwords.get("www.example.org", "blabber", "2").expect("Retrieval should succeed"), "asdf");

            assert!(passwords.has("example.info", "test", "yet another").expect("Check should succeed"));
            assert_eq!(passwords.get("example.info", "test", "yet another").expect("Retrieval should succeed"), "rjtfxqf4");
            assert!(passwords.has("www.example.info", "test", "yet another").expect("Check should succeed"));
            assert_eq!(passwords.get("www.example.info", "test", "yet another").expect("Retrieval should succeed"), "rjtfxqf4");
            assert!(!passwords.has("example.info", "blubber", "").expect("Check should succeed"));
            assert!(matches!(passwords.get("example.info", "blubber", "").expect_err("Retrieval should fail"), Error::KeyMissing { .. }));
            assert!(!passwords.has("www.example.info", "blubber", "").expect("Check should succeed"));
            assert!(matches!(passwords.get("www.example.info", "blubber", "").expect_err("Retrieval should fail"), Error::KeyMissing { .. }));
        }
    }

    mod addition
    {
        use super::*;
        use crate::storage_types::CharacterType;

        #[test]
        fn add_passwords()
        {
            let io = MemoryIO::new(empty_data());
            let mut passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");

            assert!(matches!(passwords.set_alias("www.example.org", "example.org").expect_err("Adding alias should fail"), Error::AliasToSelf { .. }));
            passwords.set_alias("www.example.org", "www.example.com").expect("Adding alias should succeed");
            assert!(matches!(passwords.set_alias("www.example.com", "example.org").expect_err("Adding alias should fail"), Error::AliasToSelf { .. }));

            passwords.set_generated("example.com", "blubber", "", 16, CharacterSet::all()).expect("Adding password should succeed");
            passwords.set_stored("example.com", "blabber", "2", "asdf").expect("Adding password should succeed");
            passwords.set_generated("example.info", "test", "yet another", 8, CharacterType::Lower | CharacterType::Digit).expect("Adding password should succeed");

            assert!(matches!(passwords.set_alias("www.example.com", "example.info").expect_err("Adding alias should fail"), Error::SiteHasPasswords { .. }));

            assert_eq!(passwords.get("example.com", "blubber", "").expect("Retrieval should succeed"), "SUDJjn&%:nBe}cr8");
            assert_eq!(passwords.get("example.org", "blubber", "").expect("Retrieval should succeed"), "SUDJjn&%:nBe}cr8");

            assert_eq!(passwords.get("www.example.com", "blabber", "2").expect("Retrieval should succeed"), "asdf");
            assert_eq!(passwords.get("www.example.org", "blabber", "2").expect("Retrieval should succeed"), "asdf");

            assert_eq!(passwords.get("example.info", "test", "yet another").expect("Retrieval should succeed"), "rjtfxqf4");
            assert!(matches!(passwords.get("example.info", "blubber", "").expect_err("Retrieval should fail"), Error::KeyMissing { .. }));
        }
    }

    mod notes
    {
        use super::*;

        #[test]
        fn notes()
        {
            let io = MemoryIO::new(default_data());
            let mut passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");

            assert_eq!(passwords.get_notes("www.example.com", "blubber", "").expect("Getting notes should succeed"), "");
            assert_eq!(passwords.get_notes("www.example.com", "blabber", "2").expect("Getting notes should succeed"), "hi there!");
            assert_eq!(passwords.get_notes("example.info", "test", "yet another").expect("Getting notes should succeed"), "nothing here");
            assert!(matches!(passwords.get_notes("example.info", "blubber", "").expect_err("Getting notes should fail"), Error::KeyMissing { .. }));

            passwords.set_notes("example.com", "blubber", "", "hey!").expect("Setting notes should succeed");
            passwords.set_notes("example.com", "blabber", "2", "").expect("Setting notes should succeed");
            passwords.set_notes("www.example.info", "test", "yet another", "something here").expect("Setting notes should succeed");
            assert!(matches!(passwords.set_notes("example.info", "blubber", "", "").expect_err("Getting notes should fail"), Error::KeyMissing { .. }));

            assert_eq!(passwords.get_notes("www.example.com", "blubber", "").expect("Getting notes should succeed"), "hey!");
            assert_eq!(passwords.get_notes("www.example.com", "blabber", "2").expect("Getting notes should succeed"), "");
            assert_eq!(passwords.get_notes("example.info", "test", "yet another").expect("Getting notes should succeed"), "something here");
            assert!(matches!(passwords.get_notes("example.info", "blubber", "").expect_err("Getting notes should fail"), Error::KeyMissing { .. }));
        }
    }

    mod removal
    {
        use super::*;

        #[test]
        fn remove_passwords()
        {
            let io = MemoryIO::new(default_data());
            let mut passwords = Passwords::new(io).expect("Creating Passwords instance should succeed");
            passwords.unlock(MASTER_PASSWORD).expect("Passwords should unlock");

            assert!(matches!(passwords.remove_alias("example.net").expect_err("Removing alias should fail"), Error::NoSuchAlias { .. }));
            passwords.remove("www.example.org", "blubber", "").expect("Removing password should succeed");
            passwords.remove_alias("www.example.org").expect("Removing alias should succeed");
            assert!(matches!(passwords.remove("example.org", "blabber", "2").expect_err("Removing password should fail"), Error::KeyMissing { .. }));
            passwords.remove("example.com", "blabber", "2").expect("Removing password should succeed");
            passwords.remove("example.info", "test", "yet another").expect("Removing password should succeed");
            assert!(matches!(passwords.remove("example.info", "test", "yet another").expect_err("Removing password should fail"), Error::KeyMissing { .. }));

            assert_eq!(passwords.list("example.com", "*").count(), 0);
            assert_eq!(passwords.list("example.info", "*").count(), 0);

            passwords.remove_sites(&["example.com".to_string(), "example.info".to_string()]).expect("Removing sites should succeed");
            assert_eq!(passwords.list_sites("*").count(), 0);
        }
    }
}
