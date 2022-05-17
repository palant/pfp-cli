/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! I/O abstraction layer
//!
//! The types defined here are used by the the
//! [Passwords type](../passwords/struct.Passwords.html).
//!
//! ```
//! use pfp::passwords::Passwords;
//! use pfp::storage_io::FileIO;
//! use std::path::Path;
//!
//! let io = FileIO::new(Path::new("test.json"));
//! let passwords = Passwords::new(io);
//! ```

mod json;

mod file;
pub use file::FileIO;

#[cfg(test)]
mod memory;
#[cfg(test)]
pub use memory::MemoryIO;

use crate::error::Error;

/// Methods to be exposed by the type wrapping access to the storage file.
pub trait StorageIO {
    /// Reads storage file.
    fn load(&mut self) -> Result<(), Error>;
    /// Checks whether a particular key is present in the data.
    fn contains_key(&self, key: &str) -> bool;
    /// Gets the value associated with a particular key or returns `Error::KeyMissing` if the key
    /// isn't found.
    fn get(&self, key: &str) -> Result<&String, Error>;
    /// Adds a new key to the file or overwrites the value for an existing key with a new value.
    fn set(&mut self, key: String, value: String);
    /// Removes the value associated with a particlar key or returns `Error::KeyMissing` if the key
    /// isn't found.
    fn remove(&mut self, key: &str) -> Result<(), Error>;
    /// Removes all data from the file.
    fn clear(&mut self);
    /// Iterates over keys contained in the data.
    fn keys(&self) -> Box<dyn Iterator<Item = &String> + '_>;
    /// Saves the changes back to the storage file if necessary.
    fn flush(&mut self) -> Result<(), Error>;
}
