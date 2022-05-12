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

use std::cell::Cell;
use std::fs;
use std::path;
use super::error::Error;

/// Methods to be exposed by the type wrapping access to the storage file.
pub trait StorageIO
{
    /// Reads storage file into a string.
    fn load(&self) -> Result<String, Error>;
    /// Saves the storage data back into the file.
    fn save(&self, data: &str) -> Result<(), Error>;
}

/// File-based I/O implementation
pub struct FileIO
{
    path: path::PathBuf,
}

impl FileIO
{
    /// Creates a new `FileIO` instance from a file path on disk.
    pub fn new(path: &path::Path) -> Self
    {
        Self {
            path: path.to_path_buf()
        }
    }
}

impl StorageIO for FileIO
{
    fn load(&self) -> Result<String, Error>
    {
        fs::read_to_string(&self.path).map_err(|error| Error::FileReadFailure { error })
    }

    fn save(&self, data: &str) -> Result<(), Error>
    {
        let parent = self.path.parent();
        if let Some(parent) = parent
        {
            fs::create_dir_all(parent).map_err(|error| Error::CreateDirFailure { error })?;
        }
        fs::write(&self.path, data).map_err(|error| Error::FileWriteFailure { error })
    }
}

/// In-memory I/O implementation (for tests)
pub struct MemoryIO
{
    data: Cell<String>,
}

impl MemoryIO
{
    #[cfg(test)]
    /// Creates a new `MemoryIO` instance with given "file" data.
    pub fn new(data: &str) -> Self
    {
        Self {
            data: Cell::new(data.to_string())
        }
    }
}

impl StorageIO for MemoryIO
{
    fn load(&self) -> Result<String, Error>
    {
        let data = self.data.take();
        self.data.set(data.clone());
        Ok(data)
    }

    fn save(&self, data: &str) -> Result<(), Error>
    {
        self.data.set(data.to_string());
        Ok(())
    }
}
