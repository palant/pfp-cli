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

use std::collections::HashMap;
use std::fs;
use std::path;
use super::error::Error;

/// Methods to be exposed by the type wrapping access to the storage file.
pub trait StorageIO
{
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
    /// Iterates over keys contained in the data.
    /// Removes all data from the file.
    fn clear(&mut self);
    fn keys(&self) -> Box<dyn Iterator<Item = &String> + '_>;
    /// Saves the changes back to the storage file if necessary.
    fn flush(&mut self) -> Result<(), Error>;
}

#[derive(Debug)]
/// File-based I/O implementation
pub struct FileIO
{
    path: path::PathBuf,
    data: HashMap<String, String>,
}

impl FileIO
{
    /// Creates a new `FileIO` instance from a file path on disk.
    pub fn new(path: &path::Path) -> Self
    {
        Self {
            path: path.to_path_buf(),
            data: HashMap::new(),
        }
    }
}

impl StorageIO for FileIO
{
    fn load(&mut self) -> Result<(), Error>
    {
        let contents = fs::read_to_string(&self.path).map_err(|error| Error::FileReadFailure { error })?;
        self.data =
            serde_json::from_str::<json::Metadata>(&contents)
                .map_err(|error| Error::InvalidJson { error })?
                .data();
        Ok(())
    }

    fn contains_key(&self, key: &str) -> bool
    {
        self.data.contains_key(key)
    }

    fn get(&self, key: &str) -> Result<&String, Error>
    {
        self.data.get(key).ok_or(Error::KeyMissing)
    }

    fn set(&mut self, key: String, value: String)
    {
        self.data.insert(key, value);
    }

    fn remove(&mut self, key: &str) -> Result<(), Error>
    {
        self.data.remove(key).map(|_| ()).ok_or(Error::KeyMissing)
    }

    fn keys(&self) -> Box<dyn Iterator<Item = &String> + '_>
    {
        Box::new(self.data.keys())
    }

    fn clear(&mut self)
    {
        self.data.clear();
    }

    fn flush(&mut self) -> Result<(), Error>
    {
        let data = std::mem::replace(&mut self.data, HashMap::new());
        let metadata = json::Metadata::new(data);
        let result = serde_json::to_string(&metadata);
        self.data = metadata.data();

        let contents = result.map_err(|error| Error::InvalidJson { error })?;

        let parent = self.path.parent();
        if let Some(parent) = parent
        {
            fs::create_dir_all(parent).map_err(|error| Error::CreateDirFailure { error })?;
        }
        fs::write(&self.path, &contents).map_err(|error| Error::FileWriteFailure { error })
    }
}

#[derive(Debug)]
/// In-memory I/O implementation (for tests)
pub struct MemoryIO
{
    file_data: HashMap<String, String>,
    data: HashMap<String, String>,
}

impl MemoryIO
{
    #[cfg(test)]
    /// Creates a new `MemoryIO` instance with some initial "file" data.
    pub fn new(data: HashMap<String, String>) -> Self
    {
        Self {
            file_data: data,
            data: HashMap::new(),
        }
    }

    pub fn data(&self) -> &HashMap<String, String>
    {
        &self.file_data
    }
}

impl StorageIO for MemoryIO
{
    fn load(&mut self) -> Result<(), Error>
    {
        self.data = self.file_data.clone();
        Ok(())
    }

    fn contains_key(&self, key: &str) -> bool
    {
        self.data.contains_key(key)
    }

    fn get(&self, key: &str) -> Result<&String, Error>
    {
        self.data.get(key).ok_or(Error::KeyMissing)
    }

    fn set(&mut self, key: String, value: String)
    {
        self.data.insert(key, value);
    }

    fn remove(&mut self, key: &str) -> Result<(), Error>
    {
        self.data.remove(key).map(|_| ()).ok_or(Error::KeyMissing)
    }

    fn keys(&self) -> Box<dyn Iterator<Item = &String> + '_>
    {
        Box::new(self.data.keys())
    }

    fn clear(&mut self)
    {
        self.data.clear();
    }

    fn flush(&mut self) -> Result<(), Error>
    {
        self.file_data = self.data.clone();
        Ok(())
    }
}
