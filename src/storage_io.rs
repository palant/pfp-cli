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

/// File-based I/O implementation
pub struct FileIO
{
    path: path::PathBuf,
    data: HashMap<String, String>,
}

impl FileIO
{
    const APPLICATION_KEY: &'static str = "application";
    const APPLICATION_VALUE: &'static str = "pfp";
    const FORMAT_KEY: &'static str = "format";
    const CURRENT_FORMAT: u32 = 3;
    const DATA_KEY: &'static str = "data";

    /// Creates a new `FileIO` instance from a file path on disk.
    pub fn new(path: &path::Path) -> Self
    {
        Self {
            path: path.to_path_buf(),
            data: HashMap::new(),
        }
    }

    fn get_object(value: &json::JsonValue) -> Result<&json::object::Object, Error>
    {
        match value
        {
            json::JsonValue::Null => Err(Error::KeyMissing),
            json::JsonValue::Object(obj) => Ok(obj),
            _unexpected => Err(Error::UnexpectedData),
        }
    }

    fn get_string(value: &json::JsonValue) -> Result<String, Error>
    {
        Ok(value.as_str().ok_or(Error::UnexpectedData)?.to_string())
    }

    fn get_u32(value: &json::JsonValue) -> Result<u32, Error>
    {
        value.as_u32().ok_or(Error::UnexpectedData)
    }
}

impl StorageIO for FileIO
{
    fn load(&mut self) -> Result<(), Error>
    {
        let contents = fs::read_to_string(&self.path).map_err(|error| Error::FileReadFailure { error })?;
        let parsed = json::parse(&contents).map_err(|error| Error::InvalidJson { error })?;
        let root = Self::get_object(&parsed)?;

        if Self::get_string(&root[Self::APPLICATION_KEY])? != Self::APPLICATION_VALUE ||
           Self::get_u32(&root[Self::FORMAT_KEY])? != Self::CURRENT_FORMAT
        {
            return Err(Error::UnexpectedStorageFormat);
        }

        self.data.clear();
        let data_obj = Self::get_object(&root[Self::DATA_KEY])?;
        for (key, value) in data_obj.iter()
        {
            if let Ok(value) = Self::get_string(value)
            {
                self.data.insert(key.to_string(), value);
            }
        }
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
        let mut root = json::object::Object::new();
        root.insert(Self::APPLICATION_KEY, Self::APPLICATION_VALUE.into());
        root.insert(Self::FORMAT_KEY, Self::CURRENT_FORMAT.into());

        let mut data_obj = json::object::Object::new();
        for (key, value) in self.data.iter()
        {
            data_obj.insert(key, value.as_str().into());
        }
        root.insert(Self::DATA_KEY, data_obj.into());

        let contents = json::stringify(root);

        let parent = self.path.parent();
        if let Some(parent) = parent
        {
            fs::create_dir_all(parent).map_err(|error| Error::CreateDirFailure { error })?;
        }
        fs::write(&self.path, &contents).map_err(|error| Error::FileWriteFailure { error })
    }
}

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
