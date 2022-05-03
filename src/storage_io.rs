/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use std::cell::Cell;
use std::fs;
use std::path;
use super::error::Error;

pub trait StorageIO
{
    fn load(&self) -> Result<String, Error>;
    fn save(&self, data: &str) -> Result<(), Error>;
}

pub struct FileIO
{
    path: path::PathBuf,
}

impl FileIO
{
    pub fn new(path: &path::PathBuf) -> Self
    {
        return Self { path: path.clone() };
    }
}

impl StorageIO for FileIO
{
    fn load(&self) -> Result<String, Error>
    {
        return fs::read_to_string(&self.path).or_else(|error| Err(Error::FileReadFailure { error }));
    }

    fn save(&self, data: &str) -> Result<(), Error>
    {
        let parent = self.path.parent();
        match parent
        {
            Some(parent) => fs::create_dir_all(parent).or_else(|error| Err(Error::CreateDirFailure { error }))?,
            None => {},
        }
        return fs::write(&self.path, data).or_else(|error| Err(Error::FileWriteFailure { error }));
    }
}

pub struct MemoryIO
{
    data: Cell<String>,
}

impl MemoryIO
{
    #[cfg(test)]
    pub fn new(data: &str) -> Self
    {
        return Self { data: Cell::new(data.to_string()) };
    }
}

impl StorageIO for MemoryIO
{
    fn load(&self) -> Result<String, Error>
    {
        let data = self.data.take();
        self.data.set(data.clone());
        return Ok(data);
    }

    fn save(&self, data: &str) -> Result<(), Error>
    {
        self.data.set(data.to_string());
        return Ok(());
    }
}
