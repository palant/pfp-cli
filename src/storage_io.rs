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

pub struct MemoryIO
{
    data: Cell<String>,
}

impl MemoryIO
{
    #[cfg(test)]
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
