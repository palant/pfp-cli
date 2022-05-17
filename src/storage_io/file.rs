/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::json;
use crate::error::Error;
use std::collections::HashMap;
use std::fs;
use std::path;

#[derive(Debug)]
/// File-based I/O implementation
pub struct FileIO {
    path: path::PathBuf,
    data: json::Metadata,
}

impl FileIO {
    /// Creates a new `FileIO` instance from a file path on disk.
    pub fn new(path: &path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
            data: json::Metadata::new(HashMap::new()),
        }
    }

    fn data(&self) -> &HashMap<String, String> {
        self.data.data()
    }

    fn data_mut(&mut self) -> &mut HashMap<String, String> {
        self.data.data_mut()
    }
}

impl super::StorageIO for FileIO {
    fn load(&mut self) -> Result<(), Error> {
        let contents =
            fs::read_to_string(&self.path).map_err(|error| Error::FileReadFailure { error })?;
        self.data = serde_json::from_str::<json::Metadata>(&contents)
            .map_err(|error| Error::InvalidJson { error })?;
        Ok(())
    }

    fn contains_key(&self, key: &str) -> bool {
        self.data().contains_key(key)
    }

    fn get(&self, key: &str) -> Result<&String, Error> {
        self.data().get(key).ok_or(Error::KeyMissing)
    }

    fn set(&mut self, key: String, value: String) {
        self.data_mut().insert(key, value);
    }

    fn remove(&mut self, key: &str) -> Result<(), Error> {
        self.data_mut()
            .remove(key)
            .map(|_| ())
            .ok_or(Error::KeyMissing)
    }

    fn keys(&self) -> Box<dyn Iterator<Item = &String> + '_> {
        Box::new(self.data().keys())
    }

    fn clear(&mut self) {
        self.data_mut().clear();
    }

    fn flush(&mut self) -> Result<(), Error> {
        let contents =
            serde_json::to_string(&self.data).map_err(|error| Error::InvalidJson { error })?;

        let parent = self.path.parent();
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|error| Error::CreateDirFailure { error })?;
        }
        fs::write(&self.path, &contents).map_err(|error| Error::FileWriteFailure { error })
    }
}
