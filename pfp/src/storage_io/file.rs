/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use json_streamed as json;

use crate::error::Error;
use json::{const_serializable, Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path;

const_serializable!(ApplicationName: String = "pfp");
const_serializable!(Format: u8 = 3);

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "json", deny_unknown_fields)]
/// File-based I/O implementation
pub struct FileIO {
    #[serde(skip)]
    path: path::PathBuf,
    application: ApplicationName,
    format: Format,
    data: HashMap<String, String>,
}

impl FileIO {
    /// Creates a `FileIO` instance without any data.
    ///
    /// `path` parameter determines where the data is saved when it is flushed to disk.
    pub fn new(path: &path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
            application: ApplicationName,
            format: Format,
            data: HashMap::new(),
        }
    }

    /// Creates a `FileIO` instance by loading data from disk.
    pub fn load(path: &path::Path) -> Result<Self, Error> {
        let contents =
            fs::read_to_string(path).map_err(|error| Error::FileReadFailure { error })?;

        let mut result =
            json::from_str::<Self>(&contents).map_err(|error| Error::InvalidJson { error })?;
        result.path = path.to_path_buf();
        Ok(result)
    }
}

impl super::StorageIO for FileIO {
    fn contains_key(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    fn get(&self, key: &str) -> Result<&String, Error> {
        self.data.get(key).ok_or(Error::KeyMissing)
    }

    fn set(&mut self, key: String, value: String) {
        self.data.insert(key, value);
    }

    fn remove(&mut self, key: &str) -> Result<(), Error> {
        self.data.remove(key).map(|_| ()).ok_or(Error::KeyMissing)
    }

    fn keys(&self) -> Box<dyn Iterator<Item = &String> + '_> {
        Box::new(self.data.keys())
    }

    fn clear(&mut self) {
        self.data.clear();
    }

    fn flush(&mut self) -> Result<(), Error> {
        let contents = json::to_string(self).map_err(|error| Error::InvalidJson { error })?;

        let parent = self.path.parent();
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|error| Error::CreateDirFailure { error })?;
        }
        fs::write(&self.path, &contents).map_err(|error| Error::FileWriteFailure { error })
    }
}
