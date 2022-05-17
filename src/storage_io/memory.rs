/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::error::Error;
use std::collections::HashMap;

#[derive(Debug)]
/// In-memory I/O implementation (for tests)
pub struct MemoryIO {
    file_data: HashMap<String, String>,
    data: HashMap<String, String>,
}

impl MemoryIO {
    #[cfg(test)]
    /// Creates a new `MemoryIO` instance with some initial "file" data.
    pub fn new(data: HashMap<String, String>) -> Self {
        Self {
            file_data: data,
            data: HashMap::new(),
        }
    }

    /// Retrieves the data stored in the "file".
    pub fn data(&self) -> &HashMap<String, String> {
        &self.file_data
    }
}

impl super::StorageIO for MemoryIO {
    fn load(&mut self) -> Result<(), Error> {
        self.data = self.file_data.clone();
        Ok(())
    }

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
        self.file_data = self.data.clone();
        Ok(())
    }
}
