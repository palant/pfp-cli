/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Functionality required to work with JSON files produced as data exports by the
//! PfP: Pain-free Passwords browser extension. Usually, you will use the high-level functionality
//! provided by the `passwords` module:
//!
//! ```
//! use pfp::passwords::Passwords;
//! use pfp::storage::Storage;
//! use pfp::storage_io::FileIO;
//! use std::path::Path;
//!
//! let io = FileIO::new(Path::new("test.json"));
//! let storage = Storage::new(io);
//! let passwords = Passwords::new(storage);
//!
//! // Password storage will be uninitialized because the file doesn't exist yet.
//! assert!(passwords.initialized().is_err());
//!
//! // Password storage will be locked because we didn't set the master password yet.
//! assert!(passwords.unlocked().is_err());
//! ```

pub mod crypto;
pub mod error;
pub mod passwords;
pub mod recovery_codes;
pub mod storage;
pub mod storage_io;
pub mod storage_types;
