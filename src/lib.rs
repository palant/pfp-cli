/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Functionality required to work with JSON files produced as data exports by the
//! PfP: Pain-free Passwords browser extension. Usually, you will use the high-level functionality
//! provided by the `passwords` module:
//!
//! ```no_run
//! use pfp::passwords::Passwords;
//! use pfp::storage_io::FileIO;
//! use std::path::Path;
//!
//! let io = FileIO::new(Path::new("test.json"));
//! Passwords::new(io).expect_err("Will error out with Error::FileReadFailure for missing file");
//!
//! let io = FileIO::new(Path::new("test.json"));
//! let mut passwords = Passwords::uninitialized(io);
//!
//! // Initialize password storage with a new master password
//! passwords.reset("my master password").unwrap();
//!
//! // At this point test.json file should exist.
//! ```

mod crypto;
pub mod error;
pub mod passwords;
pub mod recovery_codes;
mod storage;
pub mod storage_io;
pub mod storage_types;
