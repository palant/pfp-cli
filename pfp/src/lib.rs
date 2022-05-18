/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

#![deny(unsafe_code, nonstandard_style)]
#![warn(missing_debug_implementations, missing_docs)]
#![forbid(rust_2021_compatibility)]

//! Functionality required to work with JSON files produced as data exports by the
//! PfP: Pain-free Passwords browser extension. Usually, you will use the high-level functionality
//! provided by the `passwords` module:
//!
//! ```no_run
//! use pfp::passwords::Passwords;
//! use pfp::storage_io::FileIO;
//! use std::path::Path;
//!
//! // Create an uninitialized Passwords instance for the given file
//! let io = FileIO::new(Path::new("test.json"));
//! let mut passwords = Passwords::new(io);
//! assert!(!passwords.initialized());
//!
//! // Initialize password storage with a new master password
//! passwords.reset("my master password").unwrap();
//!
//! // At this point test.json file should exist.
//! ```

mod crypto;
mod storage;

pub mod error;
pub mod passwords;
pub mod recovery_codes;
pub mod storage_io;
pub mod storage_types;
