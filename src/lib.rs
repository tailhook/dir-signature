//! # Directory Signature Library
//!
//! ## v1
//!
//! Currently we have only implemented `v1` version of signature file,
//! it has the following limitations:
//!
//! * Only stores executable bit for files, no permissions and ownership
//!   support (this also means files can be replicated without privileges)
//! * File modification times are not checked and not replicated
//! * It's ascii text, so potentially 2x larger than what binary file could be
//!
//! While these limitations are not enough for generic backup purposes they
//! are fine for deploying configs and read-only images to production servers
//! in 99% use cases. Latter was a primary use case for the library. We will
//! probably make a more featureful format as v2 and later as deemed necessary.
//!
//! Design of the format features the following things:
//!
//! * Reproducible (does not depend on order of file scan)
//! * Easy to check even using a bash script (sans edge cases)
//! * Usable for file synchronization
//! * Can be produced and checked without loading full index into memory
//!
#![warn(missing_docs)]
#![recursion_limit="100"]

extern crate openat;
extern crate sha2;
extern crate blake2;
extern crate digest_writer;
extern crate generic_array;
extern crate typenum;
extern crate itertools;
#[macro_use] extern crate log;
#[macro_use] extern crate quick_error;

#[cfg(test)]
#[macro_use] extern crate matches;
#[cfg(test)]
extern crate rustc_serialize;


pub mod v1;
mod error;
mod config;
mod hash_type;
mod read;

pub use error::Error;
pub use hash_type::HashType;
pub use read::get_hash;

use std::path::PathBuf;

/// Scanner config contains a list of directories you will scan and other
/// settings that influence filesystem scanning
pub struct ScannerConfig {
    threads: usize,
    queue_size: Option<usize>,
    hash: HashType,
    block_size: u64,
    dirs: Vec<(PathBuf, PathBuf)>,
    print_progress: bool,
}
