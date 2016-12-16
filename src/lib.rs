//! # Directory Signature Library
//!
//! ## v1
//!
//! Currently whe have only implemented `v1` version of signature file,
//! it has the following limitations:
//!
//! * Only stores executable bit for files, no permissions and ownership
//!   support (this also means files can be replicated without privileges)
//! * File modification times are not checked and not replicated
//! * It's ascii text, so potentially 2x larger than what binary file could be
//! * While technically block size and hash kind are configurable we don't
//!   support anything other than 32768 and sha512/256
//!
//! While these limitations are not enough for generic backup purposes they
//! are fine for deploying configs and read-only images to production servers
//! in 99% use cases. Latter was a primary use case for the library. We will
//! probably make a more featureful format as v2 and later as deemed necessary.
//!
//! Design of the format features the following things;
//!
//! * Reproducible (does not depend on order of file scan)
//! * Easy to check even using a bash script (sans edge cases)
//! * Usable for file synchonization
//! * Can be produced and checked without loading full index into memory
//!
#![warn(missing_docs)]

#[macro_use] extern crate quick_error;

pub mod v1;
mod error;
mod config;

pub use error::Error;
pub use config::ScannerConfig;
