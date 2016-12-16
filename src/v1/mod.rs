//! A module for working with version 1 of directory signature

use std::io;

use {ScannerConfig, Error};

/// Create an index using specified config
///
/// It's better to use some buffered output file here.
pub fn scan<F: io::Write>(input: &ScannerConfig, out: &mut F)
    -> Result<(), Error>
{
    unimplemented!();
}
