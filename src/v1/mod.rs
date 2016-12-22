//! A module for working with version 1 of directory signature
//!

mod writer;
mod hash;
mod scan;

use std::io;

pub use error::Error;

use self::writer::SyncWriter;
use {ScannerConfig, HashType};

/// Create an index using specified config
///
/// It's better to use some buffered output file here.
pub fn scan<F: io::Write>(config: &ScannerConfig, out: &mut F)
    -> Result<(), Error>
{
    match config.hash {
        HashType::Sha512_256 => {
            scan::scan(config,
                &mut SyncWriter::new(out,
                    hash::Sha512_256, config.block_size)?)
        }
        HashType::Blake2b_256 => {
            scan::scan(config,
                &mut SyncWriter::new(out,
                    hash::Blake2b_256, config.block_size)?)
        }
    }
}
