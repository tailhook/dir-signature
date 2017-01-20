//! A module for working with version 1 of directory signature
//!

mod writer;
mod progress;
mod hash;
mod scan;
mod parser;

use std::io;

pub use error::Error;
pub use self::parser::{Header, Entry, Parser, ParseError};

use self::progress::Progress;
use self::writer::SyncWriter;
use {ScannerConfig, HashType};

/// Create an index using specified config
///
/// It's better to use some buffered output file here.
pub fn scan<F: io::Write>(config: &ScannerConfig, out: &mut F)
    -> Result<(), Error>
{
    if config.print_progress {
        match config.hash {
            HashType::Sha512_256 => {
                scan::scan(config,
                    &mut Progress::new(io::stderr(),
                        SyncWriter::new(out,
                            hash::Sha512_256, config.block_size)?))
            }
            HashType::Blake2b_256 => {
                scan::scan(config,
                    &mut Progress::new(io::stderr(),
                        SyncWriter::new(out,
                            hash::Blake2b_256, config.block_size)?))
            }
        }
    } else {
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
}
