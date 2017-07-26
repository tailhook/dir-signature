//! A module for working with version 1 of directory signature
//!
//!
//! Entry points:
//!
//! * [`scan`](fn.scan.html) function for creating index file
//! * [`Parser::new`](struct.Parser.html#method.new) for reading index file
//!
//! There is also global [`get_hash`](../fn.get_hash.html) for getting just
//! checksum of an index file.

mod writer;
mod progress;
mod hash;
mod scan;
mod parser;
pub mod merge;

use std::io;

pub use error::Error;
pub use self::parser::{Hashes, HashesIter};
pub use self::parser::{Header, Entry, EntryKind, Parser, EntryIterator};
pub use self::parser::{ParseError};

use self::progress::Progress;
use self::writer::SyncWriter;
use {ScannerConfig, HashTypeEnum};

/// Create an index using specified config
///
/// It's better to use some buffered output file here.
pub fn scan<F: io::Write>(config: &ScannerConfig, out: &mut F)
    -> Result<(), Error>
{
    if config.print_progress {
        match config.hash.0 {
            HashTypeEnum::Sha512_256 => {
                scan::scan(config,
                    &mut Progress::new(io::stderr(),
                        SyncWriter::new(out,
                            hash::Sha512_256, config.block_size)?))
            }
            HashTypeEnum::Blake2b_256 => {
                scan::scan(config,
                    &mut Progress::new(io::stderr(),
                        SyncWriter::new(out,
                            hash::Blake2b_256, config.block_size)?))
            }
        }
    } else {
        match config.hash.0 {
            HashTypeEnum::Sha512_256 => {
                scan::scan(config,
                    &mut SyncWriter::new(out,
                        hash::Sha512_256, config.block_size)?)
            }
            HashTypeEnum::Blake2b_256 => {
                scan::scan(config,
                    &mut SyncWriter::new(out,
                        hash::Blake2b_256, config.block_size)?)
            }
        }
    }
}
