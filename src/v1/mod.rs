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
mod emitter;
pub mod merge;
#[cfg(feature="threads")] mod threaded_writer;

use std::io;

pub use error::Error;
pub use self::parser::{Hashes, HashesIter};
pub use self::parser::{Header, Entry, EntryKind, Parser, EntryIterator};
pub use self::parser::{ParseError};
pub use v1::emitter::Emitter;

use self::progress::Progress;
use self::writer::{Writer, SyncWriter};
use v1::hash::Hash;
use {ScannerConfig, HashTypeEnum};

/// Create an index using specified config
///
/// It's better to use some buffered output file here.
pub fn scan<F: io::Write>(config: &ScannerConfig, out: &mut F)
    -> Result<(), Error>
{
    add_hash(config, out)
}

fn add_progress<W: Writer>(config: &ScannerConfig, out: W)
    -> Result<(), Error>
    where W::TotalHash: ::std::fmt::LowerHex,
{
    if config.print_progress {
        scan::scan(config, Progress::new(io::stderr(), out))
    } else {
        scan::scan(config, out)
    }
}

#[cfg(not(feature="threads"))]
fn add_threads<O, H: Hash>(config: &ScannerConfig, hash: H, out: &mut O)
    -> Result<(), Error>
    where O: io::Write,
{
    add_progress(config, SyncWriter::new(out, hash, config.block_size)?)
}

#[cfg(feature="threads")]
fn add_threads<O, H: Hash>(config: &ScannerConfig, hash: H, out: &mut O)
    -> Result<(), Error>
    where O: io::Write,
{
    if config.threads > 1 {
        add_progress(config, threaded_writer::ThreadedWriter::new(
            config.threads,
            out, hash, config.block_size)?)
    } else {
        add_progress(config, SyncWriter::new(out, hash, config.block_size)?)
    }
}

fn add_hash<O>(config: &ScannerConfig, out: &mut O)
    -> Result<(), Error>
    where O: io::Write,
{
    match config.hash.0 {
        HashTypeEnum::Sha512_256 => {
            add_threads(config, hash::Sha512_256::new(), out)
        }
        HashTypeEnum::Blake2b_256 => {
            add_threads(config, hash::Blake2b_256::new(), out)
        }
    }
}
