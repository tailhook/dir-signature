//! A module for parsing multiple directory signature files
//!
//!
//! Entry points:
//!
//! * [`FileMergeBuilder::new`](struct.FileMergeBuilder.html#method.new)
//!   for opening files and building `MergedSignatures`
//! * [`MergedSignatures::new`](struct.MergedSignatures.html#method.new)
//!   for iterating over entries from multiple signature files

use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use ::HashType;
use super::{Entry, EntryKind, Parser, ParseError};
use super::parser::EntryIterator;

quick_error! {
    /// The error type that can happen when merging signature files
    #[derive(Debug)]
    pub enum MergeError {
        /// Io error
        Io(msg: String, err: io::Error) {
            description("Io error")
            display("Io error - {}: {}", msg, err)
        }
        /// Parsing signature file error
        Parse(err: ParseError) {
            description("Parse error")
            display("Parse error: {}", err)
            from()
        }
        /// Signature files have different hash types
        HashTypesMismatch(hash_types: Vec<HashType>) {
            description("Hash types mismatch")
            display("Hash types mismatch: {:?}", hash_types)
        }
        /// Signature files have different block sizes
        BlockSizesMismatch(block_sizes: Vec<u64>) {
            description("Block sizes mismatch")
            display("Block sizes mismatch: {:?}", block_sizes)
        }
    }
}

/// Builder for `MergedSignatures`
pub struct FileMergeBuilder {
    paths: Vec<(PathBuf, PathBuf)>,
}

impl FileMergeBuilder {
    /// Creates new instalce of `FileMergeBuilder`
    pub fn new() -> FileMergeBuilder {
        FileMergeBuilder {
            paths: vec!(),
        }
    }

    /// Adds new signature file
    pub fn add<P, S>(&mut self, base_path: P, signature_path: S)
        -> &Self
        where P: AsRef<Path>, S: AsRef<Path>
    {
        self.paths.push((
            base_path.as_ref().to_path_buf(),
            signature_path.as_ref().to_path_buf()));
        self
    }

    /// Builds `MergedSignatures`
    pub fn finalize(self)
        -> Result<MergedSignatures<PathBuf, BufReader<File>>, MergeError>
    {
        let mut parsers = vec!();
        for (base_path, sig_path) in self.paths {
            let reader = BufReader::new(File::open(&sig_path)
                .map_err(|e| MergeError::Io(
                    format!("cannot open signature file {:?}", &sig_path),
                    e))?);
            let parser = Parser::new(reader)?;
            parsers.push((base_path, parser));
        }
        MergedSignatures::new(parsers)
    }
}

/// Helper struct to simplify simultaneous iteration over several
/// directory signature files
pub struct MergedSignatures<K, R: BufRead> {
    parsers: Vec<(K, Parser<R>)>,
}

impl<K, R: BufRead> MergedSignatures<K, R> {
    /// Creates merged signatures struct over `parsers`
    ///
    /// All hash types and block size should be the same
    pub fn new<I>(parsers: I)
        -> Result<MergedSignatures<K, R>, MergeError>
        where I: IntoIterator<Item=(K, Parser<R>)>
    {
        let parsers = parsers.into_iter().collect::<Vec<_>>();
        let hash_types = parsers.iter()
            .map(|p| p.1.get_header().get_hash_type())
            .collect::<Vec<_>>();
        if !check_same(&hash_types) {
            return Err(MergeError::HashTypesMismatch(hash_types));
        }
        let block_sizes = parsers.iter()
            .map(|p| p.1.get_header().get_block_size())
            .collect::<Vec<_>>();
        if !check_same(&block_sizes) {
            return Err(MergeError::BlockSizesMismatch(block_sizes));
        }
        Ok(MergedSignatures {
            parsers: parsers,
        })
    }

    /// Creates iterator
    pub fn iter<'a>(&'a mut self) -> MergedEntriesIterator<'a, K, R> {
        MergedEntriesIterator {
            merged_entries: self.parsers.iter_mut()
                .map(|&mut (ref key, ref mut parser)| {
                    (key, parser.iter())
                })
                .collect::<Vec<_>>(),
        }
    }
}

/// Iterator over the entries from several signature files
pub struct MergedEntriesIterator<'a, K: 'a, R: 'a + BufRead> {
    merged_entries: Vec<(&'a K, EntryIterator<'a, R>)>,
}

impl<'a, K, R: BufRead> MergedEntriesIterator<'a, K, R> {
    /// Advances all parsers and returns all matching entries
    pub fn advance<P: AsRef<Path>>(&mut self, to: &EntryKind<P>)
        -> Vec<(&'a K, Result<Entry, ParseError>)>
    {
        let mut entries = vec!();
        for &mut (key, ref mut iterator) in self.merged_entries.iter_mut() {
            if let Some(entry) = iterator.advance(to) {
                 entries.push((key, entry));
            }
        }
        entries
    }
}

// TODO
// impl<'a, K, R: BufRead> Iterator for MergedEntriesIterator<'a, K, R> {
//     type Item = Vec<(&'a K, Result<Entry, ParseError>)>;

//     fn next(&mut self) -> Option<Self::Item> {
//         None
//     }
// }

fn check_same<I, V>(values: I) -> bool
    where I: IntoIterator<Item=V>, V: PartialEq
{
    let mut iter = values.into_iter();
    let first = match iter.next() {
        None => return true,
        Some(v) => v,
    };
    iter.all(|v| v == first)
}
