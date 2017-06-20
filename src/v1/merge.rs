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
use std::io::{self, BufRead, BufReader};
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
        MergedEntriesIterator::new(self)
    }
}

/// Iterator over the entries from several signature files
pub struct MergedEntriesIterator<'a, K: 'a, R: 'a + BufRead> {
    iterators: Vec<(&'a K, PeekableEntryIterator<'a, R>)>,
    iterator_ixs: Vec<usize>,
}

impl<'a, K, R: BufRead> MergedEntriesIterator<'a, K, R> {
    fn new(merged_signatures: &'a mut MergedSignatures<K, R>)
        -> MergedEntriesIterator<'a, K, R>
    {
        let n = merged_signatures.parsers.len();
        MergedEntriesIterator {
            iterators: merged_signatures.parsers.iter_mut()
                .map(|&mut (ref key, ref mut parser)| {
                    (key, PeekableEntryIterator::new(parser.iter()))
                })
                .collect::<Vec<_>>(),
            iterator_ixs: Vec::with_capacity(n)
        }
    }

    /// Advances all parsers and returns all matching entries
    pub fn advance<P: AsRef<Path>>(&mut self, to: &EntryKind<P>)
        -> Vec<(&'a K, Result<Entry, ParseError>)>
    {
        let mut entries = vec!();
        for &mut (key, ref mut iterator) in self.iterators.iter_mut() {
            if let Some(entry) = iterator.advance(to) {
                entries.push((key, entry));
            }
        }
        entries
    }
}

struct PeekableEntryIterator<'a, R: 'a + BufRead> {
    head: Option<Result<Entry, ParseError>>,
    tail: EntryIterator<'a, R>,
}

impl<'a, R: 'a + BufRead> PeekableEntryIterator<'a, R> {
    fn new(iter: EntryIterator<'a, R>) -> PeekableEntryIterator<'a, R> {
        PeekableEntryIterator {
            head: None,
            tail: iter,
        }
    }

    fn peek(&mut self) -> Option<&Result<Entry, ParseError>> {
        if self.head.is_none() {
            self.head = self.tail.next();
        }
        self.head.as_ref()
    }

    fn advance<P: AsRef<Path>>(&mut self, kind: &EntryKind<P>)
        -> Option<Result<Entry, ParseError>>
    {
        use std::cmp::Ordering::*;

        let cmp_res = match self.peek() {
            Some(&Ok(ref entry)) => entry.kind().cmp(&kind.as_ref()),
            Some(&Err(_)) => Equal,
            None => return None,
        };
        match cmp_res {
            Less => {
                self.head = None;
                self.tail.advance(kind)
            },
            Greater => None,
            Equal => self.head.take(),
        }
    }
}

impl<'a, R: BufRead> Iterator for PeekableEntryIterator<'a, R> {
    type Item = Result<Entry, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.peek() {
            Some(_) => self.head.take(),
            None => None,
        }
    }
}

impl<'a, K, R: BufRead> Iterator for MergedEntriesIterator<'a, K, R> {
    type Item = Vec<(&'a K, Result<Entry, ParseError>)>;

    fn next(&mut self) -> Option<Self::Item> {
        use std::cmp::Ordering::*;

        let mut res = Vec::with_capacity(self.iterators.len());
        self.iterator_ixs.clear();
        {
            let mut min_kind = None;
            for (ix, &mut (_, ref mut iterator)) in
                self.iterators.iter_mut().enumerate()
            {
                match iterator.peek() {
                    Some(&Ok(ref entry)) => {
                        let kind = entry.kind();
                        let cmp_res = if let Some(ref min_kind) = min_kind {
                            Some(kind.cmp(min_kind))
                        } else {
                            None
                        };
                        match cmp_res {
                            Some(Less) => {
                                min_kind = Some(kind);
                                self.iterator_ixs.clear();
                                self.iterator_ixs.push(ix);
                            },
                            Some(Equal) => {
                                self.iterator_ixs.push(ix);
                            },
                            Some(Greater) => {},
                            None => {
                                min_kind = Some(kind);
                                self.iterator_ixs.push(ix);
                            }
                        }
                    },
                    Some(&Err(_)) => {
                        self.iterator_ixs.push(ix);
                    },
                    None => {},
                }
            }
        }

        for &ix in &self.iterator_ixs {
            let ref mut elem = self.iterators[ix];
            let key = elem.0;
            let ref mut iterator = elem.1;
            if let Some(entry) = iterator.next() {
                res.push((key, entry));
            }
        }

        if res.is_empty() {
            None
        } else {
            Some(res)
        }
    }
}

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
