use std;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::convert::From;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::slice::Chunks;
use std::str::FromStr;

use quick_error::ResultExt;

use ::HashType;
use super::writer::{MAGIC, VERSION};
use super::hash::{self, HashOutput};

quick_error! {
    /// The error type that represents errors which can happen when parsing
    /// specific row
    #[derive(Debug)]
    pub enum ParseRowError {
        /// Reading line error
        Read(err: io::Error) {
            description("Error reading line")
            display("Error reading line: {}", err)
            from()
        }
        /// Missing header error
        MissingHeader {
            description("Missing header")
        }
        /// Invalid header error
        InvalidHeader(msg: String) {
            description("Invalid header")
            display("Invalid header: {}", msg)
        }
        /// Invalid file signature
        InvalidSignature(magic: String) {
            description("Invalid signature")
            display("Invalid signature: expected {:?} but was {:?}",
                MAGIC, magic)
        }
        /// Missing file version
        MissingVersion {
            description("Missing version")
        }
        /// Invalid file version
        InvalidVersion(version: String) {
            description("Invalid version")
            display("Invalid version: expected {:?} but was {:?}",
                VERSION, version)
        }
        /// Missing hash type
        MissingHashType {
            description("Missing hash type")
        }
        /// Invalid hash type
        UnsupportedHashType(hash_type: String) {
            description("Unsupported hash type")
            display("Unsupported hash type: {}", hash_type)
        }
        /// Missing block size
        MissingBlockSize {
            description("Missing block size")
        }
        /// Invalid block size
        InvalidBlockSize(block_size: String) {
            description("Invalid block size")
            display("Invalid block size: {}", block_size)
        }
        /// Invalid hash
        InvalidHash(msg: String) {
            display("Invalid hash: {}", msg)
        }
        /// Invalid file type
        InvalidFileType(file_type: String) {
            description("Invalid file type")
            display("Invalid file type: {}", file_type)
        }
        /// General parsing error
        InvalidLine(msg: String) {
            description("Invalid line")
            display("Invalid line: {}", msg)
        }
        /// Invalid hexadecimal character
        InvalidHex(msg: String) {
            description("Invalid hexadecimal")
            display("Invalid hexadecimal: {}", msg)
        }
        /// Utf-8 convertion error
        InvalidUtf8(err: std::str::Utf8Error) {
            description("Invalid utf-8")
            display("Invalid utf-8: {}", err)
            from()
        }
        /// Integer parsing error
        InvalidInt(err: std::num::ParseIntError) {
            description("Invalid integer")
            display("Invalid integer: {}", err)
            from()
        }
    }
}

quick_error! {
    /// The error type that can happen when parsing directory signature file
    #[derive(Debug)]
    pub enum ParseError wraps ErrorEnum {
        /// An I/O operation error
        Io(err: io::Error) {
            cause(err)
            description("error reading buffer")
            display("Error reading buffer: {}", err)
            from()
        }
        /// Parsing error
        Parse(err: ParseRowError, row_num: usize) {
            description("parse error")
            display("Parse error at line {}: {}", row_num, err)
            context(row_num: usize, err: ParseRowError)
                -> (err, row_num)
        }
    }
}

/// Represents a type of the entry inside a signature file.
///
/// Entry kinds are ordered in a way they appear in a signature file.
/// Thus `File("/b") < Dir("/a")`.
///
/// Comparing invalid entry kinds can will panic. For example all following
/// entries `Dir("")`, `Dir("a")`, `File("")`, `File("a")` and `File("/")` are
/// invalid.
#[derive(Debug, PartialEq, Eq)]
pub enum EntryKind<P: AsRef<Path>> {
    /// A directory
    Dir(P),
    /// A file or a symbolic link
    File(P),
}

impl<P: AsRef<Path>> EntryKind<P> {
    /// Get path of the entry
    pub fn path(&self) -> &Path {
        use self::EntryKind::*;
        match *self {
            Dir(ref p) | File(ref p) => p.as_ref(),
        }
    }

    /// Converts to `EntryKind<&Path>`
    pub fn as_ref(&self) -> EntryKind<&Path> {
        use self::EntryKind::*;
        match *self {
            Dir(ref p) => Dir(p.as_ref()),
            File(ref p) => File(p.as_ref()),
        }
    }

    /// Clones path and returns `EntryKind<PathBuf>`
    pub fn cloned(&self) -> EntryKind<PathBuf> {
        use self::EntryKind::*;
        match *self {
            Dir(ref p) => Dir(p.as_ref().to_path_buf()),
            File(ref p) => File(p.as_ref().to_path_buf()),
        }
    }
}

impl<P> PartialOrd for EntryKind<P>
    where P: AsRef<Path> + PartialEq + Eq
{
    fn partial_cmp(&self, other: &EntryKind<P>)
        -> Option<Ordering>
    {
        Some(self.cmp(other))
    }
}

impl<P> Ord for EntryKind<P>
    where P: AsRef<Path> + PartialEq + Eq
{
    fn cmp(&self, other: &EntryKind<P>) -> Ordering {
        use std::cmp::Ordering::*;
        use self::EntryKind::*;

        // we cannot just compare paths since directories and files are placed
        // differently in a signature file
        match *self {
            Dir(ref path) => {
                let path = path.as_ref();
                assert!(path.is_absolute(), "Relative path");
                match *other {
                    Dir(ref other_path) => {
                        let other_path = other_path.as_ref();
                        assert!(other_path.is_absolute(), "Relative path");
                        path.cmp(other_path)
                    },
                    File(ref other_path) => {
                        let other_path = other_path.as_ref();
                        assert!(other_path.is_absolute(), "Relative path");
                        let other_parent = other_path.parent()
                            .expect("Path is not a file");
                        match path.cmp(other_parent.as_ref()) {
                            Less | Equal => Less,
                            Greater => Greater,
                        }
                    }
                }
            },
            File(ref path) => {
                let path = path.as_ref();
                assert!(path.is_absolute(), "Relative path");
                let parent = path.parent()
                    .expect("Path is not a file");
                match *other {
                    Dir(ref other_path) => {
                        let other_path = other_path.as_ref();
                        assert!(other_path.is_absolute(), "Relative path");
                        match parent.cmp(other_path) {
                            Less => Less,
                            Greater | Equal => Greater,
                        }
                    },
                    File(ref other_path) => {
                        let other_parent = other_path.as_ref().parent()
                            .expect("Path is not a file");
                        match parent.cmp(other_parent) {
                            Less => Less,
                            Greater => Greater,
                            Equal => {
                                path.file_name()
                                    .expect("Empty file name")
                                    .cmp(&other_path.as_ref().file_name()
                                         .expect("Empty file name"))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Represents header of the dir signature file
#[derive(Debug, Clone)]
pub struct Header {
    version: String,
    hash_type: HashType,
    block_size: u64,
}

impl Header {
    fn parse(row: &[u8]) -> Result<Header, ParseRowError> {
        let line = std::str::from_utf8(row).map_err(|e|
            ParseRowError::InvalidHeader(format!("{}", e)))?;
        let mut parts = line.split_whitespace();
        let version = if let Some(signature) = parts.next() {
            let mut sig_parts = signature.splitn(2, '.');
            if let Some(magic) = sig_parts.next() {
                if magic != MAGIC {
                    return Err(ParseRowError::InvalidSignature(
                        magic.to_string()));
                }
            }
            if let Some(version) = sig_parts.next() {
                if version != VERSION {
                    return Err(ParseRowError::InvalidVersion(
                        version.to_string()));
                }
                version
            } else {
                return Err(ParseRowError::MissingVersion);
            }
        } else {
            return Err(ParseRowError::MissingHeader);
        };
        let hash_type = if let Some(hash_type_str) = parts.next() {
            HashType::from_str(hash_type_str)
                .map_err(|_| ParseRowError::UnsupportedHashType(
                    hash_type_str.to_string()))?
        } else {
            return Err(ParseRowError::MissingHashType);
        };
        let block_size = if let Some(block_size_attr) = parts.next() {
            let mut block_size_kv = block_size_attr.splitn(2, '=');
            match block_size_kv.next() {
                None => {
                    return Err(ParseRowError::MissingBlockSize);
                },
                Some(k) if k != "block_size" => {
                    return Err(ParseRowError::MissingBlockSize);
                },
                Some(_) => {
                    match block_size_kv.next() {
                        Some(v) => u64::from_str_radix(v, 10)
                            .map_err(|_| ParseRowError::InvalidBlockSize(
                                v.to_string()))?,
                        None => return Err(ParseRowError::MissingBlockSize),
                    }
                },
            }
        } else {
            return Err(ParseRowError::MissingBlockSize);
        };
        Ok(Header {
            version: version.to_string(),
            hash_type: hash_type,
            block_size: block_size,
        })
    }

    /// Returns version of the signature file
    pub fn get_version(&self) -> &str {
        &self.version
    }

    /// Returns hashing algorithm
    pub fn get_hash_type(&self) -> HashType {
        self.hash_type
    }

    /// Returns block size
    pub fn get_block_size(&self) -> u64 {
        self.block_size
    }
}

#[derive(Debug)]
pub struct Footer(Vec<u8>);

impl Footer {
    fn parse(row: &[u8], hash_type: HashType)
        -> Result<Footer, ParseRowError>
    {
        let (data, tail) = parse_hashes(row, hash_type, 1)?;
        if !tail.is_empty() {
            return Err(ParseRowError::InvalidLine(
                format!("Footer is not fully consumed: {:?}",
                    String::from_utf8_lossy(tail))));
        }
        Ok(Footer(data))
    }
}

/// List of hashes for an entry
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Hashes {
    data: Vec<u8>,
    hash_type: HashType,
    block_size: u64,
}

/// Entry hashes iterator
#[derive(Debug)]
pub struct HashesIter<'a>(Chunks<'a, u8>);

impl Hashes {
    fn new(data: Vec<u8>, hash_type: HashType, block_size: u64) -> Hashes {
        Hashes {
            data: data,
            hash_type: hash_type,
            block_size: block_size,
        }
    }

    /// Number of hashes
    pub fn len(&self) -> usize {
        self.data.len() / self.hash_type.output_bytes()
    }

    /// Get hash by index
    pub fn get(&self, idx: usize) -> Option<&[u8]> {
        let bytes = self.hash_type.output_bytes();
        let off = bytes.checked_mul(idx)?;
        let end = off.checked_add(bytes)?;
        if end <= self.data.len() {
            return Some(&self.data[off..end]);
        } else {
            return None;
        }
    }

    /// Original block size of file (size that is represented by a single hash)
    pub fn block_size(&self) -> u64 {
        return self.block_size
    }

    /// Returns iterator over hashes
    pub fn iter<'a>(&'a self) -> HashesIter<'a> {
        HashesIter(self.data.chunks(self.hash_type.output_bytes()))
    }

    /// Checks whether file has the same hash
    pub fn check_file<R: io::Read>(&self, f: R) -> io::Result<bool> {
        use HashTypeEnum::*;
        match self.hash_type.0 {
            Sha512_256 => self._check_file(f, hash::Sha512_256),
            Blake2b_256 => self._check_file(f, hash::Blake2b_256),
        }
    }

    fn _check_file<R: io::Read, H: hash::Hash>(&self, mut f: R, h: H)
        -> io::Result<bool>
    {
        for orig_hash in self.iter() {
            let hash = h.hash_file(&mut f, self.block_size)?;
            if orig_hash != hash.result() {
                return Ok(false);
            }
        }
        let mut test_buf = [0; 1];
        if f.read(&mut test_buf)? != 0 {
            return Ok(false);
        }
        Ok(true)
    }
}

impl<'a> Iterator for HashesIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        self.0.next()
    }
}

/// Represents an entry from dir signature file
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Entry {
    /// Direcory
    Dir(PathBuf),
    /// File
    File {
        /// File path (joined with current directory)
        path: PathBuf,
        /// Is executable
        exe: bool,
        /// File size
        size: u64,
        /// Blocks hashes
        hashes: Hashes
    },
    /// Link
    Link(PathBuf, PathBuf),
}

impl Entry {
    fn parse(row: &[u8], current_dir: &Path, hash_type: HashType, block_size: u64)
        -> Result<Option<Entry>, ParseRowError>
    {
        let (entry, tail) = if row.starts_with(b"/") {
            let (path, row) = parse_path_buf(row)?;
            (Entry::Dir(path), row)
        } else if row.starts_with(b"  ") {
            let row = &row[2..];
            let (path, row) = parse_path(row)?;
            let path = current_dir.join(&path);
            let (file_type, row) = parse_os_str(row)?;
            if file_type == "f" || file_type == "x" {
                let (file_size, row) = parse_u64(row)?;
                let hashes_num = ((file_size + block_size - 1) / block_size) as usize;
                let (hashes_data, row) = parse_hashes(row, hash_type, hashes_num)?;
                let hashes = Hashes::new(hashes_data, hash_type, block_size);
                (Entry::File {
                    path: path,
                    exe: file_type == "x",
                    size: file_size,
                    hashes: hashes },
                 row)
            } else if file_type == "s" {
                let (dest, row) = parse_path_buf(row)?;
                (Entry::Link(path, dest), row)
            } else {
                return Err(ParseRowError::InvalidFileType(
                    format!("{}", String::from_utf8_lossy(file_type.as_bytes()))));
            }
        } else {
            return Ok(None);
        };
        if !tail.is_empty() {
            return Err(ParseRowError::InvalidLine(
                format!("Entry is not fully consumed: {:?}",
                    String::from_utf8_lossy(tail))));
        }
        Ok(Some(entry))
    }

    /// Get path of the entry
    pub fn path(&self) -> &Path {
        match *self {
            Entry::Dir(ref path) |
            Entry::File{ref path, ..} |
            Entry::Link(ref path, _) => path
        }
    }

    /// Returns kind of the entry. Can be passed into
    /// [`EntryIterator::advance`](struct.EntryIterator.html#method.advance)
    /// method
    pub fn kind(&self) -> EntryKind<&Path> {
        match *self {
            Entry::Dir(ref path) => EntryKind::Dir(path.as_ref()),
            Entry::File{ref path, ..} |
            Entry::Link(ref path, _) => EntryKind::File(path.as_ref()),
        }
    }
}

/// v1 format parser
pub struct Parser<R: BufRead> {
    header: Header,
    reader: R,
}

impl<R: BufRead> Parser<R> {
    /// Creates a directory signature parser (format v1)
    /// Tries to parse header
    pub fn new(mut reader: R) -> Result<Parser<R>, ParseError> {
        let mut header_line = vec!();
        read_line(&mut reader, &mut header_line)
            .map_err(|e| ErrorEnum::Parse(e, 1))?;
        let header = Header::parse(&header_line)
            .map_err(|e| ErrorEnum::Parse(e, 1))?;
        Ok(Parser {
            header: header,
            reader: reader,
        })
    }

    /// Returns parsed `Header`
    pub fn get_header(&self) -> Header {
        self.header.clone()
    }

    /// Creates iterator over directory signature entries
    pub fn iter(&mut self) -> EntryIterator<R> {
        EntryIterator::new(&mut self.reader,
            self.header.hash_type, self.header.block_size)
    }

    /// Consumes the parser returning ownership of the underlying reader
    ///
    /// It can be used to parse signature file again from the beginning:
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::io::{Seek, SeekFrom};
    /// use dir_signature::v1::Parser;
    /// # use std::io::{BufReader, Cursor};
    /// # let content = "DIRSIGNATURE.v1 sha512/256 block_size=32768\n";
    /// # let mut reader = BufReader::new(Cursor::new(&content[..]));
    /// # let mut parser = Parser::new(reader).unwrap();
    ///
    /// let mut reader = parser.into_reader();
    /// reader.seek(SeekFrom::Start(0)).unwrap();
    /// let mut parser = Parser::new(reader).unwrap();
    /// ```
    pub fn into_reader(self) -> R {
        self.reader
    }
}

/// Iterator over the entries of the signature file
pub struct EntryIterator<'a, R: 'a + BufRead> {
    reader: &'a mut R,
    hash_type: HashType,
    block_size: u64,
    current_row: Vec<u8>,
    current_row_num: usize,
    current_dir: PathBuf,
    exhausted: bool,
}

impl<'a, R: BufRead> EntryIterator<'a, R> {
    fn new(reader: &'a mut R, hash_type: HashType, block_size: u64)
        -> EntryIterator<R>
    {
        EntryIterator {
            reader: reader.by_ref(),
            hash_type: hash_type,
            block_size: block_size,
            current_row: vec!(),
            current_row_num: 1,
            current_dir: PathBuf::new(),
            exhausted: false,
        }
    }

    fn parse_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        self._parse_entry().map_err(|e| e.into())
    }
    fn _parse_entry(&mut self) -> Result<Option<Entry>, ErrorEnum> {
        if self.exhausted {
            return Ok(None);
        }
        self.current_row_num += 1;
        if self.current_row.is_empty() {
            read_line(self.reader.by_ref(), &mut self.current_row)
                .context(self.current_row_num)?;
        }
        let row = &self.current_row[..];
        let entry = Entry::parse(
                row, &self.current_dir, self.hash_type, self.block_size)
            .context(self.current_row_num)?;
        match entry {
            None => {
                let _footer = Footer::parse(row, self.hash_type)
                    .context(self.current_row_num)?;
                let mut test_buf = [0; 1];
                if self.reader.read(&mut test_buf)? != 0 {
                    return Err(ErrorEnum::Parse(
                        ParseRowError::InvalidLine(
                            format!("Found extra lines after the footer")),
                        self.current_row_num));
                }
                self.exhausted = true;
                Ok(None)
            },
            Some(entry) => {
                if let Entry::Dir(ref dir_path) = entry {
                    self.current_dir = dir_path.clone();
                }
                Ok(Some(entry))
            },
        }
    }

    /// Advances to the entry beyond the current whose path is equal to
    /// wanted path. If there is no such entry in the signature file,
    /// stops at the first entry that greater than advance path and
    /// returns `None`.
    /// Returns `None` if wanted path locates before the current entry.
    pub fn advance<P: AsRef<Path>>(&mut self, kind: &EntryKind<P>)
        -> Option<Result<Entry, ParseError>>
    {
        use std::cmp::Ordering::*;

        loop {
            match self.parse_entry() {
                Ok(Some(entry)) => {
                    match entry.kind().cmp(&kind.as_ref()) {
                        Less => {
                            self.current_row.clear();
                            continue;
                        },
                        Greater => {
                            return None;
                        },
                        Equal => {
                            self.current_row.clear();
                            return Some(Ok(entry));
                        },
                    }
                },
                Ok(None) => return None,
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

impl<'a, R: BufRead> Iterator for EntryIterator<'a, R> {
    type Item = Result<Entry, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let res = match self.parse_entry() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        };
        self.current_row.clear();
        res
    }
}

fn read_line<R: BufRead>(reader: &mut R, mut buf: &mut Vec<u8>)
    -> Result<(), ParseRowError>
{
    let _ = reader.read_until(b'\n', &mut buf)?;
    if !buf.ends_with(b"\n") {
        return Err(ParseRowError::InvalidLine(
            format!("Every line must end with a newline")));
    }
    buf.pop();
    Ok(())
}

fn parse_path<'a>(data: &'a [u8])
    -> Result<(Cow<Path>, &'a [u8]), ParseRowError>
{
    let (path, tail) = parse_os_str(data)?;
    let unescaped_path = match unescape_hex(path) {
        Cow::Borrowed(p) => Cow::Borrowed(Path::new(p)),
        Cow::Owned(p) => Cow::Owned(PathBuf::from(&p)),
    };
    Ok((unescaped_path, tail))
 }

fn parse_path_buf<'a>(data: &'a [u8])
    -> Result<(PathBuf, &'a [u8]), ParseRowError>
{
    let (path, tail) = parse_os_str(data)?;
    let unescaped_path = unescape_hex(path);
    Ok((PathBuf::from(&unescaped_path), tail))
}

fn parse_os_str<'a>(data: &'a [u8])
    -> Result<(&OsStr, &'a [u8]), ParseRowError>
{
    let (field, tail) = parse_field(data)?;
    Ok((OsStr::from_bytes(field), tail))
}

fn parse_u64<'a>(data: &'a [u8])
    -> Result<(u64, &'a [u8]), ParseRowError>
{
    let (field, tail) = parse_field(data)?;
    let s = std::str::from_utf8(field)?;
    let v = u64::from_str_radix(s, 10)?;
    Ok((v, tail))
}

fn parse_field<'a>(data: &'a [u8])
    -> Result<(&'a [u8], &'a [u8]), ParseRowError>
{

    if data.starts_with(b" ") {
        return Err(ParseRowError::InvalidLine(
            format!("Row has multiple spaces")));
    }
    let mut parts = data.splitn(2, |c| *c == b' ');
    let field = parts.next().unwrap();
    let tail = parts.next().unwrap_or(&data[0..0]);
    Ok((field, tail))
}

fn parse_hashes<'a>(data: &'a [u8], hash_type: HashType, hashes_num: usize)
    -> Result<(Vec<u8>, &'a [u8]), ParseRowError>
{
    let mut data = data;

    let digest_len = hash_type.output_bytes();
    let hash_len = digest_len * 2;

    let mut i = 0;
    let mut buf = Vec::with_capacity(hashes_num * digest_len);
    loop {
        if i == hashes_num {
            break;
        }
        let (hash, tail) = parse_field(data)?;
        if hash.is_empty() {
            break;
        }
        if hash.len() != hash_len {
            return Err(ParseRowError::InvalidHash(
                format!("Expected hash with length of {}: {:?}",
                    hash_len, String::from_utf8_lossy(hash))));
        }
        for d in hash.chunks(2) {
            buf.push(parse_hex(d)?);
        }
        data = tail;
        i += 1;
    }

    if i != hashes_num {
        return Err(ParseRowError::InvalidHash(
            format!("Expected {} hashes but found {}",
                hashes_num, buf.len() / digest_len)));
    }

    Ok((buf, data))
}

fn unescape_hex(s: &OsStr) -> Cow<OsStr> {
    let (mut i, has_escapes) = {
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if is_hex_encoding(&bytes[i..]) {
                break;
            }
            i += 1;
        }
        (i, i < bytes.len())
    };
    if !has_escapes {
        return Cow::Borrowed(s);
    }

    let mut v: Vec<u8> = vec!();
    let bytes = s.as_bytes();
    v.extend_from_slice(&bytes[..i]);
    while i < bytes.len() {
        if is_hex_encoding(&bytes[i..]) {
            let c = parse_hex_unchecked(&bytes[i + 2..]);
            v.push(c);
            i += 4;
        } else {
            v.push(bytes[i]);
            i += 1;
        }
    }
    Cow::Owned(OsString::from_vec(v))
}

fn parse_hex(v: &[u8]) -> Result<u8, ParseRowError> {
    Ok((hex_to_digit(v[0])? << 4) | hex_to_digit(v[1])?)
}

fn hex_to_digit(v: u8) -> Result<u8, ParseRowError> {
    Ok(match v {
        b'0'...b'9' => v & 0x0f,
        b'a'...b'f' | b'A'...b'F' => (v & 0x0f) + 9,
        _ => return Err(
            ParseRowError::InvalidHex(format!("Character ord: {:?}", v))),
    })
}

fn parse_hex_unchecked(v: &[u8]) -> u8 {
    (hex_to_digit_unchecked(v[0]) << 4) | hex_to_digit_unchecked(v[1])
}

fn hex_to_digit_unchecked(v: u8) -> u8 {
    match v {
        b'0'...b'9' => v & 0x0f,
        _ => (v & 0x0f) + 9,
    }
}

fn is_hex_encoding(s: &[u8]) -> bool {
    s.len() >= 4 && s[0] == b'\\' && s[1] == b'x'
        && is_hex(s[2]) & is_hex(s[3])
}

fn is_hex(c: u8) -> bool {
    c >= b'0' && c <= b'9'
        || c >= b'A' && c <= b'F'
        || c >= b'a' && c <= b'f'
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::ffi::OsStr;
    use std::io::Cursor;
    use std::path::Path;

    use rustc_hex::FromHex;

    use ::HashType;
    use super::{Entry, Footer, Hashes, Header, ParseRowError};
    use super::{parse_hashes, parse_hex, is_hex, is_hex_encoding, unescape_hex};

    #[test]
    fn test_entry_kind_ord() {
        use super::EntryKind::*;

        let entries = &[
            Dir("/"),
            File("/1"),
            File("/a"),
            Dir("/1"),
            File("/1/1"),
            File("/1/a"),
            Dir("/1/1"),
            Dir("/1/a"),
            Dir("/a"),
        ];
        for (i1, e1) in entries.iter().enumerate() {
            for (i2, e2) in entries.iter().enumerate() {
                assert_eq!(i1.cmp(&i2), e1.cmp(e2), "e1: {:?}, e2: {:?}", e1, e2);
            }
        }
    }

    #[test]
    fn test_header_parse() {
        let res = Header::parse(b"");
        assert!(matches!(res,
                Err(ParseRowError::MissingHeader)),
            "Result was: {:?}", res);

        let res = Header::parse(b"\xff");
        assert!(matches!(res,
                Err(ParseRowError::InvalidHeader(ref msg))
                if msg.starts_with("invalid utf-8")),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE");
        assert!(matches!(res,
                Err(ParseRowError::MissingVersion)),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v2");
        assert!(matches!(res,
                Err(ParseRowError::InvalidVersion(ref v))
                if v == "v2"),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1");
        assert!(matches!(res,
                Err(ParseRowError::MissingHashType)),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1 sha512/25");
        assert!(matches!(res,
                Err(ParseRowError::UnsupportedHashType(ref h))
                if h == "sha512/25"),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1 sha512/256 size=2");
        assert!(matches!(res,
                Err(ParseRowError::MissingBlockSize)),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1 sha512/256 block_size=dead");
        assert!(matches!(res,
                Err(ParseRowError::InvalidBlockSize(ref b))
                if b == "dead"),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1 sha512/256 block_size=1234");
        let header = res.unwrap();
        assert_eq!(header.get_version(), "v1");
        assert!(header.get_hash_type() == HashType::sha512_256());
        assert_eq!(header.get_block_size(), 1234);
    }

    #[test]
    fn test_entry_parse() {
        let t = HashType::sha512_256();
        let b = 32768;

        let res = Entry::parse(b"", Path::new(""), t, b);
        assert!(matches!(res, Ok(None)));

        let res = Entry::parse(b"/test", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::Dir(ref dir_path)))
                if dir_path == Path::new("/test")),
            "Result was: {:?}", res);

        let res = Entry::parse(b"/test\\x20escaped\\x5cx20", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::Dir(ref dir_path)))
                if dir_path == Path::new("/test escaped\\x20")),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test f 0", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::File { ref path, exe, size, .. }))
                if path == Path::new("/dir/test") && !exe && size == 0),
            "Result was: {:?}", res);

        let res = Entry::parse(
            b"  test x 100 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc",
            Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::File { ref path, exe, size, .. }))
                if path == Path::new("/dir/test") && exe && size == 100),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test s ../dest", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::Link(ref path, ref dest)))
                if path == Path::new("/dir/test") && dest == Path::new("../dest")),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test f x00", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Err(ParseRowError::InvalidInt(..))),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test l ../dest", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Err(ParseRowError::InvalidFileType(ref t))
                if t == "l"),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test s  ../dest", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Err(ParseRowError::InvalidLine(ref msg))
                if msg == "Row has multiple spaces"),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test s ../dest tail", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Err(ParseRowError::InvalidLine(ref msg))
                if msg.starts_with("Entry is not fully consumed: \"tail\"")),
            "Result was: {:?}", res);
    }

    #[test]
    fn test_parse_hashes() {
        let res = parse_hashes(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc \
              c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::sha512_256(), 1);
        assert!(matches!(res,
                Ok((ref hashes, tail))
                if hashes.len() == 32 && tail.len() == 64),
            "Result was: {:?}", res);

        let res = parse_hashes(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc  \
              c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::sha512_256(), 2);
        assert!(matches!(res,
                Err(ParseRowError::InvalidLine(ref msg))
                if msg == "Row has multiple spaces"),
            "Result was: {:?}", res);

        let res = parse_hashes(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc \
              c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::sha512_256(), 3);
        assert!(matches!(res,
                Err(ParseRowError::InvalidHash(ref msg))
                if msg == "Expected 3 hashes but found 2"),
            "Result was: {:?}", res);

        let res = parse_hashes(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc_\
              c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::sha512_256(), 1);
        assert!(matches!(res,
                Err(ParseRowError::InvalidHash(ref msg))
                if msg.starts_with("Expected hash with length of 64:")),
            "Result was: {:?}", res);
    }

    #[test]
    fn hashes_get() {
        let hashes = Hashes::new(
            b"\x3D\x37\xFE\x58\x43\x5E\x0D\x87\x32\x3D\xEE\x4A\x2C\x1B\x33\x9E\
              \xF9\x54\xDE\x63\x71\x6E\xE7\x9F\x57\x47\xF9\x4D\x97\x4F\x91\x3F".to_vec(),
            HashType::sha512_256(),
            4);
        assert!(hashes.get(0).is_some());
        assert!(hashes.get(1).is_none());

        let hashes = Hashes::new(
            b"\x3D\x37\xFE\x58\x43\x5E\x0D\x87\x32\x3D\xEE\x4A\x2C\x1B\x33\x9E\
              \xF9\x54\xDE\x63\x71\x6E\xE7\x9F\x57\x47\xF9\x4D\x97\x4F\x91\x3F\
              \x3D\x37\xFE\x58\x43\x5E\x0D\x87\x32\x3D\xEE\x4A\x2C\x1B\x33\x9E\
              \xF9\x54\xDE\x63\x71\x6E\xE7\x9F\x57\x47\xF9\x4D\x97\x4F\x91\x3F"
              .to_vec(),
            HashType::sha512_256(),
            4);
        assert!(hashes.get(0).is_some());
        assert!(hashes.get(1).is_some());
        assert!(hashes.get(2).is_none());
    }

    #[test]
    fn test_hashes_eq() {
        let b = 32768;
        assert_eq!(
            Hashes::new(b"\x00".to_vec(), HashType::sha512_256(), b),
            Hashes::new(b"\x00".to_vec(), HashType::sha512_256(), b));
        assert_ne!(
            Hashes::new(b"\x00".to_vec(), HashType::sha512_256(), b),
            Hashes::new(b"\xFF".to_vec(), HashType::sha512_256(), b));
        assert_ne!(
            Hashes::new(b"\x00".to_vec(), HashType::sha512_256(), b),
            Hashes::new(b"\x00".to_vec(), HashType::blake2b_256(), b));
    }

    #[test]
    fn test_hashes_check_file() {
        let hashes = Hashes::new(
            b"\x3D\x37\xFE\x58\x43\x5E\x0D\x87\x32\x3D\xEE\x4A\x2C\x1B\x33\x9E\
              \xF9\x54\xDE\x63\x71\x6E\xE7\x9F\x57\x47\xF9\x4D\x97\x4F\x91\x3F".to_vec(),
            HashType::sha512_256(),
            4);
        assert!(hashes.check_file(Cursor::new(b"test")).unwrap());
        assert!(!hashes.check_file(Cursor::new(b"tes1")).unwrap());
        assert!(!hashes.check_file(Cursor::new(b"tes")).unwrap());
        assert!(!hashes.check_file(Cursor::new(b"test123")).unwrap());
    }

    #[test]
    fn test_footer_parse() {
        let res = Footer::parse(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc",
            HashType::sha512_256());
        assert!(matches!(res,
                Ok(Footer(ref data))
                if data == &"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc".from_hex().unwrap()),
            "Result was: {:?}", res);

        let res = Footer::parse(b"", HashType::sha512_256());
        assert!(matches!(res,
                Err(ParseRowError::InvalidHash(ref msg))
                if msg.starts_with("Expected 1 hashes but found 0")),
            "Result was: {:?}", res);

        let res = Footer::parse(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc  test",
            HashType::sha512_256());
        assert!(matches!(res,
                Err(ParseRowError::InvalidLine(ref msg))
                if msg == "Footer is not fully consumed: \" test\""),
            "Result was: {:?}", res);

        let res = Footer::parse(
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            HashType::sha512_256());
        assert!(matches!(res,
                Err(ParseRowError::InvalidHex(ref msg))
                if msg == "Character ord: 120"),
            "Result was: {:?}", res);
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex(b"00").unwrap(), 0);
        assert_eq!(parse_hex(b"01").unwrap(), 1);
        assert_eq!(parse_hex(b"0A").unwrap(), 10);
        assert_eq!(parse_hex(b"0e").unwrap(), 14);
        assert_eq!(parse_hex(b"1f").unwrap(), 31);
        assert_eq!(parse_hex(b"7f").unwrap(), 127);
        assert_eq!(parse_hex(b"fF").unwrap(), 255);
        assert_eq!(parse_hex(b"00test").unwrap(), 0);
        assert!(parse_hex(b"0x").is_err());
    }

    #[test]
    fn test_is_hex() {
        assert!(is_hex(b'0'));
        assert!(is_hex(b'9'));
        assert!(is_hex(b'A'));
        assert!(is_hex(b'F'));
        assert!(is_hex(b'a'));
        assert!(is_hex(b'f'));
        assert!(!is_hex(b'G'));
        assert!(!is_hex(b'x'));
        assert!(!is_hex(b'\\'));
        assert!(!is_hex(b' '));
    }

    #[test]
    fn test_is_hex_encoding() {
        assert!(is_hex_encoding(br"\x00"));
        assert!(is_hex_encoding(br"\x00test"));
        assert!(is_hex_encoding(br"\x9f"));
        assert!(is_hex_encoding(br"\xfF"));
        assert!(!is_hex_encoding(br"\x"));
        assert!(!is_hex_encoding(br"\x0"));
        assert!(!is_hex_encoding(br"x001"));
        assert!(!is_hex_encoding(br"\00"));
        assert!(!is_hex_encoding(br"\xfg"));
        assert!(!is_hex_encoding(br"\xz1"));
    }

    #[test]
    fn test_unescape_hex() {
        let res = unescape_hex(OsStr::new("test"));
        assert_eq!(res, OsStr::new("test"));
        assert!(matches!(res, Cow::Borrowed(_)));
        let res = unescape_hex(OsStr::new("\\x0test"));
        assert_eq!(res, OsStr::new("\\x0test"));
        assert!(matches!(res, Cow::Borrowed(_)));
        let res = unescape_hex(OsStr::new("\\x00"));
        assert_eq!(res, OsStr::new("\x00"));
        assert!(matches!(res, Cow::Owned(_)));
        let res = unescape_hex(OsStr::new("test\\x20123"));
        assert_eq!(res, OsStr::new("test 123"));
        assert!(matches!(res, Cow::Owned(_)));
    }
}
