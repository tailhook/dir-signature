use std;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::convert::From;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::io;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::slice::Chunks;
use std::str::FromStr;

use quick_error::ResultExt;

use ::HashType;
use super::writer::{MAGIC, VERSION};

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
    pub enum ParseError {
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

/// Represents any entry inside the signature file to which we want to advance
#[derive(Debug)]
pub enum Advancing<P: AsRef<Path>> {
    /// A directory inside the signature file
    Dir(P),
    /// A file inside the signature file
    File(P),
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

/// Entry hashes iterator
#[derive(Debug, PartialEq)]
pub struct Hashes {
    data: Vec<u8>,
    hash_type: HashType,
}

impl Hashes {
    fn new(data: Vec<u8>, hash_type: HashType) -> Hashes {
        Hashes {
            data: data,
            hash_type: hash_type,
        }
    }

    /// Number of hashes
    pub fn len(&self) -> usize {
        self.data.len() / self.hash_type.output_bytes()
    }

    /// Returns iterator over hashes
    pub fn iter<'a>(&'a self) -> Chunks<'a, u8> {
        self.data.chunks(self.hash_type.output_bytes())
    }
}

/// Represents an entry from dir signature file
#[derive(Debug)]
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
                let hashes = Hashes::new(hashes_data, hash_type);
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
    pub fn get_path(&self) -> &Path {
        match *self {
            Entry::Dir(ref path) |
            Entry::File{ref path, ..} |
            Entry::Link(ref path, _) => path
        }
    }

    /// Returns proper `Advancing` instance for the entry
    /// to pass into
    /// [`EntryIterator::advance`](struct.EntryIterator.html#method.advance)
    /// method
    pub fn advancing(&self) -> Advancing<PathBuf> {
        match *self {
            Entry::Dir(ref path) => Advancing::Dir(path.clone()),
            Entry::File{ref path, ..} |
            Entry::Link(ref path, _) => Advancing::File(path.clone()),
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
        read_line(&mut reader, &mut header_line).context(1)?;
        let header = Header::parse(&header_line).context(1)?;
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
                    return Err(ParseError::Parse(
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
    pub fn advance<P: AsRef<Path>>(&mut self, advancing: &Advancing<P>)
        -> Option<Result<Entry, ParseError>>
    {
        match *advancing {
            Advancing::File(ref path) => {
                self.advance_to_file(path.as_ref())
            },
            Advancing::Dir(ref path) => {
                self.advance_to_dir(path.as_ref())
            },
        }
    }

    fn advance_to_file(&mut self, path: &Path)
        -> Option<Result<Entry, ParseError>>
    {
        let dir = if let Some(dir) = path.parent() {
            dir
        } else {
            return None;
        };
        loop {
            match self.parse_entry() {
                Ok(Some(entry)) => {
                    if let Entry::Dir(..) = entry {
                        if self.current_dir <= dir {
                            self.current_row.clear();
                            continue;
                        } else {
                            return None;
                        }
                    }
                    match entry.get_path().cmp(path) {
                        Ordering::Less => {
                            self.current_row.clear();
                            continue;
                        },
                        Ordering::Equal => {
                            self.current_row.clear();
                            return Some(Ok(entry));
                        },
                        Ordering::Greater => {
                            return None;
                        },
                    }
                },
                Ok(None) => return None,
                Err(e) => return Some(Err(e)),
            }
        }
    }

    fn advance_to_dir(&mut self, path: &Path)
        -> Option<Result<Entry, ParseError>>
    {
        loop {
            match self.parse_entry() {
                Ok(Some(entry)) => {
                    if let Entry::File{..} = entry {
                        if self.current_dir < path {
                            self.current_row.clear();
                            continue;
                        } else {
                            return None;
                        }
                    }
                    if let Entry::Dir(..) = entry {
                        match self.current_dir.as_path().cmp(path) {
                            Ordering::Less => {
                                self.current_row.clear();
                                continue;
                            },
                            Ordering::Equal => {
                                self.current_row.clear();
                                return Some(Ok(entry));
                            },
                            Ordering::Greater => {
                                return None;
                            },
                        }
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
    use std::path::Path;

    use rustc_serialize::hex::FromHex;

    use ::HashType;
    use super::{Entry, Footer, Hashes, Header, ParseRowError};
    use super::{parse_hashes, parse_hex, is_hex, is_hex_encoding, unescape_hex};

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
        assert!(matches!(header.get_hash_type(), HashType::Sha512_256));
        assert_eq!(header.get_block_size(), 1234);
    }

    #[test]
    fn test_entry_parse() {
        let t = HashType::Sha512_256;
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
            HashType::Sha512_256, 1);
        assert!(matches!(res,
                Ok((ref hashes, tail))
                if hashes.len() == 32 && tail.len() == 64),
            "Result was: {:?}", res);

        let res = parse_hashes(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc  \
              c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::Sha512_256, 2);
        assert!(matches!(res,
                Err(ParseRowError::InvalidLine(ref msg))
                if msg == "Row has multiple spaces"),
            "Result was: {:?}", res);

        let res = parse_hashes(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc \
              c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::Sha512_256, 3);
        assert!(matches!(res,
                Err(ParseRowError::InvalidHash(ref msg))
                if msg == "Expected 3 hashes but found 2"),
            "Result was: {:?}", res);

        let res = parse_hashes(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc_\
              c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::Sha512_256, 1);
        assert!(matches!(res,
                Err(ParseRowError::InvalidHash(ref msg))
                if msg.starts_with("Expected hash with length of 64:")),
            "Result was: {:?}", res);
    }

    #[test]
    fn test_hashes_eq() {
        assert_eq!(
            Hashes::new(b"\x00".to_vec(), HashType::Sha512_256),
            Hashes::new(b"\x00".to_vec(), HashType::Sha512_256));
        assert_ne!(
            Hashes::new(b"\x00".to_vec(), HashType::Sha512_256),
            Hashes::new(b"\xFF".to_vec(), HashType::Sha512_256));
        assert_ne!(
            Hashes::new(b"\x00".to_vec(), HashType::Sha512_256),
            Hashes::new(b"\x00".to_vec(), HashType::Blake2b_256));
    }

    #[test]
    fn test_footer_parse() {
        let res = Footer::parse(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc",
            HashType::Sha512_256);
        assert!(matches!(res,
                Ok(Footer(ref data))
                if data == &"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc".from_hex().unwrap()),
            "Result was: {:?}", res);

        let res = Footer::parse(b"", HashType::Sha512_256);
        assert!(matches!(res,
                Err(ParseRowError::InvalidHash(ref msg))
                if msg.starts_with("Expected 1 hashes but found 0")),
            "Result was: {:?}", res);

        let res = Footer::parse(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc  test",
            HashType::Sha512_256);
        assert!(matches!(res,
                Err(ParseRowError::InvalidLine(ref msg))
                if msg == "Footer is not fully consumed: \" test\""),
            "Result was: {:?}", res);

        let res = Footer::parse(
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            HashType::Sha512_256);
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
