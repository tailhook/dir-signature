use std;
use std::borrow::Cow;
use std::convert::From;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::fmt;
use std::io;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::slice::Chunks;
use std::str::{FromStr, Utf8Error};

use quick_error::ResultExt;

use ::HashType;
use super::writer::{MAGIC, VERSION};


macro_rules! itry {
    ($x: expr) => {
        match $x {
            Err(e) => return Some(Err(From::from(e))),
            Ok(v) => v,
        }
    }
}

#[derive(Debug)]
pub struct ParseRowError(String);

impl fmt::Display for ParseRowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Parse row error: {}", self.0)
    }
}

impl Error for ParseRowError {
    fn description(&self) -> &str {
        return &self.0;
    }
}

impl From<Utf8Error> for ParseRowError {
    fn from(err: Utf8Error) -> ParseRowError {
        ParseRowError(format!("Expected utf-8 string: {}", err))
    }
}

impl From<String> for ParseRowError {
    fn from(err: String) -> ParseRowError {
        ParseRowError(err)
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
        Parse(msg: String, row_num: usize) {
            description("parse error")
            display("Parse error at line {}: {}", row_num, msg)
            context(row_num: usize, err: ParseRowError)
                -> (err.0, row_num)
        }
    }
}

impl HashType {
    fn get_size(self) -> usize {
        match self {
            HashType::Sha512_256 | HashType::Blake2b_256 => 32,
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
        let line = std::str::from_utf8(row)?;
        let mut parts = line.split(' ');
        let version = if let Some(signature) = parts.next() {
            let mut sig_parts = signature.splitn(2, '.');
            if let Some(magic) = sig_parts.next() {
                if magic != MAGIC {
                    return Err(ParseRowError(
                        format!("Invalid signature: expected {:?} but was {:?}",
                            MAGIC, magic)));
                }
            }
            if let Some(version) = sig_parts.next() {
                if version != VERSION {
                    return Err(ParseRowError(
                        format!("Invalid version: expected {:?} but was {:?}",
                            VERSION, version)));
                }
                version
            } else {
                return Err(ParseRowError("Missing version".to_string()));
            }
        } else {
            // it is unreachable
            return Err(ParseRowError("Invalid header".to_string()));
        };
        let hash_type = if let Some(hash_type_str) = parts.next() {
            HashType::from_str(hash_type_str)
                .map_err(|e| ParseRowError(format!("Invalid hash type: {}", e)))?
        } else {
            return Err(ParseRowError(
                "Missing hash type".to_string()));
        };
        let block_size = if let Some(block_size_attr) = parts.next() {
            let mut block_size_kv = block_size_attr.splitn(2, '=');
            match block_size_kv.next() {
                None => {
                    return Err(ParseRowError(format!("Missing block_size")));
                },
                Some(k) if k != "block_size" => {
                    return Err(ParseRowError(
                        format!("Expected block_size attribute")));
                },
                Some(_) => {
                    match block_size_kv.next() {
                        Some(v) => u64::from_str_radix(v, 10)
                            .map_err(|e| ParseRowError(
                                format!("Cannot parse block size {:?}: {}", v, e)))?,
                        None => return Err(ParseRowError(
                            format!("Missing block size"))),
                    }
                },
            }
        } else {
            return Err(ParseRowError(
                format!("Missing block size attribute")));
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
        let digest_len = hash_type.get_size();
        let hash_len = digest_len * 2;
        if row.len() != hash_len {
            return Err(ParseRowError(
                format!("Footer length is {}, expected {}",
                    row.len(), hash_len)));
        }
        let mut data = Vec::with_capacity(digest_len);
        parse_hash(row, hash_len, &mut data)?;
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
    fn parse(row: &[u8], hash_type: HashType)
        -> Result<Hashes, ParseRowError>
    {
        let digest_len = hash_type.get_size();
        let hash_len = digest_len * 2;
        let hashes_num = (row.len() + 1) / (hash_len + 1);
        if row.len() != 0 && (row.len() + 1) % (hash_len + 1) != 0 {
            return Err(ParseRowError(
                format!("Hashes string length is {}, one hash should have exactly {} characters",
                    row.len(), hash_len)));
        }
        let mut data = Vec::with_capacity(hashes_num * digest_len);
        for hash in row.chunks(hash_len + 1) {
            parse_hash(&hash[..hash_len], hash_len, &mut data)?;
            if hash.len() == hash_len + 1 && hash[hash_len] != b' ' {
                return Err(ParseRowError(
                    format!("Invalid hashes delimiter: {:?}",
                        String::from_utf8_lossy(&hash[hash_len..hash_len + 1]))));
            }
        }

        Ok(Hashes {
            data: data,
            hash_type: hash_type,
        })
    }

    fn check_size(&self, file_size: u64, block_size: u64)
        -> Result<(), ParseRowError>
    {
        let expected_hashes_num = ((file_size + block_size - 1) / block_size) as usize;
        if self.len() != expected_hashes_num {
            return Err(ParseRowError(
                format!("Expected {} hashes but found {}",
                    expected_hashes_num, self.len())));
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.data.len() / self.hash_type.get_size()
    }

    pub fn iter<'a>(&'a self) -> Chunks<'a, u8> {
        self.data.chunks(self.hash_type.get_size())
    }
}

/// Represents an entry from dir signature file
#[derive(Debug)]
pub enum Entry {
    /// Direcory
    Dir(PathBuf),
    /// File
    File(PathBuf, bool, u64, Hashes),
    /// Link
    Link(PathBuf, PathBuf),
}

impl Entry {
    fn parse(row: &[u8], current_dir: &Path, hash_type: HashType, block_size: u64)
        -> Result<Option<Entry>, ParseRowError>
    {
        let (entry, tail) = if row.starts_with(b"/") {
            let (path, row) = parse_path_buf(row);
            (Entry::Dir(path), row)
        } else if row.starts_with(b"  ") {
            let row = &row[2..];
            let (path, row) = parse_path(row);
            let path = current_dir.join(&path);
            let (file_type, row) = parse_os_str(row);
            if file_type == "f" || file_type == "x" {
                let (file_size, row) = parse_u64(row)?;
                let hashes = Hashes::parse(row, hash_type)?;
                hashes.check_size(file_size, block_size)?;
                (Entry::File(path, file_type == "x", file_size, hashes), "".as_bytes())
            } else if file_type == "s" {
                let (dest, row) = parse_path_buf(row);
                (Entry::Link(path, dest), row)
            } else {
                return Err(ParseRowError(
                    format!("Unknown file type: {:?}",
                        String::from_utf8_lossy(file_type.as_bytes()))));
            }
        } else {
            return Ok(None);
        };
        if !tail.is_empty() {
            return Err(ParseRowError(
                format!("Row is not fully consumed: {:?}",
                    String::from_utf8_lossy(tail))));
        }
        Ok(Some(entry))
    }
}

/// v1 format reader
pub struct Parser<R: BufRead> {
    header: Header,
    reader: R,
}

impl<R: BufRead> Parser<R> {
    /// Creates a directory signature parser (format v1)
    /// Tries to parse header
    pub fn new(mut reader: R) -> Result<Parser<R>, ParseError> {
        let mut header_line = vec!();
        read_line(&mut reader, &mut header_line)?;
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

pub struct EntryIterator<'a, R: 'a + BufRead> {
    reader: &'a mut R,
    hash_type: HashType,
    block_size: u64,
    current_dir: PathBuf,
    current_row_num: usize,
}

impl<'a, R: BufRead> EntryIterator<'a, R> {
    fn new(reader: &'a mut R, hash_type: HashType, block_size: u64)
        -> EntryIterator<R>
    {
        EntryIterator {
            reader: reader.by_ref(),
            hash_type: hash_type,
            block_size: block_size,
            current_dir: PathBuf::new(),
            current_row_num: 1,
        }
    }
}

impl<'a, R: BufRead> Iterator for EntryIterator<'a, R> {
    type Item = Result<Entry, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = vec!();
        let is_last = itry!(read_line(self.reader.by_ref(), &mut buf));
        let row = &buf[..];
        self.current_row_num += 1;
        let entry = itry!(Entry::parse(
                row, &self.current_dir, self.hash_type, self.block_size)
            .context(self.current_row_num));
        match entry {
            None => {
                let _footer = itry!(Footer::parse(row, self.hash_type)
                    .context(self.current_row_num));
                if is_last {
                    return Some(Err(ParseError::Parse(
                        format!("Footer must be ended by a newline"),
                        self.current_row_num)));
                }
                let mut test_buf = [0; 1];
                if itry!(self.reader.read(&mut test_buf)) != 0 {
                    return Some(Err(ParseError::Parse(
                        format!("Found extra lines after the footer"),
                        self.current_row_num)));
                }
                None
            },
            Some(entry) => {
                if let Entry::Dir(ref dir_path) = entry {
                    self.current_dir = dir_path.clone();
                }
                Some(Ok(entry))
            },
        }
    }
}

fn read_line<R: BufRead>(reader: &mut R, mut buf: &mut Vec<u8>)
    -> Result<bool, io::Error>
{
    let _ = reader.read_until(b'\n', &mut buf)?;
    let is_last = if buf.ends_with(b"\n") {
        buf.pop();
        false
    } else {
        true
    };
    Ok(is_last)
}

fn parse_path<'a>(data: &'a [u8]) -> (Cow<Path>, &'a [u8]) {
    let (path, tail) = parse_os_str(data);
    let unescaped_path = match unescape_hex(path) {
        Cow::Borrowed(p) => Cow::Borrowed(Path::new(p)),
        Cow::Owned(p) => Cow::Owned(PathBuf::from(&p)),
    };
    (unescaped_path, tail)
 }

fn parse_path_buf<'a>(data: &'a [u8]) -> (PathBuf, &'a [u8]) {
    let (path, tail) = parse_os_str(data);
    let unescaped_path = unescape_hex(path);
    (PathBuf::from(&unescaped_path), tail)
}

fn parse_os_str<'a>(data: &'a [u8]) -> (&OsStr, &'a [u8]) {
    let (field, tail) = parse_field(data);
    (OsStr::from_bytes(field), tail)
}

fn parse_u64<'a>(data: &'a [u8]) -> Result<(u64, &'a [u8]), ParseRowError> {
    let (field, tail) = parse_field(data);
    let v = try!(std::str::from_utf8(field).map_err(|e| {
        ParseRowError(format!("Cannot parse integer {:?}: {}",
            String::from_utf8_lossy(field).into_owned(), e))}));

    let v = try!(u64::from_str_radix(v, 10).map_err(|e| {
        ParseRowError(format!("Cannot parse integer {:?}: {}",
            String::from_utf8_lossy(field).into_owned(), e))}));
    Ok((v, tail))
}

fn parse_field<'a>(data: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    let mut parts = data.splitn(2, |c| *c == b' ');
    let field = parts.next().unwrap();
    let tail = parts.next().unwrap_or(&data[0..0]);
    (field, tail)
}

fn parse_hash<'a>(hash: &'a [u8], hash_len: usize, mut data: &mut Vec<u8>)
                  -> Result<(), ParseRowError>
{
    if hash.len() != hash_len {
        return Err(ParseRowError(
            format!("Invalid hash: {:?}", hash)));
    }
    for d in hash.chunks(2) {
        data.push(parse_hex(d)?);
    }
    Ok(())
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
            let c = parse_hex_unsafe(&bytes[i + 2..]);
            v.push(c);
            i += 4;
        } else {
            v.push(bytes[i]);
            i += 1;
        }
    }
    Cow::Owned(OsString::from_vec(v))
}

fn parse_hex(v: &[u8]) -> Result<u8, String> {
    Ok((hex_to_digit(v[0])? << 4) | hex_to_digit(v[1])?)
}

fn hex_to_digit(v: u8) -> Result<u8, String> {
    Ok(match v {
        b'0'...b'9' => v & 0x0f,
        b'a'...b'f' | b'A'...b'F' => (v & 0x0f) + 9,
        _ => return Err(format!("Invalid hex character ord: {:?}", v))
    })
}

fn parse_hex_unsafe(v: &[u8]) -> u8 {
    (hex_to_digit_unsafe(v[0]) << 4) | hex_to_digit_unsafe(v[1])
}

fn hex_to_digit_unsafe(v: u8) -> u8 {
    if v >= b'0' && v <= b'9' {
        return v & 0x0f;
    }
    return (v & 0x0f) + 9;
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
    use super::{parse_hex, is_hex, is_hex_encoding, unescape_hex};

    #[test]
    fn test_header_parse() {
        let res = Header::parse(b"");
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Invalid signature:")),
            "Result was: {:?}", res);

        let res = Header::parse(b"\xff");
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Expected utf-8 string:")),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE");
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Missing version")),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v2");
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Invalid version:")),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1");
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Missing hash type")),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1 sha512/25");
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Invalid hash type: Unsupported hash algorithm")),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1 sha512/256 size=2");
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Expected block_size attribute")),
            "Result was: {:?}", res);

        let res = Header::parse(b"DIRSIGNATURE.v1 sha512/256 block_size=dead");
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Cannot parse block size \"dead\":")),
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

        // FIXME: IMHO next test should pass
        // TODO: writer also should double backslashes
        let res = Entry::parse(b"/test\\x20escaped\\\\x20", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::Dir(ref dir_path)))
                if dir_path == Path::new("/test escaped\\x20")),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test f 0", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::File(ref path, exe, len, _)))
                if path == Path::new("/dir/test") && !exe && len == 0),
            "Result was: {:?}", res);

        let res = Entry::parse(
            b"  test x 100 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc",
            Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::File(ref path, exe, len, _)))
                if path == Path::new("/dir/test") && exe && len == 100),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test s ../dest", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Ok(Some(Entry::Link(ref path, ref dest)))
                if path == Path::new("/dir/test") && dest == Path::new("../dest")),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test l ../dest", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Unknown file type: \"l\"")),
            "Result was: {:?}", res);

        let res = Entry::parse(b"  test s  ../dest", Path::new("/dir"), t, b);
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Row is not fully consumed: \"../dest\"")),
            "Result was: {:?}", res);
    }

    #[test]
    fn test_hashes_parse() {
        let res = Hashes::parse(
            b"\
8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc \
c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::Sha512_256);
        assert!(matches!(res,
                Ok(ref hashes @ Hashes {..})
                if hashes.len() == 2),
            "Result was: {:?}", res);
        let hashes = res.unwrap();
        assert!(matches!(hashes.check_size(1, 32768),
                Err(ParseRowError(ref msg))
                if msg.starts_with("Expected 1 hashes")));
        assert!(matches!(hashes.check_size(65536, 32768), Ok(())));
        assert!(matches!(hashes.check_size(65537, 32768),
                Err(ParseRowError(ref msg))
                if msg.starts_with("Expected 3 hashes")));
        let mut hashes_iter = hashes.iter();
        let first_digest = hashes_iter.next();
        assert!(matches!(first_digest,
                Some(dig)
                if dig == &"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc".from_hex().unwrap()[..]),
            "Digest was: {:?}", first_digest);
        let second_digest = hashes_iter.next();
        assert!(matches!(second_digest,
                Some(dig)
                if dig == &"c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4".from_hex().unwrap()[..]),
            "Digest was: {:?}", second_digest);
        assert!(hashes_iter.next().is_none());

        let res = Hashes::parse(
            b"\
8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc_\
c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::Sha512_256);
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Invalid hashes delimiter: \"_\"")),
            "Result was: {:?}", res);

        let res = Hashes::parse(
            b"8dd499a3",
            HashType::Sha512_256);
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Hashes string length is 8")),
            "Result was: {:?}", res);

        let res = Hashes::parse(
            b"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc ",
            HashType::Sha512_256);
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Hashes string length is 65")),
            "Result was: {:?}", res);

        let res = Hashes::parse(
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            HashType::Sha512_256);
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Invalid hex character ord: 120")),
            "Result was: {:?}", res);
    }

    #[test]
    fn test_hashes_eq() {
        let hashes1_sha = Hashes::parse(
            b"\
8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc \
c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::Sha512_256).unwrap();
        let hashes2_sha = Hashes::parse(
            b"\
8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc \
c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::Sha512_256).unwrap();
        let hashes1_blake = Hashes::parse(
            b"\
8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc \
c384d6b21c50e0aa9bf80124256d56ba36c6a05ce0cc09bf858fa09e84aa19d4",
            HashType::Blake2b_256).unwrap();

        assert_eq!(hashes1_sha, hashes2_sha);
        assert_ne!(hashes1_sha, hashes1_blake);
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
                Err(ParseRowError(ref msg))
                if msg.starts_with("Footer length is 0, expected 64")),
            "Result was: {:?}", res);

        let res = Footer::parse(
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            HashType::Sha512_256);
        assert!(matches!(res,
                Err(ParseRowError(ref msg))
                if msg.starts_with("Invalid hex character ord: 120")),
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
