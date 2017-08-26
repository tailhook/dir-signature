use std::io::{BufReader, Cursor, Seek, SeekFrom};
use std::path::Path;

extern crate rustc_hex;
use rustc_hex::FromHex;

#[macro_use] extern crate matches;

extern crate dir_signature;
use dir_signature::HashType;
use dir_signature::v1::{Entry, EntryKind, Parser};

#[test]
fn test_parser() {
    let content = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  empty.txt f 0
  hello.txt f 6 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc
/subdir
  .hidden f 58394 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819 9ce28248299290fe84340d7821adf01b3b6a579ef827e1e58bc3949de4b7e5d9
  just\\x20link s ../hello.txt
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
";
    let reader = BufReader::new(Cursor::new(&content[..]));
    let mut signature_parser = Parser::new(reader).unwrap();

    let header = signature_parser.get_header();
    assert_eq!(header.get_version(), "v1");
    assert_eq!(header.get_hash_type(), HashType::sha512_256());
    assert_eq!(header.get_block_size(), 32768);

    let mut entry_iter = signature_parser.iter();

    let entry = entry_iter.next().unwrap().unwrap();
    match entry {
        Entry::Dir(dir) => {
            assert_eq!(dir, Path::new("/"));
        },
        _ => {
            panic!("Expected directory, found {:?}", entry);
        }
    }

    let entry = entry_iter.next().unwrap().unwrap();
    match entry {
        Entry::File {path, exe, size, hashes} => {
            assert_eq!(path, Path::new("/empty.txt"));
            assert_eq!(exe, false);
            assert_eq!(size, 0);
            assert!(hashes.iter().next().is_none());
        },
        _ => {
            panic!("Expected file, found {:?}", entry)
        }
    }

    let entry = entry_iter.next().unwrap().unwrap();
    match entry {
        Entry::File {path, exe, size, hashes} => {
            let mut hashes_iter = hashes.iter();
            assert_eq!(path, Path::new("/hello.txt"));
            assert_eq!(exe, false);
            assert_eq!(size, 6);
            assert_eq!(hashes_iter.next().unwrap(),
                &"8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc"
                .from_hex().unwrap()[..]);
            assert!(hashes_iter.next().is_none());
        },
        _ => {
            panic!("Expected file, found {:?}", entry)
        }
    }

    let _ = entry_iter.next().unwrap().unwrap();
    let _ = entry_iter.next().unwrap().unwrap();
    let entry = entry_iter.next().unwrap().unwrap();
    match entry {
        Entry::Link(path, dest) => {
            assert_eq!(path, Path::new("/subdir/just link"));
            assert_eq!(dest, Path::new("../hello.txt"));
        },
        _ => {
            panic!("Expected symlink, found {:?}", entry)
        }
    }

    let entry = entry_iter.next();
    assert!(matches!(entry, None), "Was: {:?}", entry);
    let entry = entry_iter.next();
    assert!(matches!(entry, None), "Was: {:?}", entry);
}

#[test]
fn test_parser_advance_file() {
    let content = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  empty.txt f 0
  hello.txt f 6 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc
/empty
/full
  test.txt f 0
/subdir
  .hidden f 28394 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
  just\\x20link s ../hello.txt
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
";
    let reader = BufReader::new(Cursor::new(&content[..]));
    let mut signature_parser = Parser::new(reader).unwrap();
    let mut entry_iter = signature_parser.iter();

    let entry = entry_iter.advance(&EntryKind::File("/hello.txt"));
    assert!(matches!(entry,
            Some(Ok(Entry::File {ref path, exe, size, ..}))
            if path == Path::new("/hello.txt") && !exe && size == 6),
        "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File("/hello.txt"));
    assert!(matches!(entry, None), "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File("/subdir"));
    assert!(matches!(entry, None), "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::Dir("/empty"));
    assert!(matches!(entry,
            Some(Ok(Entry::Dir(ref path))) if path == Path::new("/empty")),
        "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File("/subdir/.hidden"));
    assert!(matches!(entry,
            Some(Ok(Entry::File {ref path, exe, size, ..}))
            if path == Path::new("/subdir/.hidden") && !exe && size == 28394),
            "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File("/subdir/just"));
    assert!(matches!(entry, None), "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File("/subdir/just link"));
    assert!(matches!(entry,
            Some(Ok(Entry::Link(ref path, ref dest)))
            if path == Path::new("/subdir/just link") &&
                dest == Path::new("../hello.txt")),
        "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File("/zzz"));
    assert!(matches!(entry, None), "Entry was: {:?}", entry);
}

#[test]
fn test_parser_advance_current_path_is_greater_than_wanted_file_dir() {
    let content = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
/etc
  zzz f 0
/etc/z
  a f 0
0000000000000000000000000000000000000000000000000000000000000000
";
    let reader = BufReader::new(Cursor::new(&content[..]));
    let mut signature_parser = Parser::new(reader).unwrap();
    let mut entry_iter = signature_parser.iter();

    let entry = entry_iter.advance(&EntryKind::File("/etc/z/a"));
    assert!(matches!(entry,
            Some(Ok(Entry::File {ref path, ..}))
            if path == Path::new("/etc/z/a")),
        "Entry was: {:?}", entry);
}

#[test]
fn test_parser_advance_current_path_is_less_than_wanted_file_dir() {
    let content = b"\
    DIRSIGNATURE.v1 sha512/256 block_size=32768
/
/etc
  zzz f 0
/etc/z
  a f 0
  b f 0
0000000000000000000000000000000000000000000000000000000000000000
";
    let reader = BufReader::new(Cursor::new(&content[..]));
    let mut signature_parser = Parser::new(reader).unwrap();
    let mut entry_iter = signature_parser.iter();

    let entry = entry_iter.advance(&EntryKind::File("/etc/z/a"));
    assert!(matches!(entry,
            Some(Ok(Entry::File {ref path, ..}))
            if path == Path::new("/etc/z/a")),
        "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File("/etc/zzz"));
    assert!(matches!(entry, None), "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File("/etc/z/b"));
    assert!(matches!(entry,
            Some(Ok(Entry::File {ref path, ..}))
            if path == Path::new("/etc/z/b")),
        "Entry was: {:?}", entry);
}

#[test]
fn test_parser_advance_dir() {
    let content = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  empty.txt f 0
/bin
/dev
/etc
  hosts f 0
/usr
/usr/bin
/usr/share
  test f 0
/var
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
";
    let reader = BufReader::new(Cursor::new(&content[..]));
    let mut signature_parser = Parser::new(reader).unwrap();
    let mut entry_iter = signature_parser.iter();

    let entry = entry_iter.advance(&EntryKind::Dir(Path::new("/etc")));
    assert!(matches!(entry,
            Some(Ok(Entry::Dir(ref path)))
            if path == Path::new("/etc")),
        "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::Dir(Path::new("/etc")));
    assert!(matches!(entry, None), "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File(Path::new("/etc/hosts")));
    assert!(matches!(entry,
            Some(Ok(Entry::File{ref path, ..}))
            if path == Path::new("/etc/hosts")),
        "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::Dir(Path::new("/usr/share")));
    assert!(matches!(entry,
            Some(Ok(Entry::Dir(ref path)))
            if path == Path::new("/usr/share")),
        "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::Dir(Path::new("/usr/bin")));
    assert!(matches!(entry, None), "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::File(Path::new("/usr/share/test")));
    assert!(matches!(entry,
            Some(Ok(Entry::File{ref path, ..}))
            if path == Path::new("/usr/share/test")),
        "Entry was: {:?}", entry);
    let entry = entry_iter.advance(&EntryKind::Dir(Path::new("/var")));
    assert!(matches!(entry,
            Some(Ok(Entry::Dir(ref path)))
            if path == Path::new("/var")),
        "Entry was: {:?}", entry);

    let entry = entry_iter.next();
    assert!(matches!(entry, None), "Entry was: {:?}", entry);
}

#[test]
fn test_parser_invalid_header_signature() {
    let content = "DIRSIGNATUR.v1 sha512/256 block_size=32768\n";
    let reader = BufReader::new(Cursor::new(&content[..]));
    match Parser::new(reader) {
        Err(err) => {
            assert_eq!(format!("{}", err),
                "Parse error at line 1: \
                 Invalid signature: expected \"DIRSIGNATURE\" \
                 but was \"DIRSIGNATUR\"");
        },
        Ok(_) => {
            panic!("Expected error");
        },
    }
}

#[test]
fn test_parser_invalid_footer() {
    let content = "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc";
    let reader = BufReader::new(Cursor::new(&content[..]));
    let mut parser = Parser::new(reader).unwrap();
    let entry_res = parser.iter().next();
    assert_eq!(format!("{}", entry_res.unwrap().unwrap_err()),
        "Parse error at line 2: Invalid line: \
         Every line must end with a newline");
    /*
    assert!(matches!(entry_res,
            Some(Err(ParseError::Parse(ParseRowError::InvalidLine(ref msg), row_num)))
            if msg.starts_with("Every line must end with a newline") && row_num == 2),
        "Entry result was: {:?}", entry_res);
    */
}

#[test]
fn test_parser_reset() {
    let content = "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc
";
    let reader = BufReader::new(Cursor::new(&content[..]));
    let mut parser = Parser::new(reader).unwrap();

    {
        let mut entry_iter = parser.iter();
        let entry = entry_iter.next();
        assert!(matches!(entry,
                Some(Ok(Entry::Dir(ref path))) if path == Path::new("/")),
            "Entry result was: {:?}", entry);
        let entry = entry_iter.next();
        assert!(matches!(entry, None), "Entry result was: {:?}", entry);
    }

    let mut reader = parser.into_reader();
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut parser = Parser::new(reader).unwrap();

    let mut entry_iter = parser.iter();
    let entry = entry_iter.next();
    assert!(matches!(entry,
            Some(Ok(Entry::Dir(ref path))) if path == Path::new("/")),
        "Entry result was: {:?}", entry);
}
