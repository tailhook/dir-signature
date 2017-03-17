use std::io::{BufReader, Cursor};
use std::path::Path;

extern crate rustc_serialize;
use rustc_serialize::hex::FromHex;

#[macro_use] extern crate matches;

extern crate dir_signature;
use dir_signature::HashType;
use dir_signature::v1::{Entry, Parser, ParseError, ParseRowError};

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
    assert_eq!(header.get_hash_type(), HashType::Sha512_256);
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
fn test_parser_invalid_header_signature() {
    let content = "DIRSIGNATUR.v1 sha512/256 block_size=32768\n";
    let reader = BufReader::new(Cursor::new(&content[..]));
    match Parser::new(reader) {
        Err(ParseError::Parse(ref err, row_num)) => {
            assert_eq!(format!("{}", err),
                "Invalid signature: expected \"DIRSIGNATURE\" but was \"DIRSIGNATUR\"");
            assert_eq!(row_num, 1);
        },
        Err(_) => {
            panic!("Expected \"ParseError::Parse\" error");
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
    assert!(matches!(entry_res,
            Some(Err(ParseError::Parse(ParseRowError::InvalidLine(ref msg), row_num)))
            if msg.starts_with("Every line must end with a newline") && row_num == 2),
        "Entry result was: {:?}", entry_res);
}
