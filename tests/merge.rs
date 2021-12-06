use std::io::{BufReader, Cursor};
use std::path::{Path, PathBuf};

#[macro_use] extern crate matches;


use dir_signature::HashType;
use dir_signature::v1::{Entry, EntryKind, Parser};
use dir_signature::v1::merge::{MergeError, MergedSignatures};

#[test]
fn test_merger() {
    let content1 = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  empty.txt f 0
  hello.txt f 6 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc
/subdir
  .hidden f 28394 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
  link s ../hello.txt
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
";
    let content2 = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  empty.txt f 0
  byebye.txt f 3 339d14455c458d1ad7b57ee247a6628e4fc8e39958bbc23f2579827456818fc8
/subdir
  .hidden f 28394 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
  link2 s ../hello.txt
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
";
    let parsers = vec!(
        (
            PathBuf::from("/111"),
            Parser::new(BufReader::new(Cursor::new(&content1[..]))).unwrap()
        ),
        (
            PathBuf::from("/222"),
            Parser::new(BufReader::new(Cursor::new(&content2[..]))).unwrap()
        ),
    );

    let mut merger = MergedSignatures::new(parsers).unwrap();
    let mut merged_iter = merger.iter();

    let entries = merged_iter.advance(&EntryKind::File("/empty.txt"));
    assert_eq!(entries.len(), 2);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::File{ref path, exe, size, ..}))
            if base_path == Path::new("/111") &&
                path == Path::new("/empty.txt") &&
                !exe && size == 0),
        "Was: {:?}", entry);
    let ref entry = entries[1];
    assert!(matches!(entry, &(base_path, Ok(Entry::File{ref path, exe, size, ..}))
            if base_path.clone() == Path::new("/222") &&
                path == Path::new("/empty.txt") &&
                !exe && size == 0),
        "Was: {:?}", entry);

    let entries = merged_iter.advance(&EntryKind::File("/z.txt"));
    assert_eq!(entries.len(), 0);
}

#[test]
fn test_merge_different_hash_types() {
    let content1 = b"DIRSIGNATURE.v1 blake2b/256 block_size=32768\n";
    let content2 = b"DIRSIGNATURE.v1 sha512/256 block_size=32768\n";
    let parsers = vec!(
        (
            PathBuf::from("/111"),
            Parser::new(BufReader::new(Cursor::new(&content1[..]))).unwrap()
        ),
        (
            PathBuf::from("/222"),
            Parser::new(BufReader::new(Cursor::new(&content2[..]))).unwrap()
        ),
    );

    let merger = MergedSignatures::new(parsers);
    assert!(matches!(merger,
            Err(MergeError::HashTypesMismatch(ref types))
            if types == &vec![HashType::blake2b_256(),
                              HashType::sha512_256()]));
}

#[test]
fn test_merge_different_block_sizes() {
    let content1 = b"DIRSIGNATURE.v1 sha512/256 block_size=32768\n";
    let content2 = b"DIRSIGNATURE.v1 sha512/256 block_size=65536\n";
    let parsers = vec!(
        (
            PathBuf::from("/111"),
            Parser::new(BufReader::new(Cursor::new(&content1[..]))).unwrap()
        ),
        (
            PathBuf::from("/222"),
            Parser::new(BufReader::new(Cursor::new(&content2[..]))).unwrap()
        ),
    );

    let merger = MergedSignatures::new(parsers);
    assert!(matches!(merger,
            Err(MergeError::BlockSizesMismatch(ref sizes))
            if sizes == &vec!(32768, 65536)));
}

#[test]
fn test_merge_iter() {
    let content1 = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
/a
  .hidden f 28394 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
/b
  empty.txt f 0
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
";
    let content2 = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  1 f 0
  hello.txt f 5 339d14455c458d1ad7b57ee247a6628e4fc8e39958bbc23f2579827456818fc8
/a
  .hidden f 28394 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
/c
  empty.txt f 0
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
";
    let parsers = vec!(
        (
            PathBuf::from("/111"),
            Parser::new(BufReader::new(Cursor::new(&content1[..]))).unwrap()
        ),
        (
            PathBuf::from("/222"),
            Parser::new(BufReader::new(Cursor::new(&content2[..]))).unwrap()
        ),
    );

    let mut merger = MergedSignatures::new(parsers).unwrap();
    let mut merged_iter = merger.iter();

    let entries = merged_iter.next().unwrap();
    assert_eq!(entries.len(), 2);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::Dir(ref path)))
                     if base_path == Path::new("/111") &&
                     path == Path::new("/")),
            "Was: {:?}", entry);
    let ref entry = entries[1];
    assert!(matches!(entry, &(base_path, Ok(Entry::Dir(ref path)))
                     if base_path == Path::new("/222") &&
                     path == Path::new("/")),
            "Was: {:?}", entry);

    let entries = merged_iter.next().unwrap();
    assert_eq!(entries.len(), 1);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::File{ref path, size, ..}))
                     if base_path == Path::new("/222") &&
                     path == Path::new("/1") && size == 0),
            "Was: {:?}", entry);

    let entries = merged_iter.next().unwrap();
    assert_eq!(entries.len(), 1);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::File{ref path, size, ..}))
                     if base_path == Path::new("/222") &&
                     path == Path::new("/hello.txt") && size == 5),
            "Was: {:?}", entry);

    let entries = merged_iter.next().unwrap();
    assert_eq!(entries.len(), 2);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::Dir(ref path)))
                     if base_path == Path::new("/111") &&
                     path == Path::new("/a")),
            "Was: {:?}", entry);
    let ref entry = entries[1];
    assert!(matches!(entry, &(base_path, Ok(Entry::Dir(ref path)))
                     if base_path == Path::new("/222") &&
                     path == Path::new("/a")),
            "Was: {:?}", entry);

    let entries = merged_iter.next().unwrap();
    assert_eq!(entries.len(), 2);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::File{ref path, size, ..}))
                     if base_path == Path::new("/111") &&
                     path == Path::new("/a/.hidden") && size == 28394),
            "Was: {:?}", entry);
    let ref entry = entries[1];
    assert!(matches!(entry, &(base_path, Ok(Entry::File{ref path, size, ..}))
                     if base_path == Path::new("/222") &&
                     path == Path::new("/a/.hidden") && size == 28394),
            "Was: {:?}", entry);

    let entries = merged_iter.next().unwrap();
    assert_eq!(entries.len(), 1);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::Dir(ref path)))
                     if base_path == Path::new("/111") &&
                     path == Path::new("/b")),
            "Was: {:?}", entry);

    println!("Advancing to -> /c");
    let entries = merged_iter.advance(&EntryKind::Dir("/c"));
    assert_eq!(entries.len(), 1);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::Dir(ref path)))
                     if base_path == Path::new("/222") &&
                     path == Path::new("/c")),
            "Was: {:?}", entry);

    let entries = merged_iter.next().unwrap();
    assert_eq!(entries.len(), 1);
    let ref entry = entries[0];
    assert!(matches!(entry, &(base_path, Ok(Entry::File{ref path, size, ..}))
                     if base_path == Path::new("/222") &&
                     path == Path::new("/c/empty.txt") && size == 0),
            "Was: {:?}", entry);

    assert!(merged_iter.next().is_none());
}
