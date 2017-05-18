#![feature(test)]

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process;

extern crate test;
use test::Bencher;

extern crate dir_signature;
use dir_signature::v1::{Entry, Parser};
use dir_signature::v1::merge::FileMergeBuilder;

#[bench]
fn bench_parser_iterator_ubuntu(bencher: &mut Bencher) {
    let sig_path = get_ubuntu_signature_path();
    let (num_dirs, num_files, num_links) = warmup_signature_file(sig_path);
    println!("");
    println!("Signature file contains:");
    println!("{} directories", num_dirs);
    println!("{} files", num_files);
    println!("{} links", num_links);

    bencher.iter(|| {
        let idx_file = File::open(sig_path).unwrap();
        let reader = BufReader::new(idx_file);
        let mut signature_parser = Parser::new(reader).unwrap();
        for entry in signature_parser.iter() {
            match entry.unwrap() {
                Entry::Dir(_) => {},
                Entry::File{..} => {},
                Entry::Link(..) => {},
            }
        }
    });
}

#[bench]
fn bench_merged_iterator(bencher: &mut Bencher) {
    let sig_path = get_ubuntu_signature_path();
    warmup_signature_file(sig_path);

    bencher.iter(|| {
        let mut merge_builder = FileMergeBuilder::new();
        merge_builder.add("/a", sig_path);
        merge_builder.add("/b", sig_path);
        merge_builder.add("/c", sig_path);
        let mut merged = merge_builder.finalize().unwrap();
        let merged_iter = merged.iter();
        for entries in merged_iter {
            assert_eq!(entries.len(), 3);
            for (_, entry) in entries {
                let entry = entry.unwrap();
                match entry {
                    Entry::Dir(_) => {},
                    Entry::File{..} => {},
                    Entry::Link(..) => {},
                }
            }
        }
    });
}

fn get_ubuntu_signature_path<'a>() -> &'a Path {
    let ubuntu_idx_path = Path::new("benches/ubuntu-xenial.v1.idx");
    if !ubuntu_idx_path.exists() {
        println!("");
        println!("To generate direcotry signature run: vagga gen-test-data");
        process::exit(1);
    }
    ubuntu_idx_path
}

fn warmup_signature_file(path: &Path) -> (usize, usize, usize) {
    let mut num_dirs = 0;
    let mut num_files = 0;
    let mut num_links = 0;
    let idx_file = File::open(path).unwrap();
    let reader = BufReader::new(idx_file);
    let mut signature_parser = Parser::new(reader).unwrap();
    for entry in signature_parser.iter() {
        match entry.unwrap() {
            Entry::Dir(_) => num_dirs += 1,
            Entry::File{..} => num_files += 1,
            Entry::Link(..) => num_links += 1,
        }
    }
    (num_dirs, num_files, num_links)
}
