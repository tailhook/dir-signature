#[macro_use] extern crate log;

use env_logger;



use std::io::{self, Write};
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::exit;

use argparse::{ArgumentParser, List, ParseOption, Store, StoreTrue, StoreFalse};
#[cfg(feature="threads")]
use num_cpus::get as get_num_cpus;

use dir_signature::{v1, ScannerConfig, HashType};

#[cfg(not(feature="threads"))]
fn get_num_cpus() -> usize {
    1
}

pub fn run() -> i32 {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "warn");
    }
    env_logger::init();

    let mut index = None::<PathBuf>;
    let mut threads = get_num_cpus();
    let mut dirs = Vec::<String>::new();
    let mut hash_type = HashType::sha512_256();
    let mut progress = true;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("
            Scan directories of files. And produce consisten hash of them.
        ");
        ap.refer(&mut dirs)
            .add_argument("[PREFIX:]DIR", List, "
                A path to the directory to add contents from.
                By default all are added recursively at the root of image.
                But you might specify a PREFIX")
            .required();
        ap.refer(&mut index)
            .add_option(&["-o", "--write-index"], ParseOption,
                "The file to write index to")
            .metavar("PATH");
        ap.refer(&mut progress)
            .add_option(&["-q", "--no-progress"], StoreFalse,
                "Do not output progress or anything except errors")
            .add_option(&["--progress"], StoreTrue,
                "Show progress (default)");
        ap.refer(&mut hash_type)
            .add_option(&["--hash"], Store,
                "Use specified hasher.
                 Options: `sha512/256` (default), `blake2b/256`.")
            .metavar("HASH");
        #[cfg(feature="threads")]
        ap.refer(&mut threads)
            .add_option(&["-t", "--threads"], Store,
                "Number of threads to use for hashing files (defaults to a
                number of CPUs (cores) on the machine. Utility will use
                another thread to scan directories. Setting to 0 will use
                a single thread both for scanning and calculating hashes.")
            .metavar("NUM");
        #[cfg(not(feature="threads"))]
        ap.refer(&mut threads)
            .add_option(&["-t", "--threads"], Store,
                "Does nothing as thread support was disabled at complie time")
            .metavar("NUM");
        match ap.parse_args() {
            Ok(()) => {}
            Err(x) => return x,
        }
    }

    let mut cfg = ScannerConfig::new();
    cfg.threads(threads + 1);
    cfg.hash(hash_type);
    if progress {
        cfg.print_progress();
    }
    if dirs.len() > 1 {
        warn!("Using more than one source dir is not recommended as it's \
               not implemented properly yet");
    }
    for dir in dirs.iter() {
        let mut seq = dir.splitn(1, ':');
        let (prefix, path) = match (seq.next().unwrap(), seq.next()) {
            (prefix, Some(dir)) => (Path::new(prefix), Path::new(dir)),
            (dir, None) => (Path::new("/"), Path::new(dir)),
        };
        if !prefix.is_absolute() {
            error!("Prefix must be absolute path");
            return 1;
        }
        cfg.add_dir(path, prefix);
    }

    let res = if let Some(path) = index {
        let file = match File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                writeln!(&mut io::stderr(), "Can't create index: {}", e).ok();
                return 1;
            }
        };
        v1::scan(&cfg, &mut io::BufWriter::new(file))
    } else {
        v1::scan(&cfg, &mut io::stdout())
    };
    match res {
        Ok(()) => return 0,
        Err(e) => {
            writeln!(&mut io::stderr(), "Error: {}", e).ok();
            return 1;
        }
    }
}

fn main() {
    exit(run());
}
