use std::str::FromStr;
use std::path::Path;

use {ScannerConfig, Error};

#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum HashType {
    Sha512_256,
}

impl FromStr for HashType {
    type Err = Error;
    fn from_str(val: &str) -> Result<HashType, Self::Err> {
        match val {
            "sha512/256" => Ok(HashType::Sha512_256),
            _ => Err(Error::UnsupportedHash),
        }
    }
}


impl ScannerConfig {
    /// Create an empty scanner config
    pub fn new() -> ScannerConfig {
        ScannerConfig {
            threads: 0,
            queue_size: None,
            hash: HashType::Sha512_256,
            block_size: 32768,
            dirs: Vec::new(),
        }
    }
    /// Set number of threads to use for scanning
    ///
    /// Default is 1 which means don't create additional threads run scanning
    /// in current one
    pub fn threads(&mut self, num: usize) -> &mut Self {
        self.threads = num;
        self
    }
    /// Set number of index entries that can be queued in the background
    ///
    /// It only makes sense if threads > 0 and you may need to tweak it only
    /// in very memory constraint situations
    ///
    /// Default is some value proportional to the number of threads.
    pub fn queue_size(&mut self, num: usize) -> &mut Self {
        self.queue_size = Some(num);
        self
    }
    /// Add a directory to the index
    ///
    /// `prefix` should either be `/` or a subdirectory where indexed files
    /// will be placed
    pub fn add_dir<P, R>(&mut self, path: P, prefix: R) -> &mut Self
        where P: AsRef<Path>, R: AsRef<Path>
    {
        self.dirs.push((path.as_ref().to_path_buf(),
                        prefix.as_ref().to_path_buf()));
        self
    }
}
