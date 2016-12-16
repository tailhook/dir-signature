use std::path::{Path, PathBuf};

/// Scanner config contains a list of directories you will scan and other
/// settings that influence filesystem scanning
pub struct ScannerConfig {
    threads: usize,
    dirs: Vec<(PathBuf, PathBuf)>,
}

impl ScannerConfig {
    /// Create an empty scanner config
    pub fn new() -> ScannerConfig {
        ScannerConfig {
            threads: 1,
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
