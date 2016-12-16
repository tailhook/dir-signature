use std::path::Path;

/// Scanner config contains a list of directories you will scan and other
/// settings that influence filesystem scanning
pub struct ScannerConfig {
    threads: usize,
}

impl ScannerConfig {
    /// Create an empty scanner config
    pub fn new() -> ScannerConfig {
        ScannerConfig {
            threads: 1,
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
    pub fn add_dir<P, R>(&mut self, path: P, prefix: R) -> &mut Self
        where P: AsRef<Path>, R: AsRef<Path>
    {
        unimplemented!();
        self
    }
}
