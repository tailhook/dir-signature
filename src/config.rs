use std::path::Path;

use {ScannerConfig, HashType, HashTypeEnum};


impl ScannerConfig {
    /// Create an empty scanner config with defaults
    ///
    /// By default we use ``sha512/256`` hasher as it increases
    /// interoperability, but consider using ``blake2b/256`` as it 25% faster
    pub fn new() -> ScannerConfig {
        ScannerConfig {
            threads: 0,
            queue_size: None,
            hash: HashType(HashTypeEnum::Sha512_256),
            block_size: 32768,
            dirs: Vec::new(),
            print_progress: false,
        }
    }
    /// Use different hash type
    pub fn hash(&mut self, hash: HashType) -> &mut Self {
        self.hash = hash;
        self
    }
    /// Set number of threads to use for scanning
    ///
    /// Default is 0 which means don't create additional threads and do
    /// hashing and directory scanning in current thread. Otherwise we will
    /// create num threads for hashing and will use current thread for
    /// scanning directories and priting progress.
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
    /// Enable printing progress to stderr
    pub fn print_progress(&mut self) -> &mut Self {
        self.print_progress = true;
        self
    }
}
