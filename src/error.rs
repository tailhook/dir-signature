use std::io;

/// This is just a common error returned from the library
///
// TODO(tailhook) should we split it?
quick_error! {
    /// Error returned from scanning and making an index
    #[derive(Debug)]
    pub enum Error {
        /// Error writing index
        WriteError(err: io::Error) {
            description("error writing index")
            display("error writing index: {}", err)
        }
        /// Error opening dir (O_PATH)
        OpenDir(err: io::Error) {
            description("error opening dir")
            display("error opening dir: {}", err)
        }
        /// Error listing dir
        ListDir(err: io::Error) {
            description("error listing directory")
            display("error listing directory: {}", err)
        }
        /// Error reading file
        ReadFile(err: io::Error) {
            description("error reading file")
            display("error reading file: {}", err)
        }
        /// No root directory
        // TODO(tailhook) lift this restriction
        NoRootDirectory {
            description("no root directory to build index for")
        }
        /// Unsupported hash algorithm
        UnsupportedHash {
            description("Unsupported hash algorithm")
        }
    }
}
