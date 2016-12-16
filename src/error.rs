use std::io;

quick_error! {
    /// Error returned from scanning and making an index
    #[derive(Debug)]
    pub enum Error {
        /// Error writing index
        WriteError(err: io::Error) {
            description("error writing index")
            display("error writing index: {}", err)
        }
    }
}
