use std::io;
use std::sync::Arc;
use std::path::Path;
use error::Error::{self, WriteError as EWrite, ReadFile as EFile};

use openat::{Dir, Entry};

use super::hash::Hash;

pub trait Writer {
    fn start_dir(&mut self, path: &Path) -> Result<(), Error>;
    fn add_file(&mut self, dir: &Arc<Dir>, entry: Entry) -> Result<(), Error>;
    fn add_symlink(&mut self, dir: &Arc<Dir>, entry: Entry)
        -> Result<(), Error>;
}

pub struct SyncWriter<F, H> {
    file: F,
    block_size: u64,
    hash: H,
}

impl<F: io::Write, H: Hash> Writer for SyncWriter<F, H> {
    fn start_dir(&mut self, path: &Path) -> Result<(), Error> {
        writeln!(&mut self.file, "{}",
            // TODO(tailhook) excape path
            path.display()
        ).map_err(EWrite)?;
        Ok(())
    }
    fn add_file(&mut self, dir: &Arc<Dir>, entry: Entry)
        -> Result<(), Error>
    {
        let mut f = dir.open_file(&entry).map_err(EFile)?;
        let meta = f.metadata().map_err(EFile)?;
        let mut n = meta.len();
        write!(&mut self.file, "  {} f {}",
            // TODO(tailhook) escape correctly
            Path::new(entry.file_name()).display(),
            n,
        ).map_err(EWrite)?;
        while n > 0 {
            let h = self.hash.hash(&mut f, self.block_size).map_err(EFile)?;
            write!(&mut self.file, " {:x}", h).map_err(EWrite)?;
            n = n.saturating_sub(self.block_size);
        }
        self.file.write_all(b"\n").map_err(EWrite)?;
        Ok(())
    }
    fn add_symlink(&mut self, dir: &Arc<Dir>, entry: Entry)
        -> Result<(), Error>
    {
        let dest = dir.read_link(&entry).map_err(EFile)?;
        write!(&mut self.file, "  {} s {}\n",
            // TODO(tailhook) escape correctly
            Path::new(entry.file_name()).display(),
            // TODO(tailhook) escape correctly
            dest.display(),
        ).map_err(EWrite)?;
        Ok(())
    }
}

impl<F: io::Write, H: Hash> SyncWriter<F, H> {
    pub fn new(mut f: F, hash: H, block_size: u64)
        -> Result<SyncWriter<F, H>, Error>
    {
        writeln!(&mut f,
            "DIRSIGNATURE.v1 {} block_size={}",
            hash.name(),
            block_size,
        ).map_err(EWrite)?;
        Ok(SyncWriter {
            file: f,
            block_size: block_size,
            hash: hash,
        })
    }
}
