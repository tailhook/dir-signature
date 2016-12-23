use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::path::Path;
use std::os::unix::ffi::OsStrExt;


use sha2::Digest;
use openat::{Dir, Entry};

use error::Error::{self, WriteError as EWrite, ReadFile as EFile};
use super::hash::Hash;


pub struct Name<'a>(&'a Path);


pub trait Writer {
    fn start_dir(&mut self, path: &Path) -> Result<(), Error>;
    fn add_file(&mut self, dir: &Arc<Dir>, entry: Entry) -> Result<(), Error>;
    fn add_symlink(&mut self, dir: &Arc<Dir>, entry: Entry)
        -> Result<(), Error>;
    fn done(&mut self) -> Result<(), Error>;
}

pub struct HashWriter<F, H> {
    file: F,
    digest: H,
}

pub struct SyncWriter<F, H: Hash> {
    file: HashWriter<F, H::Digest>,
    block_size: u64,
    hash: H,
}

impl<F: io::Write, H: Hash> Writer for SyncWriter<F, H> {
    fn start_dir(&mut self, path: &Path) -> Result<(), Error> {
        writeln!(&mut self.file, "{}", Name(path)).map_err(EWrite)?;
        Ok(())
    }
    fn add_file(&mut self, dir: &Arc<Dir>, entry: Entry)
        -> Result<(), Error>
    {
        let mut f = dir.open_file(&entry).map_err(EFile)?;
        let meta = f.metadata().map_err(EFile)?;
        let mut n = meta.len();
        write!(&mut self.file, "  {} f {}",
            Name(&Path::new(entry.file_name())),
            n,
        ).map_err(EWrite)?;
        while n > 0 {
            let h = self.hash.hash_file(&mut f, self.block_size)
                .map_err(EFile)?;
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
            Name(&Path::new(entry.file_name())),
            Name(&dest),
        ).map_err(EWrite)?;
        Ok(())
    }
    fn done(&mut self) -> Result<(), Error>
    {
        write!(&mut self.file.file, "{:x}\n",
            self.hash.total_hash(&self.file.digest)
        ).map_err(EFile)
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
            file: HashWriter { file: f, digest: hash.total_hasher() },
            block_size: block_size,
            hash: hash,
        })
    }
}

impl<F: io::Write, H: Digest> io::Write for HashWriter<F, H> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.digest.input(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl<'a> fmt::Display for Name<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::fmt::Write;

        for &b in self.0.as_os_str().as_bytes() {
            if b <= 0x20 || b >= 0x7F {
                write!(f, "\\x{:02x}", b)?;
            } else {
                f.write_char(b as char)?;
            }
        }
        Ok(())
    }
}
