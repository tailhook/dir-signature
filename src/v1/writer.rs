use std::fmt;
use std::io::{self, Write};
use std::ops::Add;
use std::sync::Arc;
use std::path::Path;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;


use sha2::Digest;
use openat::{Dir, Entry};
use generic_array::ArrayLength;

use error::Error::{self, WriteError as EWrite, ReadFile as EFile};
use super::hash::Hash;


struct Name<'a>(&'a Path);

const EXE_MASK: u32 = 0o100;

pub const MAGIC: &'static str = "DIRSIGNATURE";
pub const VERSION: &'static str = "v1";


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

impl<F, H> Writer for SyncWriter<F, H>
    where F: io::Write,
          H: Hash,
          <H::OutputSize as Add>::Output: ArrayLength<u8>
{
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
        write!(&mut self.file, "  {} {} {}",
            Name(&Path::new(entry.file_name())),
            if meta.permissions().mode() & EXE_MASK > 0 { "x" } else { "f" },
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
            "{}.{} {} block_size={}",
            MAGIC,
            VERSION,
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
            if b <= 0x20 || b >= 0x7F || b == b'\\' {
                write!(f, "\\x{:02x}", b)?;
            } else {
                f.write_char(b as char)?;
            }
        }
        Ok(())
    }
}

#[test]
fn test_escapes() {
    assert_eq!(&format!("{}", Name(Path::new("a\x05b"))),
               r"a\x05b");
    assert_eq!(&format!("{}", Name(Path::new("a\\x05b"))),
               r"a\x5cx05b");
}
