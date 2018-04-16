use std::io::{self, Write};
use std::ffi::OsStr;
use std::path::Path;

use sha2::{self, Digest};
use blake2::{Blake2b, digest::VariableOutput};

use {HashType, HashTypeEnum};
use v1::writer::{MAGIC, VERSION, Name};
use v1::parser::{Hashes, Hexlified};

/// A non-validating emitter of v1 index files
///
/// Note: emitter doesn't verify that output is correct. In particular,
/// user is responsible that entries are written in file are
/// in the correct order.
pub struct Emitter<'a> {
    out: HashWriter<'a>
}

pub(crate) struct HashWriter<'a> {
    out: &'a mut Write,
    hash: Box<HashTrait>,
}

/// Object-safe version of hash trait
trait HashTrait {
    fn input(&mut self, data: &[u8]);
    fn write_hash(&mut self, out: &mut Write) -> io::Result<()>;
}

impl<'a> Emitter<'a> {
    /// Create a new emitter and write a header
    ///
    /// The Write implementation here should preferably be a buffered writer.
    pub fn new<'x>(hash_type: HashType, block_size: u64, dest: &'x mut Write)
        -> io::Result<Emitter<'x>>
    {
        let hash = match hash_type.0 {
            HashTypeEnum::Sha512_256 => {
                Box::new(sha2::Sha512Trunc256::new())
                as Box<HashTrait>
            }
            HashTypeEnum::Blake2b_256 => {
                Box::new(<Blake2b as VariableOutput>::new(32)
                         .expect("Valid length"))
                as Box<HashTrait>
            }
        };
        writeln!(dest,
            "{}.{} {} block_size={}",
            MAGIC, VERSION, hash_type, block_size,
        )?;
        Ok(Emitter {
            out: HashWriter {
                out: dest,
                hash,
            },
        })
    }

    /// Start a directory
    ///
    /// Note: you must ensure that directories are sorted from child to parent,
    /// alphabetically sorted within the same parent and always come after
    /// files.
    ///
    /// The only reason this method may fail is when it failed to write to the
    /// underlying buffer.
    ///
    /// # Panics
    ///
    /// If directory is not absolute
    pub fn start_dir(&mut self, path: &Path) -> io::Result<()> {
        writeln!(self.out, "{}", Name(path))?;
        Ok(())
    }

    /// Add a file
    ///
    /// Note: you must ensure that files within the directory are sorted and
    /// come before the directories.
    ///
    /// The only reason this method may fail is when it failed to write to the
    /// underlying buffer.
    pub fn add_file(&mut self, name: &OsStr, executable: bool, size: u64,
        hashes: &Hashes)
        -> io::Result<()>
    {
        write!(self.out, "  {} {} {}",
            Name(&Path::new(name)),
            if executable { "x" } else { "f" },
            size,
        )?;
        for item in hashes.hex_iter() {
            write!(self.out, " {:x}", item)?;
        }
        self.out.write_all(b"\n")?;
        Ok(())
    }

    /// Add a symlink
    ///
    /// Note: symlinks are sorted together with files.
    ///
    /// The only reason this method may fail is when it failed to write to the
    /// underlying buffer.
    pub fn add_symlink(&mut self, name: &OsStr, dest: &Path)
        -> io::Result<()>
    {
        write!(self.out, "  {} s {}\n",
            Name(&Path::new(name)),
            Name(dest),
        )?;
        Ok(())
    }

    /// Write the final line of the image
    ///
    /// It's the expected that nothing will be called after this method
    pub fn finish(&mut self) -> io::Result<()> {
        self.out.hash.write_hash(self.out.out)?;
        Ok(())
    }
}

impl HashTrait for sha2::Sha512Trunc256 {
    fn input(&mut self, data:&[u8]) {
        Digest::input(self, data);
    }
    fn write_hash(&mut self, out: &mut Write) -> io::Result<()> {
        writeln!(out, "{:x}", Hexlified(self.clone().result().as_ref()))
    }
}

impl HashTrait for Blake2b {
    fn input(&mut self, data:&[u8]) {
        Digest::input(self, data);
    }
    fn write_hash(&mut self, out: &mut Write) -> io::Result<()> {
        let mut val = [0u8; 32];
        self.clone().variable_result(&mut val).expect("valid length");
        writeln!(out, "{:x}", Hexlified(&val))
    }
}

impl<'a> io::Write for HashWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.hash.input(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod test {
    use v1::emitter::Emitter;
    use v1::parser::Hashes;
    use ::HashType;
    use std::path::Path;

    #[test]
    fn test1() {
        let mut buf = Vec::with_capacity(4096);
        {
            let mut e = Emitter::new(HashType::sha512_256(), 32768, &mut buf)
                .unwrap();
            e.start_dir(Path::new("/")).unwrap();
            e.add_file(Path::new("hello.txt").as_os_str(), false, 6,
                &Hashes::from_hex(
                "a79eef66019bfb9a41f798f2cff2d2d36ed294cc3f96bf53bbfc5192ebe60192",
                HashType::sha512_256(), 1, 32768)
            ).unwrap();
            e.add_file(Path::new("test.txt").as_os_str(), false, 0,
                &Hashes::from_hex("", HashType::sha512_256(), 0, 32768)
            ).unwrap();
            e.start_dir(&Path::new("/subdir")).unwrap();
            e.add_file(Path::new(".hidden").as_os_str(), false, 7,
                &Hashes::from_hex(
                "6d7f5f9804ee4dbc1ff7e12c7665387e0119e8ea629996c52d38b75c12ad0acf",
                HashType::sha512_256(), 1, 32768)
            ).unwrap();
            e.add_file(Path::new("file.txt").as_os_str(), false, 10,
                &Hashes::from_hex(
                "0119865c765e02554f6fc5a06fa76aa92c590c09225775c092144079f9964899",
                HashType::sha512_256(), 1, 32768)
            ).unwrap();
            e.finish().unwrap();
        }
        assert_eq!(String::from_utf8(buf).unwrap(), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  hello.txt f 6 a79eef66019bfb9a41f798f2cff2d2d36ed294cc3f96bf53bbfc5192ebe60192
  test.txt f 0
/subdir
  .hidden f 7 6d7f5f9804ee4dbc1ff7e12c7665387e0119e8ea629996c52d38b75c12ad0acf
  file.txt f 10 0119865c765e02554f6fc5a06fa76aa92c590c09225775c092144079f9964899
552ca5730ee95727e890a2155c88609d244624034ff70de264cf88220d11d6df
");
    }
}
