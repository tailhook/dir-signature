use std::io;
use std::sync::Arc;
use std::path::Path;
use std::time::{Instant, Duration};

use super::writer::Writer;
use openat::{Dir, Entry};
use {Error};


pub struct Progress<W, S> {
    dest: W,
    progress_dest: S,
    last_print: Instant,
    files: u64,
    dirs: u64,
    symlinks: u64,
    started: Instant,
}

fn duration_float(d: Duration) -> f64 {
    d.as_secs() as f64 + d.subsec_nanos() as f64 / 1_000_000_000.
}

impl<W: Writer, S: io::Write> Progress<W, S> {
    pub fn new(out: S, hasher: W) -> Progress<W, S> {
        Progress {
            dest: hasher,
            progress_dest: out,
            last_print: Instant::now(),
            files: 0,
            dirs: 0,
            symlinks: 0,
            started: Instant::now(),
        }
    }
    pub fn check_print(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_print) > Duration::from_millis(100) {
            self.last_print = now;
            write!(&mut self.progress_dest,
                "Indexing... {} dirs, {} files, {} symlinks\r",
                self.dirs, self.files, self.symlinks).ok();
            self.progress_dest.flush().ok();
        }
    }
}


impl<W: Writer, S: io::Write> Writer for Progress<W, S>
    where W::TotalHash: ::std::fmt::LowerHex,
{
    type TotalHash = W::TotalHash;
    fn start_dir(&mut self, path: &Path) -> Result<(), Error> {
        self.dirs += 1;
        self.dest.start_dir(path)?;
        self.check_print();
        Ok(())
    }
    fn add_file(&mut self, dir: &Arc<Dir>, entry: Entry) -> Result<(), Error> {
        self.files += 1;
        self.dest.add_file(dir, entry)?;
        self.check_print();
        Ok(())
    }
    fn add_symlink(&mut self, dir: &Arc<Dir>, entry: Entry)
        -> Result<(), Error>
    {
        self.symlinks += 1;
        self.dest.add_symlink(dir, entry)?;
        self.check_print();
        Ok(())
    }
    fn get_hash(&mut self) -> Result<Self::TotalHash, Error> {
        self.dest.get_hash()
    }
    fn done(mut self) -> Result<(), Error> {
        let hash = self.get_hash()?;
        self.dest.done()?;
        write!(&mut self.progress_dest,
            "Done {:.8x}. Indexed {} dirs, \
             {} files, {} symlinks in {:.3} sec.\n",
            hash, self.dirs, self.files, self.symlinks,
            duration_float(Instant::now().duration_since(self.started)),
            ).ok();
        self.progress_dest.flush().ok();
        Ok(())
    }
}

