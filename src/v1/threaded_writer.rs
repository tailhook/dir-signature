use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;

use futures::{Async, Future, executor};
use openat::{Dir, Entry};
use futures_cpupool::{CpuPool, CpuFuture};

use error::Error::{self, WriteError as EWrite, ReadFile as EFile};
use v1::writer::{Writer, HashWriter, Name, EXE_MASK, MAGIC, VERSION};
use v1::hash::Hash;

#[derive(Clone)]
struct Notify;

struct FileEntry {
    file_name: PathBuf,
    exe: bool,
    size: u64,
    hashes: String,
}

enum Operation {
    StartDir(PathBuf),
    File(CpuFuture<FileEntry, Error>),
    Symlink(Arc<Dir>, Entry),
}

pub struct ThreadedWriter<F, H: Hash> {
    pool: CpuPool,
    file: HashWriter<F, H>,
    block_size: u64,
    hash: H,
    queue_limit: usize,
    queue: VecDeque<Operation>,
}

impl<F: io::Write, H: Hash> ThreadedWriter<F, H> {
    pub fn new(threads: usize, mut f: F, hash: H, block_size: u64)
        -> Result<ThreadedWriter<F, H>, Error>
    {
        writeln!(&mut f,
            "{}.{} {} block_size={}",
            MAGIC,
            VERSION,
            hash.name(),
            block_size,
        ).map_err(EWrite)?;
        Ok(ThreadedWriter {
            file: HashWriter { file: f, digest: hash.clone() },
            block_size: block_size,
            hash: hash,
            queue_limit: threads*16,
            queue: VecDeque::with_capacity(threads*16),
            pool: CpuPool::new(threads),
        })
    }
    fn poll_item(&mut self, item: Operation, blocking: bool)
        -> Result<bool, Error>
    {
        match item {
            Operation::StartDir(ref path) => {
                writeln!(&mut self.file, "{}", Name(path))
                    .map_err(EWrite)?;
            }
            Operation::File(mut fut) => {
                let entry = if blocking {
                        fut.wait()?
                    } else {
                        let r = executor::spawn(&mut fut)
                            .poll_future_notify(&&Notify, 0);
                        match r? {
                            Async::Ready(entry) => entry,
                            Async::NotReady => {
                                self.queue.push_front(Operation::File(fut));
                                return Ok(false);
                            }
                        }
                    };

                write!(&mut self.file, "  {} {} {}{}\n",
                    Name(&entry.file_name),
                    if entry.exe { "x" } else { "f" },
                    entry.size,
                    entry.hashes,  // includes space
                ).map_err(EWrite)?;
            }
            Operation::Symlink(dir, entry) => {
                let dest = dir.read_link(&entry).map_err(EFile)?;
                write!(&mut self.file, "  {} s {}\n",
                    Name(&Path::new(entry.file_name())),
                    Name(&dest),
                ).map_err(EWrite)?;
            }
        }
        return Ok(true);
    }
    fn poll_queue(&mut self) -> Result<(), Error> {
        while let Some(item) = self.queue.pop_front() {
            let want_block = self.queue.len() >= self.queue_limit;
            if !self.poll_item(item, want_block)? {
                break;
            }
        }
        Ok(())
    }
    // TODO(tailhook) deduplicate code
    fn wait_queue(&mut self) -> Result<(), Error> {
        while let Some(item) = self.queue.pop_front() {
            self.poll_item(item, true)?;
        }
        Ok(())
    }
}

impl<F: io::Write, H: Hash> Writer for ThreadedWriter<F, H> {
    type TotalHash = H::Output;
    fn start_dir(&mut self, path: &Path) -> Result<(), Error> {
        // TODO(tailhook) optimize allocation if no queue is present
        self.queue.push_back(Operation::StartDir(path.to_path_buf()));
        self.poll_queue()
    }
    fn add_file(&mut self, dir: &Arc<Dir>, entry: Entry)
        -> Result<(), Error>
    {
        use std::fmt::Write;
        let dir = dir.clone();
        let block_size = self.block_size;
        let mut hash = self.hash.clone();
        self.queue.push_back(Operation::File(self.pool.spawn_fn(move || {
            let mut f = dir.open_file(&entry).map_err(EFile)?;
            let meta = f.metadata().map_err(EFile)?;
            let mut n = meta.len();
            let mut buf = String::with_capacity((33*n/block_size) as usize);
            while n > 0 {
                let h = hash.hash_file(&mut f, block_size).map_err(EFile)?;
                write!(&mut buf, " {:x}", h).unwrap();
                n = n.saturating_sub(block_size);
            }
            Ok(FileEntry {
                file_name: Path::new(entry.file_name()).to_path_buf(),
                exe: meta.permissions().mode() & EXE_MASK > 0,
                size: meta.len(),
                hashes: buf,
            })
        })));
        self.poll_queue()
    }
    fn add_symlink(&mut self, dir: &Arc<Dir>, entry: Entry)
        -> Result<(), Error>
    {
        // TODO(tailhook) optimize allocation if no queue is present
        self.queue.push_back(Operation::Symlink(dir.clone(), entry));
        self.poll_queue()
    }
    fn get_hash(&mut self) -> Result<Self::TotalHash, Error> {
        self.wait_queue()?;
        Ok(self.file.digest.total_hash())
    }
    fn done(mut self) -> Result<(), Error>
    {
        let hash = self.get_hash()?;
        write!(&mut self.file.file, "{:x}\n", hash).map_err(EFile)
    }
}

impl executor::Notify for Notify {
    fn notify(&self, _: usize) {
        // nothing to notify, it's fine, we'll just poll when needed
    }
}
