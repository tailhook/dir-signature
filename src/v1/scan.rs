use std::path::{Path, PathBuf};
use std::sync::Arc;

use openat::Dir;

use {ScannerConfig, Error};
use Error::{OpenDir as EDir, ListDir as EList};
use super::writer::Writer;


fn find_roots(config: &ScannerConfig) -> Result<Vec<Arc<Dir>>, Error> {
    let mut root = Vec::new();
    for &(ref path, ref prefix) in &config.dirs {
        if prefix == Path::new("/") {
            let path: &Path = path;  // TODO(tailhook until openat() updated
            root.push(Arc::new(Dir::open(path).map_err(EDir)?));
        }
    }
    if root.len() == 0 {
        return Err(Error::NoRootDirectory);
    }
    return Ok(root);
}

pub fn scan<W: Writer>(config: &ScannerConfig, index: &mut W)
    -> Result<(), Error>
{
    use openat::SimpleType as T;
    let mut stack = Vec::new();
    let mut path = PathBuf::from("/");

    stack.push(find_roots(config)?);

    while stack.len() > 0 {
        let dirs = stack.pop().unwrap();
        let mut subdirs = Vec::new();
        let mut files = Vec::new();
        for dir in dirs {
            for entry in dir.list_dir(".").map_err(EList)? {
                let entry = entry.map_err(EList)?;
                let typ = match entry.simple_type() {
                    Some(x) => x,
                    None => unimplemented!(),  // implement Dir::stat ?
                };
                match typ {
                    T::Dir => subdirs.push((dir.clone(), entry)),
                    T::Symlink | T::File => files.push((dir.clone(), entry)),
                    T::Other => {
                        warn!("File {:?} has unknown type, ignoring",
                            // TODO(tailhook) show source file, not dest?
                            path.join(entry.file_name()));
                    }
                }
            }
        }
        files.sort_by(|&(_, ref a), &(_, ref b)| {
            a.file_name().cmp(&b.file_name())
        });
        index.start_dir(&path)?;
        for (dir, entry) in files {
            // TODO(tailhook) deduplicate!
            index.add_file(&dir, entry)?;
        }
        subdirs.sort_by(|&(_, ref a), &(_, ref b)| {
            a.file_name().cmp(&b.file_name())
        });
        println!("Dirs {:?}", subdirs);
    }

    unimplemented!();
}
