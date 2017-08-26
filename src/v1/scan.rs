use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::collections::VecDeque;

use openat::Dir;
use itertools::Itertools;

use {ScannerConfig, Error};
use Error::{OpenDir as EDir, ListDir as EList, ReadFile as ERead};
use super::writer::Writer;


fn find_roots(config: &ScannerConfig)
    -> Result<Vec<(Arc<Dir>, PathBuf)>, Error>
{
    let mut root = Vec::new();
    for &(ref path, ref prefix) in &config.dirs {
        if prefix == Path::new("/") {
            root.push((
                Arc::new(Dir::open(path).map_err(EDir)?),
                PathBuf::from("."),
            ));
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
    let mut queue = VecDeque::new();

    queue.push_back((PathBuf::from("/"), find_roots(config)?));

    while queue.len() > 0 {
        let (path, dirs) = queue.pop_front().unwrap();
        let mut subdirs = Vec::new();
        let mut files = Vec::new();
        for (base, name) in dirs {
            let dir = Arc::new(base.sub_dir(&name).map_err(EList)?);
            for entry in dir.list_dir(".").map_err(EList)? {
                let entry = entry.map_err(EList)?;
                let typ = match entry.simple_type() {
                    Some(x) => x,
                    None => dir.metadata(&entry).map_err(ERead)?.simple_type(),
                };
                match typ {
                    T::Dir => subdirs.push((dir.clone(), entry)),
                    T::Symlink => files.push((dir.clone(), entry, true)),
                    T::File => files.push((dir.clone(), entry, false)),
                    T::Other => {
                        let base = dir.recover_path()
                            // if recover fails, use destination path
                            // this is better than nothing anyway
                            .unwrap_or(path.clone());
                        warn!("File {:?} has unknown type, ignoring",
                            base.join(entry.file_name()));
                    }
                }
            }
        }
        files.sort_by(|&(_, ref a, _), &(_, ref b, _)| {
            a.file_name().cmp(&b.file_name())
        });
        index.start_dir(&path)?;
        for (dir, entry, is_symlink) in files {
            // TODO(tailhook) deduplicate!
            if is_symlink {
                index.add_symlink(&dir, entry)?;
            } else {
                index.add_file(&dir, entry)?;
            }
        }
        subdirs.sort_by(|&(_, ref a), &(_, ref b)| {
            b.file_name().cmp(&a.file_name())  // note: reverse sort
        });
        for (dirpath, seq) in subdirs.into_iter()
            .group_by(|&(_, ref e)| path.join(e.file_name())).into_iter()
        {
            // TODO(tailhook) deduplicate! (kinda)
            queue.push_front((
                dirpath,
                seq.map(|(base, entry)|{
                    (base, Path::new(entry.file_name()).to_path_buf())
                }).collect()
            ));
        }
    }
    index.done()?;
    Ok(())
}
