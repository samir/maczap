//! One maczap run at a time (DESIGN §5.2): an advisory `flock` on a file in the
//! state directory, released when the process exits.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

use rustix::fs::{FlockOperation, flock};

#[derive(Debug)]
pub struct Lock {
    _file: File,
}

impl Lock {
    pub fn acquire(state_dir: &Path) -> io::Result<Lock> {
        fs::create_dir_all(state_dir)?;
        let path = state_dir.join("lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Lock { _file: file }),
            Err(rustix::io::Errno::WOULDBLOCK) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another maczap run is in progress",
            )),
            Err(e) => Err(e.into()),
        }
    }
}
