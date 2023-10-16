use std::fs;
use std::os::unix::fs as unixfs;
use std::path::PathBuf;

use birdcage::error::Error;
use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::NamedTempFile;

fn main() {
    // Setup a symlink without target.
    let tempfile = NamedTempFile::new().unwrap();
    let tempfile_path = tempfile.path().to_path_buf();
    let symlink_str = tempfile_path.to_string_lossy() + "_tmpfile";
    let symlink = PathBuf::from(symlink_str.as_ref());
    unixfs::symlink(&tempfile, &symlink).unwrap();
    drop(tempfile);
    assert!(!tempfile_path.exists());

    // Sandbox exception fails with invalid path error.
    let mut birdcage = Birdcage::new();
    let result = birdcage.add_exception(Exception::Read(symlink.clone()));
    assert!(matches!(result, Err(Error::InvalidPath(_))));
    birdcage.lock().unwrap();

    // Read/Write results in error.
    let result = fs::read_to_string(&symlink);
    assert!(result.is_err());
    let result = fs::write(&symlink, "bob");
    assert!(result.is_err());
}
