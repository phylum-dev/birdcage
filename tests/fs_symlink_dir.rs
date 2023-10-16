use std::fs;
use std::os::unix::fs as unixfs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::TempDir;

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test directory.
    let tempdir = TempDir::new().unwrap();
    let symlink_str = tempdir.path().to_string_lossy() + "_tmpfile";
    let symlink_path = PathBuf::from(symlink_str.as_ref());
    unixfs::symlink(&tempdir, &symlink_path).unwrap();

    // Activate our sandbox.
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::WriteAndRead(symlink_path.clone())).unwrap();
    birdcage.lock().unwrap();

    // Try to create a file in the symlinked directory.
    let path = symlink_path.join("tmpfile");
    fs::write(&path, FILE_CONTENT.as_bytes()).unwrap();
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
