use std::fs;
use std::os::unix::fs as unixfs;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::TempDir;

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test directories.
    let tempdir = TempDir::new().unwrap().into_path();
    let symlink_src = tempdir.join("src");
    fs::create_dir(&symlink_src).unwrap();
    let symlink_dst = tempdir.join("dst");
    unixfs::symlink(&symlink_src, &symlink_dst).unwrap();

    // Add read+write for src, but also add readonly for dst.
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::WriteAndRead(symlink_src.clone())).unwrap();
    birdcage.add_exception(Exception::Read(symlink_dst.clone())).unwrap();
    birdcage.lock().unwrap();

    // Ensure writing works.
    let testfile = symlink_src.join("file");
    fs::write(&testfile, FILE_CONTENT).unwrap();

    // Ensure reading works.
    let content = fs::read_to_string(&testfile).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
