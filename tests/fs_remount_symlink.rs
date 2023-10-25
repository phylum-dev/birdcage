use std::fs;
use std::os::unix::fs as unixfs;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test tree.

    let root = tempfile::tempdir().unwrap().into_path();

    let lib = root.join("usr").join("lib");
    fs::create_dir_all(&lib).unwrap();
    let file = lib.join("os-release");

    let etc = root.join("etc");
    fs::create_dir(&etc).unwrap();
    fs::write(&file, FILE_CONTENT.as_bytes()).unwrap();
    let symlink = etc.join("os-release");
    unixfs::symlink("../usr/lib/os-release", &symlink).unwrap();

    // Setup sandbox, ensuring sandbox can be created.
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::Read(etc.clone())).unwrap();
    birdcage.add_exception(Exception::Read(symlink.clone())).unwrap();
    birdcage.lock().unwrap();

    // Ensure we can read from the symlink.
    let content = fs::read_to_string(symlink).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
