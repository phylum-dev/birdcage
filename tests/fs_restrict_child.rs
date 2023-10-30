use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test tree.
    let tempdir = tempfile::tempdir().unwrap().into_path();
    let tempfile = tempdir.join("target-file");
    fs::write(&tempfile, FILE_CONTENT.as_bytes()).unwrap();

    // Setup sandbox, allowing read/write to dir, but only read for the file.
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::WriteAndRead(tempdir.clone())).unwrap();
    birdcage.add_exception(Exception::Read(tempfile.clone())).unwrap();
    birdcage.lock().unwrap();

    // Write access to directory works.
    fs::create_dir(tempdir.join("boop")).unwrap();

    // Read access to file works.
    let content = fs::read_to_string(&tempfile).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Write access to file is denied.
    let result = fs::write(&tempfile, "no");
    assert!(result.is_err());
}
