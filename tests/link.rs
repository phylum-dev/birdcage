use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::TempDir;

#[test]
fn link() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test files.
    let source_dir = TempDir::new().unwrap();
    let dest_dir = TempDir::new().unwrap();
    let source_file = source_dir.path().join("file.txt");
    let dest_file = dest_dir.path().join("file.txt");
    fs::write(&source_file, FILE_CONTENT).unwrap();

    // Activate our sandbox.
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Read("/".into())).unwrap();
    birdcage.add_exception(Exception::Write("/".into())).unwrap();
    // birdcage.add_exception(Exception::Read(source_dir.path().into())).unwrap();
    // birdcage.add_exception(Exception::Write(source_dir.path().into())).unwrap();
    // birdcage.add_exception(Exception::Read(dest_dir.path().into())).unwrap();
    // birdcage.add_exception(Exception::Write(dest_dir.path().into())).unwrap();
    birdcage.lock().unwrap();

    // Access to the source file is allowed.
    let content = fs::read_to_string(&source_file).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Rename is allowed.
    fs::rename(&source_file, &dest_file).unwrap();

    // The renamed file contains the expected content.
    let content = fs::read_to_string(&dest_file).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
