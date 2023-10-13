use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::NamedTempFile;

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test files.
    let file = NamedTempFile::new().unwrap();

    // Activate our sandbox.
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::WriteAndRead(file.path().into())).unwrap();
    birdcage.lock().unwrap();

    // Write access is allowed.
    fs::write(&file, FILE_CONTENT.as_bytes()).unwrap();

    // Read access is allowed.
    let content = fs::read_to_string(file).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
