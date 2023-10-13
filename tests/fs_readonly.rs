use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::NamedTempFile;

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Setup the test file.
    let file = NamedTempFile::new().unwrap();
    fs::write(&file, FILE_CONTENT.as_bytes()).unwrap();

    // Activate our sandbox.
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::Read(file.path().into())).unwrap();
    birdcage.lock().unwrap();

    // Reading from the file is allowed.
    let content = fs::read_to_string(&file).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Writing to the file is prohibited.
    let result = fs::write(&file, FILE_CONTENT.as_bytes());
    assert!(result.is_err());
}
