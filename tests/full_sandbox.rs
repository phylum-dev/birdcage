use std::fs;
use std::io::Write;

use birdcage::{Birdcage, Sandbox};
use tempfile::NamedTempFile;

#[test]
fn full_sandbox() {
    const FILE_CONTENT: &str = "expected content";

    // Create testfile.
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(FILE_CONTENT.as_bytes()).unwrap();

    // Ensure non-sandboxed read works.
    let content = fs::read_to_string(file.path()).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Activate our sandbox.
    Birdcage::new().unwrap().lock().unwrap();

    // Ensure sandboxed read is blocked.
    let result = fs::read_to_string(file.path());
    assert!(result.is_err());
}
