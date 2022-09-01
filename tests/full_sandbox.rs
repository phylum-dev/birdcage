use std::fs;

use birdcage::{Birdcage, Sandbox};
use tempfile::NamedTempFile;

#[test]
fn full_sandbox() {
    const FILE_CONTENT: &str = "expected content";

    // Create testfile.
    let path = fs::canonicalize(NamedTempFile::new().unwrap()).unwrap();

    // Ensure non-sandboxed write works.
    fs::write(&path, FILE_CONTENT.as_bytes()).unwrap();

    // Ensure non-sandboxed read works.
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Activate our sandbox.
    Birdcage::new().unwrap().lock().unwrap();

    // Ensure sandboxed write is blocked.
    let result = fs::write(&path, b"x");
    assert!(result.is_err());

    // Ensure sandboxed read is blocked.
    let result = fs::read_to_string(path);
    assert!(result.is_err());
}
