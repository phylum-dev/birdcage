use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::NamedTempFile;

#[test]
fn partial_fs() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test files.
    let private_path = NamedTempFile::new().unwrap();
    fs::write(&private_path, FILE_CONTENT.as_bytes()).unwrap();
    let public_path = NamedTempFile::new().unwrap();
    fs::write(&public_path, FILE_CONTENT.as_bytes()).unwrap();

    // Activate our sandbox.
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Read(public_path.path().into())).unwrap();
    birdcage.lock().unwrap();

    // Access to the public file is allowed.
    let content = fs::read_to_string(public_path).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Access to the private file is prohibited.
    let result = fs::read_to_string(private_path);
    assert!(result.is_err());
}
