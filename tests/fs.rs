use std::fs;
use std::io::Write;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::NamedTempFile;

#[test]
fn partial_fs() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test files.
    let mut private_file = NamedTempFile::new().unwrap();
    private_file.write_all(FILE_CONTENT.as_bytes()).unwrap();
    let mut public_file = NamedTempFile::new().unwrap();
    public_file.write_all(FILE_CONTENT.as_bytes()).unwrap();

    // Activate our sandbox.
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Read(public_file.path().into())).unwrap();
    birdcage.lock().unwrap();

    // Access to the public file is allowed.
    let content = fs::read_to_string(public_file).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Access to the private file is prohibited.
    let result = fs::read_to_string(private_file);
    assert!(result.is_err());
}
