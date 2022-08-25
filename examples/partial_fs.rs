//! Example of a partial filesystem sandbox.

use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::NamedTempFile;

fn main() {
    // Setup our test files.
    let private_file = NamedTempFile::new().unwrap();
    let public_file = NamedTempFile::new().unwrap();

    // Initialize the sandbox; by default everything is prohibited.
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Read(public_file.path().into())).unwrap();
    birdcage.lock().unwrap();

    // Access to the public file is allowed.
    fs::read_to_string(public_file).unwrap();

    // Access to the private file is prohibited.
    let result = fs::read_to_string(private_file);
    assert!(result.is_err());
}
