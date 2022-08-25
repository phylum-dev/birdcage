//! Example of a full sandbox, allowing no outside access.

use std::fs;

use birdcage::{Birdcage, Sandbox};
use tempfile::NamedTempFile;

fn main() {
    // Setup our test file.
    let file = NamedTempFile::new().unwrap();

    // Reads without sandbox work.
    fs::read_to_string(file.path()).unwrap();

    // Initialize the sandbox; by default everything is prohibited.
    Birdcage::new().unwrap().lock().unwrap();

    // Reads with sandbox should fail.
    let result = fs::read_to_string(file.path());
    assert!(result.is_err());
}
