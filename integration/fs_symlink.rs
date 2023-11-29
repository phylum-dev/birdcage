use std::fs;
use std::os::unix::fs as unixfs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::TestSetup;

const FILE_CONTENT: &str = "expected content";

#[derive(Serialize, Deserialize)]
struct TestData {
    private: PathBuf,
    public: PathBuf,
}

pub fn setup() -> TestSetup {
    // Setup our test files.
    let private_path = NamedTempFile::new().unwrap().into_temp_path().keep().unwrap();
    fs::write(&private_path, FILE_CONTENT.as_bytes()).unwrap();
    let public_path = NamedTempFile::new().unwrap().into_temp_path().keep().unwrap();
    fs::write(&public_path, FILE_CONTENT.as_bytes()).unwrap();

    // Create symlinks for the files.
    let private_str = private_path.to_string_lossy() + "_tmpfile";
    let private = PathBuf::from(private_str.as_ref());
    let public_str = public_path.to_string_lossy() + "_tmpfile";
    let public = PathBuf::from(public_str.as_ref());
    unixfs::symlink(&private_path, &private).unwrap();
    unixfs::symlink(&public_path, &public).unwrap();

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::Read(public.clone())).unwrap();

    // Serialize test data.
    let data = TestData { private, public };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Access to the public file is allowed.
    let content = fs::read_to_string(&data.public).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Access to the private file is prohibited.
    let result = fs::read_to_string(&data.private);
    assert!(result.is_err());
}
