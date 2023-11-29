use std::fs;
use std::os::unix::fs as unixfs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::TestSetup;

const FILE_CONTENT: &str = "expected content";

#[derive(Serialize, Deserialize)]
struct TestData {
    symlink_path: PathBuf,
}

pub fn setup() -> TestSetup {
    // Setup our test directory.
    let tempdir = TempDir::new().unwrap().into_path();
    let symlink_str = tempdir.to_string_lossy() + "_tmpfile";
    let symlink_path = PathBuf::from(symlink_str.as_ref());
    unixfs::symlink(&tempdir, &symlink_path).unwrap();

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::WriteAndRead(symlink_path.clone())).unwrap();

    // Serialize test data.
    let data = TestData { symlink_path };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Try to create a file in the symlinked directory.
    let path = data.symlink_path.join("tmpfile");
    fs::write(&path, FILE_CONTENT.as_bytes()).unwrap();
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
