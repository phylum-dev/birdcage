use std::fs::{self, File};
use std::os::unix::fs as unixfs;
use std::path::PathBuf;

use birdcage::error::Error;
use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};

use crate::TestSetup;

#[derive(Serialize, Deserialize)]
struct TestData {
    symlink: PathBuf,
}

pub fn setup(tempdir: PathBuf) -> TestSetup {
    // Create a target for the symlink.
    let tempfile_path = tempdir.join("broken_target");
    File::create(&tempfile_path).unwrap();

    // Setup a symlink to the target file.
    let symlink_str = tempfile_path.to_string_lossy() + "_symlink";
    let symlink = PathBuf::from(symlink_str.as_ref());
    unixfs::symlink(&tempfile_path, &symlink).unwrap();

    // Remove the target, breaking the symlink.
    fs::remove_file(&tempfile_path).unwrap();
    assert!(!tempfile_path.exists());

    // Sandbox exception fails with invalid path error.
    let mut sandbox = Birdcage::new();
    let result = sandbox.add_exception(Exception::Read(symlink.clone()));
    assert!(matches!(result, Err(Error::InvalidPath(_))));

    // Serialize test data.
    let data = TestData { symlink };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Read/Write results in error.
    let result = fs::read_to_string(&data.symlink);
    assert!(result.is_err());
    let result = fs::write(&data.symlink, "bob");
    assert!(result.is_err());
}
