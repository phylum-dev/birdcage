use std::fs;
use std::os::unix::fs as unixfs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};

use crate::TestSetup;

const FILE_CONTENT: &str = "expected content";

#[derive(Serialize, Deserialize)]
struct TestData {
    symlink: PathBuf,
}

pub fn setup(tempdir: PathBuf) -> TestSetup {
    // Setup our test directory.
    let symlink_target = tempdir.join("target");
    fs::create_dir(symlink_target).unwrap();
    let symlink = tempdir.join("symlink");
    unixfs::symlink(&tempdir, &symlink).unwrap();

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::WriteAndRead(symlink.clone())).unwrap();

    // Serialize test data.
    let data = TestData { symlink };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Try to create a file in the symlinked directory.
    let path = data.symlink.join("tmpfile");
    fs::write(&path, FILE_CONTENT.as_bytes()).unwrap();
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
