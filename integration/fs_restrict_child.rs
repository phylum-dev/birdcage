use std::fs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};

use crate::TestSetup;

const FILE_CONTENT: &str = "expected content";

#[derive(Serialize, Deserialize)]
struct TestData {
    tempfile: PathBuf,
    tempdir: PathBuf,
}

pub fn setup(tempdir: PathBuf) -> TestSetup {
    // Setup our test tree.
    let tempfile = tempdir.join("target-file");
    fs::write(&tempfile, FILE_CONTENT.as_bytes()).unwrap();

    // Setup sandbox, allowing read/write to dir, but only read for the file.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::WriteAndRead(tempdir.clone())).unwrap();
    sandbox.add_exception(Exception::Read(tempfile.clone())).unwrap();

    // Serialize test data.
    let data = TestData { tempfile, tempdir };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Write access to directory works.
    fs::create_dir(data.tempdir.join("boop")).unwrap();

    // Read access to file works.
    let content = fs::read_to_string(&data.tempfile).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Write access to file is denied.
    let result = fs::write(&data.tempfile, "no");
    assert!(result.is_err());
}
