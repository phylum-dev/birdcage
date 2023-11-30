use std::fs::{self, File};
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};

use crate::TestSetup;

const FILE_CONTENT: &str = "expected content";

#[derive(Serialize, Deserialize)]
struct TestData {
    path: PathBuf,
}

pub fn setup(tempdir: PathBuf) -> TestSetup {
    // Setup our test files.
    let path = tempdir.join("fs_write_also_read");
    File::create(&path).unwrap();

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::WriteAndRead(path.clone())).unwrap();

    // Serialize test data.
    let data = TestData { path };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Write access is allowed.
    fs::write(&data.path, FILE_CONTENT.as_bytes()).unwrap();

    // Read access is allowed.
    let content = fs::read_to_string(data.path).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
