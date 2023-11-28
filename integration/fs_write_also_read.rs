use std::fs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::TestSetup;

const FILE_CONTENT: &str = "expected content";

#[derive(Serialize, Deserialize)]
struct TestData {
    file: PathBuf,
}

pub fn setup() -> TestSetup {
    // Setup our test files.
    let file = NamedTempFile::new().unwrap().into_temp_path().keep().unwrap();

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::WriteAndRead(file.clone())).unwrap();

    // Serialize test data.
    let data = TestData { file };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Write access is allowed.
    fs::write(&data.file, FILE_CONTENT.as_bytes()).unwrap();

    // Read access is allowed.
    let content = fs::read_to_string(data.file).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
