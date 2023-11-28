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
    // Setup the test file.
    let file = NamedTempFile::new().unwrap().into_temp_path().keep().unwrap();
    fs::write(&file, FILE_CONTENT.as_bytes()).unwrap();

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::Read(file.clone())).unwrap();

    // Serialize test data.
    let data = TestData { file };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Reading from the file is allowed.
    let content = fs::read_to_string(&data.file).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Writing to the file is prohibited.
    let result = fs::write(&data.file, FILE_CONTENT.as_bytes());
    assert!(result.is_err());
}
