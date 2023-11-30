use std::fs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};

use crate::TestSetup;

const FILE_CONTENT: &str = "expected content";

#[derive(Serialize, Deserialize)]
struct TestData {
    public_path: PathBuf,
    private_path: PathBuf,
}

pub fn setup(tempdir: PathBuf) -> TestSetup {
    // Setup our test files.
    let private_path = tempdir.join("private");
    fs::write(&private_path, FILE_CONTENT.as_bytes()).unwrap();
    let public_path = tempdir.join("public");
    fs::write(&public_path, FILE_CONTENT.as_bytes()).unwrap();

    // Setup sandbox exceptions.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::Read(public_path.clone())).unwrap();

    // Serialize test data.
    let data = TestData { public_path, private_path };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Access to the public file is allowed.
    let content = fs::read_to_string(data.public_path).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Access to the private file is prohibited.
    let result = fs::read_to_string(data.private_path);
    assert!(result.is_err());
}
