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
    symlink_src: PathBuf,
}

pub fn setup() -> TestSetup {
    // Setup our test directories.
    let tempdir = TempDir::new().unwrap().into_path();
    let symlink_src = tempdir.join("src");
    fs::create_dir(&symlink_src).unwrap();
    let symlink_dst = tempdir.join("dst");
    unixfs::symlink(&symlink_src, &symlink_dst).unwrap();

    // Add read+write for src, but also add readonly for dst.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::WriteAndRead(symlink_src.clone())).unwrap();
    sandbox.add_exception(Exception::Read(symlink_dst.clone())).unwrap();

    // Serialize test data.
    let data = TestData { symlink_src };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Ensure writing works.
    let testfile = data.symlink_src.join("file");
    fs::write(&testfile, FILE_CONTENT).unwrap();

    // Ensure reading works.
    let content = fs::read_to_string(&testfile).unwrap();
    assert_eq!(content, FILE_CONTENT);
}
