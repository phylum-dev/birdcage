use std::fs;
use std::os::unix::fs as unixfs;
use std::path::PathBuf;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};
use serde::{Deserialize, Serialize};

use crate::TestSetup;

#[derive(Serialize, Deserialize)]
struct TestData {
    symlink_exec: PathBuf,
}

pub fn setup() -> TestSetup {
    // Create symlinked executable.
    let tempdir = tempfile::tempdir().unwrap().into_path();
    let exec_dir = tempdir.join("bin");
    fs::create_dir(&exec_dir).unwrap();
    let symlink_exec = exec_dir.join("true");
    unixfs::symlink("/usr/bin/true", &symlink_exec).unwrap();

    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::ExecuteAndRead(symlink_exec.clone())).unwrap();

    // Serialize test data.
    let data = TestData { symlink_exec };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    // Ensure symlinked executable works.
    let cmd = Command::new(data.symlink_exec).status().unwrap();
    assert!(cmd.success());

    // Ensure original executable works.
    let cmd = Command::new("/usr/bin/true").status().unwrap();
    assert!(cmd.success());
}
