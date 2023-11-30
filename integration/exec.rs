use std::path::PathBuf;
use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup(_tempdir: PathBuf) -> TestSetup {
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::ExecuteAndRead("/usr/bin/true".into())).unwrap();

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    // Check for success when executing `true`.
    let cmd = Command::new("/usr/bin/true").status().unwrap();
    assert!(cmd.success());

    // Check for success on reading the `true` file.
    let cmd_file = fs::read("/usr/bin/true");
    assert!(cmd_file.is_ok());
}
