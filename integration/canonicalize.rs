use std::fs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup(_tempdir: PathBuf) -> TestSetup {
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::Read("./".into())).unwrap();

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    // Check for success on reading the `Cargo.toml` file.
    let file = fs::read_to_string("./Cargo.toml").unwrap();
    assert!(file.contains("birdcage"));
}
