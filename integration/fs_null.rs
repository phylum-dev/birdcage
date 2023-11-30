use std::path::PathBuf;
use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup(_tempdir: PathBuf) -> TestSetup {
    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::WriteAndRead("/dev/null".into())).unwrap();

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    // Writing to `/dev/null` is allowed.
    fs::write("/dev/null", "blub").unwrap();
}
