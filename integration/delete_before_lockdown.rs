
use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::NamedTempFile;

use crate::TestSetup;

pub fn setup() -> TestSetup {
    // Create temporary file.
    let tempfile = NamedTempFile::new().unwrap();

    // Setup sandbox exceptions.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::Read(tempfile.path().into())).unwrap();

    tempfile.close().unwrap();

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    // We just want to test sandbox creation worked.
}
