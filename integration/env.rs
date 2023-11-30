use std::path::PathBuf;
use std::env;

use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup(_tempdir: PathBuf) -> TestSetup {
    // Setup our environment variables
    env::set_var("PUBLIC", "GOOD");
    env::set_var("PRIVATE", "BAD");

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::Environment("PUBLIC".into())).unwrap();

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    // Only the `PUBLIC` environment variable remains.
    let env: Vec<_> = env::vars().collect();
    assert_eq!(env, vec![("PUBLIC".into(), "GOOD".into())]);
}
