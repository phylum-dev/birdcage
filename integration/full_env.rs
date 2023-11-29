use std::env;

use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup() -> TestSetup {
    // Setup our environment variables
    env::set_var("PUBLIC", "GOOD");

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::FullEnvironment).unwrap();

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    // The `PUBLIC` environment variable can be accessed.
    assert_eq!(env::var("PUBLIC"), Ok("GOOD".into()));
}
