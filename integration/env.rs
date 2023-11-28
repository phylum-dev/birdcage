use std::env;

use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup() -> TestSetup {
    // Setup our environment variables
    env::set_var("PUBLIC", "GOOD");
    env::set_var("PRIVATE", "BAD");

    // Activate our sandbox.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::Environment("PUBLIC".into())).unwrap();

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    // The `PUBLIC` environment variable can be accessed.
    assert_eq!(env::var("PUBLIC"), Ok("GOOD".into()));

    // The `PRIVATE` environment variable was removed.
    assert_eq!(env::var_os("PRIVATE"), None);
}
