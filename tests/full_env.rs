use std::env;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn full_env() {
    // Setup our environment variables
    env::set_var("PUBLIC", "GOOD");

    // Activate our sandbox.
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::FullEnvironment).unwrap();
    birdcage.lock().unwrap();

    // The `PUBLIC` environment variable can be accessed.
    assert_eq!(env::var("PUBLIC"), Ok("GOOD".into()));
}
