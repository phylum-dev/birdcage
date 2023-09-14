use std::env;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    // Setup our environment variables
    env::set_var("PUBLIC", "GOOD");
    env::set_var("PRIVATE", "BAD");

    // Activate our sandbox.
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Environment("PUBLIC".into())).unwrap();
    birdcage.lock().unwrap();

    // The `PUBLIC` environment variable can be accessed.
    assert_eq!(env::var("PUBLIC"), Ok("GOOD".into()));

    // The `PRIVATE` environment variable was removed.
    assert_eq!(env::var_os("PRIVATE"), None);
}
