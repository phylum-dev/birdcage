use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn canonicalize() {
    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::Read("./".into())).unwrap();
    bc.lock().unwrap();

    // Check for success on reading the `Cargo.toml` file.
    let file = fs::read_to_string("./Cargo.toml").unwrap();
    assert!(file.contains("birdcage"));
}
