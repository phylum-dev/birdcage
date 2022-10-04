use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn canonicalize() {
    Birdcage::new().unwrap().add_exception(Exception::Read("./".into())).unwrap().lock().unwrap();

    // Check for success on reading the `Cargo.toml` file.
    let file = fs::read_to_string("./Cargo.toml").unwrap();
    assert!(file.contains("birdcage"));
}
