use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Read("./".into())).unwrap();
    birdcage.lock().unwrap();

    // Check for success on reading the `Cargo.toml` file.
    let file = fs::read_to_string("./Cargo.toml").unwrap();
    assert!(file.contains("birdcage"));
}
