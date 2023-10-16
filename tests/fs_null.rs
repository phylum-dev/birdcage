use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    // Activate our sandbox.
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::WriteAndRead("/dev/null".into())).unwrap();
    birdcage.lock().unwrap();

    // Writing to `/dev/null` is allowed.
    fs::write("/dev/null", "blub").unwrap();
}
