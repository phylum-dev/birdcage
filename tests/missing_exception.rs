use std::path::PathBuf;

use birdcage::error::Error;
use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    let mut birdcage = Birdcage::new();

    // Add a path that doesn't exist.
    let result = birdcage.add_exception(Exception::Read("/does/not/exist".into()));

    // Ensure it is appropriately reported that exception was NOT added.
    match result {
        Err(Error::InvalidPath(path)) => assert_eq!(path, PathBuf::from("/does/not/exist")),
        _ => panic!("expected path error"),
    }

    // Ensure locking is always successful.
    birdcage.lock().unwrap();
}
