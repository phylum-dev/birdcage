use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn execution() {
    Birdcage::new()
        .unwrap()
        .add_exception(Exception::ExecuteAndRead("/usr/bin/true".into()))
        .unwrap()
        .add_exception(Exception::ExecuteAndRead("/usr/lib".into()))
        .unwrap()
        .lock()
        .unwrap();

    // Check for success when executing `true`.
    let cmd = Command::new("/usr/bin/true").status().unwrap();
    assert!(cmd.success());

    // Check for success on reading the `true` file.
    let cmd_file = fs::read("/usr/bin/true");
    assert!(cmd_file.is_ok());
}
