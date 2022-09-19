use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn execution() {
    const TRUE_PATH: &str = if cfg!(target_os = "macos") { "/usr/bin/true" } else { "/bin/true" };

    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::ExecuteAndRead(TRUE_PATH.into())).unwrap();
    bc.lock().unwrap();

    // Check for success when executing `true`.
    let cmd = Command::new(TRUE_PATH).status().unwrap();
    assert!(cmd.success());

    // Check for success on reading the `true` file.
    let cmd_file = fs::read(TRUE_PATH);
    assert!(cmd_file.is_ok());
}
