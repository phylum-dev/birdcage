use std::fs;
use std::path::PathBuf;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::ExecuteAndRead("/usr/bin/true".into())).unwrap();
    birdcage.add_exception(Exception::ExecuteAndRead("/usr/lib".into())).unwrap();
    if PathBuf::from("/lib64").exists() {
        birdcage.add_exception(Exception::ExecuteAndRead("/lib64".into())).unwrap();
    }
    if PathBuf::from("/lib").exists() {
        birdcage.add_exception(Exception::ExecuteAndRead("/lib".into())).unwrap();
    }
    birdcage.lock().unwrap();

    // Check for success when executing `true`.
    let cmd = Command::new("/usr/bin/true").status().unwrap();
    assert!(cmd.success());

    // Check for success on reading the `true` file.
    let cmd_file = fs::read("/usr/bin/true");
    assert!(cmd_file.is_ok());
}
