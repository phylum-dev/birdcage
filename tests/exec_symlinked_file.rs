use std::fs;
use std::os::unix::fs as unixfs;
use std::path::PathBuf;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    // Create symlinked executable.
    let tempdir = tempfile::tempdir().unwrap().into_path();
    let exec_dir = tempdir.join("bin");
    fs::create_dir(&exec_dir).unwrap();
    let symlink_exec = exec_dir.join("true");
    unixfs::symlink("/usr/bin/true", &symlink_exec).unwrap();

    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::ExecuteAndRead(symlink_exec.clone())).unwrap();
    if PathBuf::from("/lib64").exists() {
        birdcage.add_exception(Exception::ExecuteAndRead("/lib64".into())).unwrap();
    }
    if PathBuf::from("/lib").exists() {
        birdcage.add_exception(Exception::ExecuteAndRead("/lib".into())).unwrap();
    }
    birdcage.lock().unwrap();

    // Ensure symlinked executable works.
    let cmd = Command::new(symlink_exec).status().unwrap();
    assert!(cmd.success());

    // Ensure original executable works.
    let cmd = Command::new("/usr/bin/true").status().unwrap();
    assert!(cmd.success());
}
