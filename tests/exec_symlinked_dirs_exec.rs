use std::os::unix::fs as unixfs;
use std::path::PathBuf;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    // Create symlinked executable dir.
    let tempdir = tempfile::tempdir().unwrap().into_path();
    let symlink_dir = tempdir.join("bin");
    let symlink_dir_exec = symlink_dir.join("true");
    unixfs::symlink("/usr/bin", &symlink_dir).unwrap();

    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::ExecuteAndRead(symlink_dir_exec.clone())).unwrap();
    if PathBuf::from("/lib64").exists() {
        birdcage.add_exception(Exception::ExecuteAndRead("/lib64".into())).unwrap();
    }
    if PathBuf::from("/lib").exists() {
        birdcage.add_exception(Exception::ExecuteAndRead("/lib".into())).unwrap();
    }
    birdcage.lock().unwrap();

    // Ensure symlinked dir's executable works.
    let cmd = Command::new(symlink_dir_exec).status().unwrap();
    assert!(cmd.success());

    // Ensure original dir's executable works.
    let cmd = Command::new("/usr/bin/true").status().unwrap();
    assert!(cmd.success());
}
