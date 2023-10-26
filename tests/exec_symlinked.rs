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

    // Create symlinked dir with non-symlinked executable.
    let truer_path = exec_dir.join("truer");
    fs::copy("/usr/bin/true", &truer_path).unwrap();
    let symlink_dir = tempdir.join("symbin");
    let symlink_dir_exec = symlink_dir.join("truer");
    unixfs::symlink(&exec_dir, &symlink_dir).unwrap();

    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::ExecuteAndRead(symlink_dir_exec.clone())).unwrap();
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

    // Ensure symlinked dir's executable works.
    let cmd = Command::new(symlink_dir_exec).status().unwrap();
    assert!(cmd.success());
}
