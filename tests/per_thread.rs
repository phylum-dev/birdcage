use std::fs;
use std::thread;

use birdcage::{Birdcage, Sandbox};
use tempfile::NamedTempFile;

#[test]
fn per_thread_sandboxing() {
    let unsandboxed = thread::spawn(|| {
        let path = fs::canonicalize(NamedTempFile::new().unwrap()).unwrap();
        fs::write(&path, b"hello")
    })
    .join().unwrap();

    let sandboxed = thread::spawn(|| {
        let path = fs::canonicalize(NamedTempFile::new().unwrap()).unwrap();
        Birdcage::new().unwrap().lock().unwrap();
        fs::write(&path, b"hello")
    })
    .join().unwrap();

    println!("{:?}", sandboxed);
    println!("{:?}", unsandboxed);
    assert!(sandboxed.is_err());
    assert!(unsandboxed.is_ok());
}
