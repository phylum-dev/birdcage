use std::fs;
use std::os::unix::fs as unixfs;
use std::path::PathBuf;

use birdcage::{Birdcage, Exception, Sandbox};
use tempfile::NamedTempFile;

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test files.
    let private_path = NamedTempFile::new().unwrap();
    fs::write(&private_path, FILE_CONTENT.as_bytes()).unwrap();
    let public_path = NamedTempFile::new().unwrap();
    fs::write(&public_path, FILE_CONTENT.as_bytes()).unwrap();

    // Create symlinks for the files.
    let private_str = private_path.path().to_string_lossy() + "_tmpfile";
    let private = PathBuf::from(private_str.as_ref());
    let public_str = public_path.path().to_string_lossy() + "_tmpfile";
    let public = PathBuf::from(public_str.as_ref());
    unixfs::symlink(&private_path, &private).unwrap();
    unixfs::symlink(&public_path, &public).unwrap();

    // Activate our sandbox.
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::Read(public.clone())).unwrap();
    birdcage.lock().unwrap();

    // Access to the public file is allowed.
    let content = fs::read_to_string(&public).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Access to the private file is prohibited.
    let result = fs::read_to_string(&private);
    assert!(result.is_err());
}
