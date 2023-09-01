#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs;

use birdcage::{Birdcage, Exception, Sandbox};
#[cfg(target_os = "linux")]
use libc;
use tempfile::NamedTempFile;

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Setup our test files.
    let private_path = NamedTempFile::new().unwrap();
    fs::write(&private_path, FILE_CONTENT.as_bytes()).unwrap();
    let public_path = NamedTempFile::new().unwrap();
    fs::write(&public_path, FILE_CONTENT.as_bytes()).unwrap();

    // Activate our sandbox.
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Read(public_path.path().into())).unwrap();
    birdcage.lock().unwrap();

    // Access to the public file is allowed.
    let content = fs::read_to_string(public_path).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Access to the private file is prohibited.
    let result = fs::read_to_string(private_path);
    assert!(result.is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_v3_truncate() {
    let file = NamedTempFile::new().unwrap();
    let path = file.path();
    fs::write(path, "truncate this").unwrap();

    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Write(path.into())).unwrap();
    birdcage.lock().unwrap();

    let path_str = path.to_string_lossy().to_string();
    let c_path = CString::new(path_str).unwrap();
    let result = unsafe { libc::truncate(c_path.as_ptr(), 0) };

    assert_eq!(result, 0);
}
