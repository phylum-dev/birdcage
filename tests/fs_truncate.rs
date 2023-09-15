#[rustfmt::skip]
#[cfg(target_os = "linux")]
use {
    std::ffi::CString,
    std::fs,

    birdcage::linux::LANDLOCK_ABI,
    birdcage::{Birdcage, Exception, Sandbox},
    tempfile::NamedTempFile,
};

#[cfg(target_os = "linux")]
fn main() {
    // Create files with non-zero length.
    let input = "truncate this";
    let public_file = NamedTempFile::new().unwrap();
    let public_path = public_file.path();
    fs::write(public_path, input).unwrap();
    let private_file = NamedTempFile::new().unwrap();
    let private_path = private_file.path();
    fs::write(private_path, input).unwrap();

    // Enable our sandbox.
    let mut birdcage = match Birdcage::new_with_version(LANDLOCK_ABI::V3) {
        Ok(birdcage) => birdcage,
        // Skip this test if LANDLOCK_ABI::V3 is not supported.
        Err(_) => return,
    };
    birdcage.add_exception(Exception::Write(public_path.into())).unwrap();
    birdcage.add_exception(Exception::Read(public_path.into())).unwrap();
    birdcage.add_exception(Exception::Read(private_path.into())).unwrap();
    birdcage.lock().unwrap();

    // Allow truncating public file.
    let path_str = public_path.to_string_lossy().to_string();
    let c_path = CString::new(path_str).unwrap();
    let result = unsafe { libc::truncate(c_path.as_ptr(), 0) };
    assert_eq!(result, 0);

    // Ensure the file is empty.
    let content = fs::read_to_string(public_path).unwrap();
    assert_eq!(content, String::new());

    // Prevent truncating private file.
    let path_str = private_path.to_string_lossy().to_string();
    let c_path = CString::new(path_str).unwrap();
    let result = unsafe { libc::truncate(c_path.as_ptr(), 0) };
    assert_eq!(result, -1);

    // Ensure the file is NOT empty.
    let content = fs::read_to_string(private_path).unwrap();
    assert_eq!(content, String::from(input));
}

#[cfg(not(target_os = "linux"))]
fn main() {}
