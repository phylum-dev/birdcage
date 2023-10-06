#[cfg(target_os = "linux")]
use std::ffi::CString;

#[cfg(target_os = "linux")]
use birdcage::{Birdcage, Sandbox};

#[cfg(target_os = "linux")]
fn main() {
    // Activate our sandbox.
    Birdcage::new().lock().unwrap();

    // Ensure `chdir` is allowed.
    let root_path = CString::new("/").unwrap();
    let result = unsafe { libc::chdir(root_path.as_ptr()) };
    assert_eq!(result, 0);

    // Ensure `unshare` is always blocked.
    let result = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    assert_eq!(result, -1);

    // Ensure `clone` is blocked with `CLONE_NEWUSER`.
    let stack = unsafe { libc::malloc(4096) };
    let flags = libc::CLONE_NEWUSER as libc::c_ulong;
    let result = unsafe { libc::syscall(libc::SYS_clone, flags, stack) };
    assert_eq!(result, -1);

    // Ensure `clone` is allowed without flags.
    let flags = 0;
    let result = unsafe { libc::syscall(libc::SYS_clone, flags, stack) };
    assert!(result > 0);
}

#[cfg(not(target_os = "linux"))]
fn main() {}
