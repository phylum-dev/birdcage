#[cfg(target_os = "linux")]
use birdcage::{Birdcage, Sandbox};

#[cfg(target_os = "linux")]
fn main() {
    // Activate our sandbox.
    Birdcage::new().lock().unwrap();

    let result = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    assert_eq!(result, -1);
}

#[cfg(not(target_os = "linux"))]
fn main() {}
