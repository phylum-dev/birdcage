#[cfg(target_os = "linux")]
use birdcage::{Birdcage, Sandbox};

#[cfg(target_os = "linux")]
fn main() {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    let birdcage = Birdcage::new();
    birdcage.lock().unwrap();

    assert_eq!(uid, unsafe { libc::getuid() });
    assert_eq!(gid, unsafe { libc::getgid() });
    assert_eq!(euid, unsafe { libc::geteuid() });
    assert_eq!(egid, unsafe { libc::getegid() });
}

#[cfg(not(target_os = "linux"))]
fn main() {}
