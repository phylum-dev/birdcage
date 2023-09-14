#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::net::TcpStream;

#[cfg(target_os = "linux")]
use birdcage::{Birdcage, Sandbox};
#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_os = "linux")]
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

#[cfg(target_os = "linux")]
fn main() {
    // Create seccomp filter blocking `unshare` syscall.
    let mut rules = BTreeMap::new();
    rules.insert(libc::SYS_unshare, Vec::new());
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES as u32),
        ARCH,
    )
    .unwrap();
    let program: BpfProgram = filter.try_into().unwrap();
    seccompiler::apply_filter(&program).unwrap();

    let birdcage = Birdcage::new().unwrap();
    let result = birdcage.lock();

    match result {
        // Seccomp is supported, so networking should still be blocked.
        Ok(_) => {
            let result = TcpStream::connect("8.8.8.8:443");
            assert!(result.is_err());
        },
        // Seccomp isn't supported, so failure is desired.
        Err(_) => (),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
