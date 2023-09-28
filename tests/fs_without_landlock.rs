#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "linux")]
use birdcage::{Birdcage, Exception, Sandbox};
#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
#[cfg(target_os = "linux")]
use tempfile::NamedTempFile;

#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_os = "linux")]
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

#[cfg(target_os = "linux")]
fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Create seccomp filter blocking `landlock_restrict_self` syscall.
    let mut rules = BTreeMap::new();
    rules.insert(libc::SYS_landlock_restrict_self, Vec::new());
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES as u32),
        ARCH,
    )
    .unwrap();
    let program: BpfProgram = filter.try_into().unwrap();
    seccompiler::apply_filter(&program).unwrap();

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

#[cfg(not(target_os = "linux"))]
fn main() {}
