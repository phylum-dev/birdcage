#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::net::TcpStream;

#[cfg(target_os = "linux")]
use birdcage::{Birdcage, Sandbox};
#[cfg(target_os = "linux")]
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_os = "linux")]
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

#[cfg(target_os = "linux")]
fn main() {
    // Create seccomp filter blocking seccomp prctl syscall.
    let mut rules = BTreeMap::new();
    let seccomp_prctl = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::PR_SET_SECCOMP as u64,
    )
    .unwrap();
    let rule = SeccompRule::new(vec![seccomp_prctl]).unwrap();
    rules.insert(libc::SYS_prctl, vec![rule]);
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
    birdcage.lock().unwrap();

    let result = TcpStream::connect("8.8.8.8:443");
    assert!(result.is_err());
}

#[cfg(not(target_os = "linux"))]
fn main() {}
