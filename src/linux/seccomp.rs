//! Seccomp system call filtering.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::Result;

#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

/// Seccomp filter.
#[derive(Default)]
pub struct Filter {
    rules: BTreeMap<i64, Vec<SeccompRule>>,
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deny network access.
    pub fn deny_networking(&mut self) -> Result<()> {
        // Allow local AF_UNIX/AF_LOCAL sockets.
        let allow_unix = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )?;

        // Allow local IPC AF_NETLINK sockets.
        let allow_netlink = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_NETLINK as u64,
        )?;

        let socket_rule = vec![SeccompRule::new(vec![allow_unix, allow_netlink])?];

        // Restrict socket creation to allowed socket domain types.
        self.rules.insert(libc::SYS_socketpair, socket_rule.clone());
        self.rules.insert(libc::SYS_socket, socket_rule);

        Ok(())
    }

    /// Apply all rules in this filter.
    pub fn apply(self) -> Result<()> {
        let filter = SeccompFilter::new(
            self.rules,
            // Action performed if no rules match.
            SeccompAction::Allow,
            // Action performed if any rule matches.
            SeccompAction::KillProcess,
            ARCH,
        )?;
        let program: BpfProgram = filter.try_into()?;
        seccompiler::apply_filter(&program)?;
        Ok(())
    }
}
