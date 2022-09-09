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

/// System calls that should not have any side-effects.
const BENIGN_SYSCALLS: &[i64] = &[
    libc::SYS_arch_prctl,
    libc::SYS_brk,
    libc::SYS_capget,
    libc::SYS_capset,
    libc::SYS_clock_getres,
    libc::SYS_clock_gettime,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_futex,
    libc::SYS_getegid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getgroups,
    libc::SYS_getpgid,
    libc::SYS_getpgrp,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_getrandom,
    libc::SYS_getresgid,
    libc::SYS_getresuid,
    libc::SYS_getrlimit,
    libc::SYS_get_robust_list,
    libc::SYS_getrusage,
    libc::SYS_getsid,
    libc::SYS_gettid,
    libc::SYS_getuid,
    libc::SYS_madvise,
    libc::SYS_mincore,
    libc::SYS_mlock,
    libc::SYS_mlock2,
    libc::SYS_mlockall,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munlock,
    libc::SYS_munlockall,
    libc::SYS_munmap,
    libc::SYS_pipe,   // TODO: FS?
    libc::SYS_pipe2,  // TODO: FS?
    libc::SYS_tee,    // TODO: FS?
    libc::SYS_splice, // TODO: FS?
    libc::SYS_pkey_alloc,
    libc::SYS_pkey_free,
    libc::SYS_pkey_mprotect,
    libc::SYS_prctl,
    libc::SYS_prlimit64,
    libc::SYS_rseq,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_yield,
    libc::SYS_setrlimit,
    libc::SYS_gettimeofday,
    libc::SYS_set_robust_list,
    libc::SYS_set_tid_address,
    libc::SYS_sigaltstack,
    libc::SYS_sysinfo,
    libc::SYS_uname,
    libc::SYS_mremap,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    libc::SYS_pause,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_getitimer,
    libc::SYS_setitimer,
    libc::SYS_alarm,
    libc::SYS_times,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setpgid,
    libc::SYS_setsid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_personality,
    libc::SYS_setpriority,
    libc::SYS_getpriority,
    libc::SYS_sched_setparam,
    libc::SYS_sched_getparam,
    libc::SYS_sched_setscheduler,
    libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max,
    libc::SYS_sched_get_priority_min,
    libc::SYS_sched_rr_get_interval,
    libc::SYS_time,
    libc::SYS_seccomp,
    libc::SYS_bpf,
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
    libc::SYS_timer_create,
    libc::SYS_timer_settime,
    libc::SYS_timer_gettime,
    libc::SYS_timer_getoverrun,
    libc::SYS_timer_delete,
    libc::SYS_sched_setattr,
    libc::SYS_sched_getattr,
    libc::SYS_getcpu,
    libc::SYS_unshare,
    libc::SYS_mbind,
    libc::SYS_ioprio_set,
    libc::SYS_ioprio_get,
    libc::SYS_kcmp,
    libc::SYS_memfd_create,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_gettime,
    libc::SYS_timerfd_settime,
    // TODO
    libc::SYS_setgroups,
    // libc::SYS_landlock_create_ruleset,
    444,
    // libc::SYS_landlock_add_rule,
    445,
    // libc::SYS_landlock_restrict_self,
    446,
    libc::SYS_tkill,
    libc::SYS_tgkill,
];

/// System calls for filesystem operations.
const FS_SYSCALLS: &[i64] = &[
    libc::SYS_access,
    libc::SYS_chmod,
    libc::SYS_chown,
    libc::SYS_close,
    libc::SYS_close_range,
    libc::SYS_copy_file_range,
    libc::SYS_creat,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_fadvise64,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_fcntl,
    libc::SYS_fdatasync,
    libc::SYS_flock,
    libc::SYS_fstat,
    libc::SYS_fstatfs,
    libc::SYS_fsync,
    libc::SYS_ftruncate,
    libc::SYS_getcwd,
    libc::SYS_getdents,
    libc::SYS_getdents64,
    libc::SYS_ioctl,
    libc::SYS_lchown,
    libc::SYS_link,
    libc::SYS_linkat,
    libc::SYS_lseek,
    libc::SYS_lstat,
    libc::SYS_mkdir,
    libc::SYS_mkdirat,
    libc::SYS_msync,
    libc::SYS_newfstatat,
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_pread64,
    libc::SYS_preadv,
    libc::SYS_preadv2,
    libc::SYS_pwrite64,
    libc::SYS_pwritev,
    libc::SYS_pwritev2,
    libc::SYS_read,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    libc::SYS_readv,
    libc::SYS_readahead,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_rmdir,
    libc::SYS_stat,
    libc::SYS_statfs,
    libc::SYS_statx,
    libc::SYS_symlink,
    libc::SYS_symlinkat,
    libc::SYS_truncate,
    libc::SYS_umask,
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_utimensat,
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_utime,
    libc::SYS_utimes,
    libc::SYS_futimesat,
    libc::SYS_mknod,
    libc::SYS_mknodat,
    libc::SYS_ustat,
    libc::SYS_sysfs,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_getxattr,
    libc::SYS_lgetxattr,
    libc::SYS_fgetxattr,
    libc::SYS_listxattr,
    libc::SYS_llistxattr,
    libc::SYS_flistxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    libc::SYS_sync,
    libc::SYS_syncfs,
    libc::SYS_sync_file_range,
    libc::SYS_fallocate,
    libc::SYS_lookup_dcookie,
];

/// System calls for evented I/O.
const EVENT_SYSCALLS: &[i64] = &[
    libc::SYS_epoll_create,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_epoll_wait,
    libc::SYS_eventfd,
    libc::SYS_eventfd2,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_pselect6,
    libc::SYS_select,
    libc::SYS_inotify_init,
    libc::SYS_inotify_init1,
    libc::SYS_inotify_add_watch,
    libc::SYS_inotify_rm_watch,
    libc::SYS_io_setup,
    libc::SYS_io_destroy,
    libc::SYS_io_getevents,
    libc::SYS_io_submit,
    libc::SYS_io_cancel,
    libc::SYS_fanotify_init,
    libc::SYS_fanotify_mark,
];

/// System calls for sockets.
const SOCKET_SYSCALLS: &[i64] = &[
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_bind,
    libc::SYS_connect,
    libc::SYS_getpeername,
    libc::SYS_getsockname,
    libc::SYS_getsockopt,
    libc::SYS_listen,
    libc::SYS_recvfrom,
    libc::SYS_recvmmsg,
    libc::SYS_recvmsg,
    libc::SYS_sendfile,
    libc::SYS_sendmmsg,
    libc::SYS_sendmsg,
    libc::SYS_sendto,
    libc::SYS_setsockopt,
    libc::SYS_shutdown,
];

/// System calls for executing files.
const EXEC_SYSCALLS: &[i64] = &[
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_wait4,
    libc::SYS_waitid,
];

/// System calls that are always prohibited.
const _FORBIDDEN_SYSCALLS: &[i64] = &[
    libc::SYS_settimeofday,
    libc::SYS_adjtimex,
    libc::SYS_clock_adjtime,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_finit_module,
    libc::SYS_init_module,
    libc::SYS_delete_module,
];

/// Seccomp filter.
#[derive(Default)]
pub struct Filter {
    rules: BTreeMap<i64, Vec<SeccompRule>>,
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow all benign system calls.
    ///
    /// These are generally system calls that should not have any significant
    /// side-effects which could be abused.
    pub fn allow_benign(&mut self) {
        for syscall in BENIGN_SYSCALLS {
            self.rules.insert(*syscall, Vec::new());
        }
    }

    /// Allow all filesystem operations.
    pub fn allow_fs(&mut self) {
        for syscall in FS_SYSCALLS.iter().chain(EVENT_SYSCALLS) {
            self.rules.insert(*syscall, Vec::new());
        }
    }

    /// Allow creating new processes and threads.
    pub fn allow_exec(&mut self) {
        for syscall in EXEC_SYSCALLS {
            self.rules.insert(*syscall, Vec::new());
        }
    }

    /// Allow creation of sockets.
    pub fn allow_sockets(&mut self, local_only: bool) -> Result<()> {
        let rules = if local_only {
            // Allow local AF_UNIX/AF_LOCAL sockets.
            let allow_unix = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_UNIX as u64,
            )?;
            let unix_rule = SeccompRule::new(vec![allow_unix])?;

            // Allow local IPC AF_NETLINK sockets.
            let allow_netlink = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_NETLINK as u64,
            )?;
            let netlink_rule = SeccompRule::new(vec![allow_netlink])?;

            vec![unix_rule, netlink_rule]
        } else {
            // Allow all socket types.
            Vec::new()
        };

        // Restrict socket creation to allowed socket domain types.
        self.rules.insert(libc::SYS_socket, rules.clone());
        self.rules.insert(libc::SYS_socketpair, rules);

        // Allow all socket I/O.
        for syscall in SOCKET_SYSCALLS {
            self.rules.insert(*syscall, Vec::new());
        }

        Ok(())
    }

    /// Apply all rules in this filter.
    pub fn apply(self) -> Result<()> {
        let filter = SeccompFilter::new(
            self.rules,
            // Action performed if no rules match.
            SeccompAction::KillProcess,
            // Action performed if any rule matches.
            SeccompAction::Allow,
            ARCH,
        )?;
        let program: BpfProgram = filter.try_into()?;
        seccompiler::apply_filter(&program)?;
        Ok(())
    }
}
