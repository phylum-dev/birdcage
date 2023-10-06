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

/// Bitmask for the clone syscall seccomp filter.
///
/// A 1 in the bitmask means system calls with this flag set will be denied.
///
/// Filtered flags:
///  - CLONE_NEWNS     = 0x00020000
///  - CLONE_NEWCGROUP = 0x02000000
///  - CLONE_NEWUTS    = 0x04000000
///  - CLONE_NEWIPC    = 0x08000000
///  - CLONE_NEWUSER   = 0x10000000
///  - CLONE_NEWPID    = 0x20000000
///  - CLONE_NEWNET    = 0x40000000
///  - CLONE_IO        = 0x80000000
const CLONE_NAMESPACE_FILTER: u32 = 0b01111110000000100000000000000000;

/// Seccomp system call filter.
///
/// This filter is aimed at restricting system calls which shouldn't be
/// executable by an untrusted client.
#[derive(Default)]
pub struct SyscallFilter;

impl SyscallFilter {
    /// Apply the seccomp filter.
    pub fn apply() -> Result<()> {
        let mut rules = BTreeMap::new();

        // Add exceptions for allowed syscalls.
        for syscall in SYSCALL_WHITELIST {
            rules.insert(*syscall, Vec::new());
        }

        // Add exception for the `clone` syscall.
        let allow_clone = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(CLONE_NAMESPACE_FILTER as u64),
            0,
        )?;
        let clone_rule = SeccompRule::new(vec![allow_clone])?;
        rules.insert(libc::SYS_clone, vec![clone_rule]);

        // Apply seccomp filter.
        let filter = SeccompFilter::new(
            rules,
            // Action performed if no rule matches.
            SeccompAction::Errno(libc::EACCES as u32),
            // Action performed if any rule matches.
            SeccompAction::Allow,
            ARCH,
        )?;
        let program: BpfProgram = filter.try_into()?;
        seccompiler::apply_filter(&program)?;

        // Change `clone3` syscall error to "not implemented", to force `clone` usage.
        let mut rules = BTreeMap::new();
        rules.insert(libc::SYS_clone3, Vec::new());
        let filter = SeccompFilter::new(
            rules,
            // Action performed if no rule matches.
            SeccompAction::Allow,
            // Action performed if any rule matches.
            SeccompAction::Errno(libc::ENOSYS as u32),
            ARCH,
        )?;
        let program: BpfProgram = filter.try_into()?;
        seccompiler::apply_filter(&program)?;

        Ok(())
    }
}

/// Unconditionally allowed syscalls for networking.
const SYSCALL_WHITELIST: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_open,
    libc::SYS_close,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_stat,
    libc::SYS_fstat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_lstat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_poll,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_ioctl,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_readv,
    libc::SYS_writev,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_access,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_pipe,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_select,
    libc::SYS_sched_yield,
    libc::SYS_mremap,
    libc::SYS_msync,
    libc::SYS_mincore,
    libc::SYS_madvise,
    libc::SYS_shmget,
    libc::SYS_shmat,
    libc::SYS_shmctl,
    libc::SYS_dup,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_dup2,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_pause,
    libc::SYS_nanosleep,
    libc::SYS_getitimer,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_alarm,
    libc::SYS_setitimer,
    libc::SYS_getpid,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_sendfile,
    libc::SYS_connect,
    libc::SYS_accept,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_shutdown,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_fork,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_vfork,
    libc::SYS_execve,
    libc::SYS_exit,
    libc::SYS_wait4,
    libc::SYS_kill,
    libc::SYS_uname,
    libc::SYS_semget,
    libc::SYS_semop,
    libc::SYS_semctl,
    libc::SYS_shmdt,
    libc::SYS_msgget,
    libc::SYS_msgsnd,
    libc::SYS_msgrcv,
    libc::SYS_msgctl,
    libc::SYS_fcntl,
    libc::SYS_flock,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_truncate,
    libc::SYS_ftruncate,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_getdents,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_rename,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_mkdir,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_rmdir,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_creat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_link,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_unlink,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_symlink,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_readlink,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_chmod,
    libc::SYS_fchmod,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_chown,
    libc::SYS_fchown,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_lchown,
    libc::SYS_umask,
    libc::SYS_gettimeofday,
    libc::SYS_getrlimit,
    libc::SYS_getrusage,
    libc::SYS_sysinfo,
    libc::SYS_times,
    libc::SYS_getuid,
    libc::SYS_getgid,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_geteuid,
    libc::SYS_getegid,
    libc::SYS_setpgid,
    libc::SYS_getppid,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_getpgrp,
    libc::SYS_setsid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_getgroups,
    libc::SYS_setgroups,
    libc::SYS_setresuid,
    libc::SYS_getresuid,
    libc::SYS_setresgid,
    libc::SYS_getresgid,
    libc::SYS_getpgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_getsid,
    libc::SYS_capget,
    libc::SYS_capset,
    libc::SYS_rt_sigpending,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_rt_sigsuspend,
    libc::SYS_sigaltstack,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_utime,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_mknod,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_getpriority,
    libc::SYS_setpriority,
    libc::SYS_sched_setparam,
    libc::SYS_sched_getparam,
    libc::SYS_sched_setscheduler,
    libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max,
    libc::SYS_sched_get_priority_min,
    libc::SYS_sched_rr_get_interval,
    libc::SYS_mlock,
    libc::SYS_munlock,
    libc::SYS_mlockall,
    libc::SYS_munlockall,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_modify_ldt,
    libc::SYS_prctl,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_arch_prctl,
    libc::SYS_adjtimex,
    libc::SYS_setrlimit,
    libc::SYS_sync,
    libc::SYS_gettid,
    libc::SYS_readahead,
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
    libc::SYS_tkill,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_time,
    libc::SYS_futex,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_getaffinity,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_set_thread_area,
    libc::SYS_io_setup,
    libc::SYS_io_destroy,
    libc::SYS_io_getevents,
    libc::SYS_io_submit,
    libc::SYS_io_cancel,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_get_thread_area,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_epoll_create,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_epoll_ctl_old,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_epoll_wait_old,
    libc::SYS_remap_file_pages,
    libc::SYS_getdents64,
    libc::SYS_set_tid_address,
    libc::SYS_restart_syscall,
    libc::SYS_semtimedop,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_fadvise64,
    libc::SYS_timer_create,
    libc::SYS_timer_settime,
    libc::SYS_timer_gettime,
    libc::SYS_timer_getoverrun,
    libc::SYS_timer_delete,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_exit_group,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_epoll_wait,
    libc::SYS_epoll_ctl,
    libc::SYS_tgkill,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_utimes,
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
    libc::SYS_waitid,
    libc::SYS_ioprio_set,
    libc::SYS_ioprio_get,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_inotify_init,
    libc::SYS_inotify_add_watch,
    libc::SYS_inotify_rm_watch,
    libc::SYS_migrate_pages,
    libc::SYS_openat,
    libc::SYS_mkdirat,
    libc::SYS_mknodat,
    libc::SYS_fchownat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_futimesat,
    libc::SYS_newfstatat,
    libc::SYS_unlinkat,
    libc::SYS_renameat,
    libc::SYS_linkat,
    libc::SYS_symlinkat,
    libc::SYS_readlinkat,
    libc::SYS_fchmodat,
    libc::SYS_faccessat,
    libc::SYS_pselect6,
    libc::SYS_ppoll,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_splice,
    libc::SYS_tee,
    libc::SYS_sync_file_range,
    libc::SYS_vmsplice,
    libc::SYS_utimensat,
    libc::SYS_epoll_pwait,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_signalfd,
    libc::SYS_timerfd_create,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_eventfd,
    libc::SYS_fallocate,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_accept4,
    libc::SYS_signalfd4,
    libc::SYS_eventfd2,
    libc::SYS_epoll_create1,
    libc::SYS_dup3,
    libc::SYS_pipe2,
    libc::SYS_inotify_init1,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_rt_tgsigqueueinfo,
    libc::SYS_recvmmsg,
    libc::SYS_fanotify_mark,
    libc::SYS_prlimit64,
    libc::SYS_name_to_handle_at,
    libc::SYS_syncfs,
    libc::SYS_sendmmsg,
    libc::SYS_getcpu,
    libc::SYS_sched_setattr,
    libc::SYS_sched_getattr,
    libc::SYS_renameat2,
    libc::SYS_seccomp,
    libc::SYS_getrandom,
    libc::SYS_memfd_create,
    libc::SYS_execveat,
    libc::SYS_membarrier,
    libc::SYS_mlock2,
    libc::SYS_copy_file_range,
    libc::SYS_preadv2,
    libc::SYS_pwritev2,
    libc::SYS_pkey_mprotect,
    libc::SYS_pkey_alloc,
    libc::SYS_pkey_free,
    libc::SYS_statx,
    libc::SYS_rseq,
    libc::SYS_pidfd_send_signal,
    libc::SYS_pidfd_open,
    libc::SYS_close_range,
    libc::SYS_openat2,
    libc::SYS_faccessat2,
    libc::SYS_epoll_pwait2,
    libc::SYS_landlock_create_ruleset,
    libc::SYS_landlock_add_rule,
    libc::SYS_landlock_restrict_self,
    libc::SYS_memfd_secret,
    libc::SYS_process_mrelease,
    libc::SYS_futex_waitv,
    libc::SYS_socketpair,
    libc::SYS_socket,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_io_uring_setup,
];
