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

/// Seccomp network filter.
#[derive(Default)]
pub struct NetworkFilter;

impl NetworkFilter {
    /// Apply all rules in this filter.
    pub fn apply() -> Result<()> {
        let mut rules = BTreeMap::new();

        // Add unconditionally allowed syscalls.
        for syscall in SYSCALL_WHITELIST {
            rules.insert(*syscall, Vec::new());
        }

        // Add socket syscalls which do not perform network operations.
        Self::add_local_socket_whitelist(&mut rules)?;

        let filter = SeccompFilter::new(
            rules,
            // Action performed if no rules match.
            SeccompAction::Errno(libc::EACCES as u32),
            // Action performed if any rule matches.
            SeccompAction::Allow,
            ARCH,
        )?;
        let program: BpfProgram = filter.try_into()?;
        seccompiler::apply_filter(&program)?;

        Ok(())
    }

    /// Allow local filesystem sockets.
    fn add_local_socket_whitelist(
        rules: &mut BTreeMap<libc::c_long, Vec<SeccompRule>>,
    ) -> Result<()> {
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

        let socket_rule = vec![unix_rule, netlink_rule];

        // Restrict socket creation to allowed socket domain types.
        rules.insert(libc::SYS_socketpair, socket_rule.clone());
        rules.insert(libc::SYS_socket, socket_rule);

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
    libc::SYS_clone,
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
    libc::SYS_ptrace,
    libc::SYS_getuid,
    libc::SYS_syslog,
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
    libc::SYS_personality,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_ustat,
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
    libc::SYS_vhangup,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_modify_ldt,
    libc::SYS_pivot_root,
    libc::SYS_prctl,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_arch_prctl,
    libc::SYS_adjtimex,
    libc::SYS_setrlimit,
    libc::SYS_chroot,
    libc::SYS_sync,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_umount2,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_get_kernel_syms,
    libc::SYS_quotactl,
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
    libc::SYS_lookup_dcookie,
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
    libc::SYS_clock_settime,
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
    libc::SYS_mbind,
    libc::SYS_set_mempolicy,
    libc::SYS_get_mempolicy,
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
    libc::SYS_waitid,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
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
    libc::SYS_unshare,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_splice,
    libc::SYS_tee,
    libc::SYS_sync_file_range,
    libc::SYS_vmsplice,
    libc::SYS_move_pages,
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
    libc::SYS_perf_event_open,
    libc::SYS_recvmmsg,
    libc::SYS_fanotify_init,
    libc::SYS_fanotify_mark,
    libc::SYS_prlimit64,
    libc::SYS_name_to_handle_at,
    libc::SYS_open_by_handle_at,
    libc::SYS_clock_adjtime,
    libc::SYS_syncfs,
    libc::SYS_sendmmsg,
    libc::SYS_setns,
    libc::SYS_getcpu,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    libc::SYS_sched_setattr,
    libc::SYS_sched_getattr,
    libc::SYS_renameat2,
    libc::SYS_seccomp,
    libc::SYS_getrandom,
    libc::SYS_memfd_create,
    libc::SYS_bpf,
    libc::SYS_execveat,
    libc::SYS_userfaultfd,
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
    libc::SYS_open_tree,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fspick,
    libc::SYS_pidfd_open,
    libc::SYS_clone3,
    libc::SYS_close_range,
    libc::SYS_openat2,
    libc::SYS_faccessat2,
    libc::SYS_process_madvise,
    libc::SYS_epoll_pwait2,
    libc::SYS_mount_setattr,
    libc::SYS_quotactl_fd,
    libc::SYS_landlock_create_ruleset,
    libc::SYS_landlock_add_rule,
    libc::SYS_landlock_restrict_self,
    libc::SYS_memfd_secret,
    libc::SYS_process_mrelease,
    libc::SYS_futex_waitv,
    libc::SYS_set_mempolicy_home_node,
];

#[cfg(test)]
mod tests {
    use std::io::{Error as IoError, ErrorKind as IoErrorKind};

    use super::*;

    #[test]
    fn block_io_uring() {
        NetworkFilter::apply().unwrap();

        let mut io_uring_params =
            vec![IoUringParams { flags: 1, sq_entries: 32, cq_entries: 32, ..Default::default() }];

        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                io_uring_params.len(),
                io_uring_params.as_mut_ptr(),
            )
        };

        assert_eq!(result, -1);
        assert_eq!(IoError::last_os_error().kind(), IoErrorKind::PermissionDenied);
    }

    #[test]
    fn allow_local_sockets() {
        NetworkFilter::apply().unwrap();

        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            panic!("AF_UNIX socket creation failed: {}", IoError::last_os_error());
        }

        unsafe { libc::close(fd) };
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoUringParams {
        sq_entries: u32,
        cq_entries: u32,
        flags: u32,
        sq_thread_cpu: u32,
        sq_thread_idle: u32,
        features: u32,
        wq_fd: u32,
        resv: [u32; 3],
        sq_off: IoSqringOffsets,
        cq_off: IoSqringOffsets,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoSqringOffsets {
        head: u32,
        tail: u32,
        ring_mask: u32,
        ring_entries: u32,
        flags: u32,
        dropped: u32,
        array: u32,
        resv: [u32; 3],
    }
}
