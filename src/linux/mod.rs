//! Linux sandboxing.
//!
//! This module implements sandboxing on Linux based on the Landlock LSM, Linux
//! namespaces, and seccomp.

use std::fs;
use std::io::Error as IoError;

use bitflags::bitflags;
use landlock::{
    make_bitflags, Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI as LANDLOCK_ABI,
};

use crate::error::{Error, Result};
use crate::linux::seccomp::NetworkFilter;
use crate::{Exception, Sandbox};

mod seccomp;

/// Minimum landlock ABI version.
const ABI: LANDLOCK_ABI = LANDLOCK_ABI::V1;

/// Linux sandboxing.
pub struct LinuxSandbox {
    env_exceptions: Vec<String>,
    landlock: RulesetCreated,
    allow_networking: bool,
    full_env: bool,
}

impl Sandbox for LinuxSandbox {
    fn new() -> Result<Self> {
        // Setup landlock filtering.
        let mut landlock = Ruleset::new()
            .set_best_effort(false)
            .handle_access(AccessFs::from_all(ABI))?
            .create()?;
        landlock.as_mut().set_no_new_privs(true);

        Ok(Self { landlock, env_exceptions: Vec::new(), allow_networking: false, full_env: false })
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        let (path, access) = match exception {
            Exception::Read(path) => (path, make_bitflags!(AccessFs::{ ReadFile | ReadDir })),
            Exception::Write(path) => (path, AccessFs::from_write(ABI)),
            Exception::ExecuteAndRead(path) => (path, AccessFs::from_read(ABI)),
            Exception::Environment(key) => {
                self.env_exceptions.push(key);
                return Ok(self);
            },
            Exception::FullEnvironment => {
                self.full_env = true;
                return Ok(self);
            },
            Exception::Networking => {
                self.allow_networking = true;
                return Ok(self);
            },
        };

        let rule = PathBeneath::new(PathFd::new(path)?, access);

        self.landlock.as_mut().add_rule(rule)?;

        Ok(self)
    }

    fn lock(self) -> Result<()> {
        // Remove environment variables.
        if !self.full_env {
            crate::restrict_env_variables(&self.env_exceptions);
        }

        // Clear abstract namespace by entering a new user namespace.
        let _ = create_user_namespace(false);

        // Create network namespace.
        if !self.allow_networking {
            restrict_networking()?;
        }

        // Apply landlock rules.
        let status = self.landlock.restrict_self()?;

        // Ensure all restrictions were properly applied.
        if status.no_new_privs && status.ruleset == RulesetStatus::FullyEnforced {
            Ok(())
        } else {
            Err(Error::ActivationFailed("sandbox could not be fully enforced".into()))
        }
    }
}

/// Restrict networking using seccomp and namespaces.
fn restrict_networking() -> Result<()> {
    // Create network namespace.
    let result = create_user_namespace(true).and_then(|_| unshare(Namespaces::NETWORK));

    // Apply seccomp network filter.
    match NetworkFilter::apply() {
        _ if result.is_ok() => Ok(()),
        result => result,
    }
}

/// Create a new user namespace.
///
/// If the `become_root` flag is set, then the current user will be mapped to
/// UID 0 inside the namespace. Otherwise the current user will be mapped to its
/// UID of the parent namespace.
fn create_user_namespace(become_root: bool) -> Result<()> {
    // Get the current UID.
    let uid = unsafe { libc::getuid() };

    // Create the namespace.
    unshare(Namespaces::USER)?;

    // Map the UID and GID.
    let map = if become_root { format!("0 {uid} 1\n") } else { format!("{uid} {uid} 1\n") };
    fs::write("/proc/self/uid_map", map.as_bytes())?;
    fs::write("/proc/self/setgroups", b"deny")?;
    fs::write("/proc/self/gid_map", map.as_bytes())?;

    Ok(())
}

/// Enter a namespace.
fn unshare(namespaces: Namespaces) -> Result<()> {
    let result = unsafe { libc::unshare(namespaces.bits()) };
    if result == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error().into())
    }
}

bitflags! {
    /// Unshare system call namespace flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct Namespaces: libc::c_int {
        /// Unshare the file descriptor table, so that the calling process no longer
        /// shares its file descriptors with any other process.
        const FILES = libc::CLONE_FILES;
        /// Unshare filesystem attributes, so that the calling process no longer shares
        /// its root directory, current directory, or umask attributes with any other process.
        const FS = libc::CLONE_FS;
        /// Unshare the cgroup namespace.
        const CGROUP = libc::CLONE_NEWCGROUP;
        /// Unshare the IPC namespace, so that the calling process has a private copy of
        /// the IPC namespace which is not shared with any other process. Specifying
        /// this flag automatically implies [`Namespaces::SYSVSEM`] as well.
        const IPC = libc::CLONE_NEWIPC;
        /// Unshare the network namespace, so that the calling process is moved into a
        /// new network namespace which is not shared with any previously existing process.
        const NETWORK = libc::CLONE_NEWNET;
        /// Unshare the mount namespace, so that the calling process has a private copy
        /// of its namespace which is not shared with any other process. Specifying this
        /// flag automatically implies [`Namespaces::FS`] as well.
        const MOUNT = libc::CLONE_NEWNS;
        /// Unshare the PID namespace, so that the calling process has a new PID
        /// namespace for its children which is not shared with any previously existing
        /// process. The calling process is **not** moved into the new namespace. The
        /// first child created by the calling process will have the process ID 1 and
        /// will assume the role of init in the new namespace. Specifying this flag
        /// automatically implies [`libc::CLONE_THREAD`] as well.
        const PID = libc::CLONE_NEWPID;
        /// Unshare the time namespace, so that the calling process has a new time
        /// namespace for its children which is not shared with any previously existing
        /// process. The calling process is **not** moved into the new namespace.
        const TIME = 0x80;
        /// Unshare the user namespace, so that the calling process is moved into a new
        /// user namespace which is not shared with any previously existing process. The
        /// caller obtains a full set of capabilities in the new namespace.
        ///
        /// Requires that the calling process is not threaded; specifying this flag
        /// automatically implies [`libc::CLONE_THREAD`] and [`Namespaces::FS`] as well.
        const USER = libc::CLONE_NEWUSER;
        /// Unshare the UTS IPC namespace, so that the calling process has a private
        /// copy of the UTS namespace which is not shared with any other process.
        const UTS = libc::CLONE_NEWUTS;
        /// Unshare System V semaphore adjustment (semadj) values, so that the calling
        /// process has a new empty semadj list that is not shared with any other
        /// process. If this is the last process that has a reference to the process's
        /// current semadj list, then the adjustments in that list are applied to the
        /// corresponding semaphores
        const SYSVSEM = libc::CLONE_SYSVSEM;
    }
}
