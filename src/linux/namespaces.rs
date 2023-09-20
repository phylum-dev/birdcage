//! Linux namespaces.

use std::fs;
use std::io::Error as IoError;

use bitflags::bitflags;

use crate::error::Result;

/// Isolate process using Linux namespaces.
///
/// If successful, this will always clear the abstract namespace.
///
/// Additionally it will isolate network access if `deny_networking` is `true`.
pub fn create_namespaces(deny_networking: bool) -> Result<()> {
    // Get EUID/EGID outside of the namespace.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };

    // Setup the network namespace.
    if deny_networking {
        create_user_namespace(uid, gid, 0, 0, Namespaces::NETWORK)?;
    }

    // Drop root user mapping and ensure abstract namespace is cleared.
    create_user_namespace(uid, gid, uid, gid, Namespaces::empty())?;

    Ok(())
}

/// Create a new user namespace.
///
/// The parent and child UIDs and GIDs define the user and group mappings
/// between the parent namespace and the new user namespace.
fn create_user_namespace(
    parent_uid: u32,
    parent_gid: u32,
    child_uid: u32,
    child_gid: u32,
    extra_namespaces: Namespaces,
) -> Result<()> {
    // Create the namespace.
    unshare(Namespaces::USER | extra_namespaces)?;

    // Map the UID and GID.
    let uid_map = format!("{child_uid} {parent_uid} 1\n");
    let gid_map = format!("{child_gid} {parent_gid} 1\n");
    fs::write("/proc/self/uid_map", uid_map.as_bytes())?;
    fs::write("/proc/self/setgroups", b"deny")?;
    fs::write("/proc/self/gid_map", gid_map.as_bytes())?;

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
