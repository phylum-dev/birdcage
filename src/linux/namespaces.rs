//! Linux namespaces.

use std::cmp::Ordering;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::Error as IoError;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unixfs;
use std::path::{Component, Path, PathBuf};
use std::{env, io, mem, ptr};

use bitflags::bitflags;

use crate::linux::PathExceptions;

/// Path for mount namespace's new root.
const NEW_ROOT: &str = "/tmp/birdcage-root";

/// Isolate filesystem access in an existing mount namespace.
///
/// This will deny access to any path which isn't part of `bind_mounts`. Allowed
/// paths are mounted according to their bind mount flags.
pub(crate) fn setup_mount_namespace(exceptions: PathExceptions) -> io::Result<()> {
    // Get target paths for new and old root.
    let new_root = PathBuf::from(NEW_ROOT);

    // Ensure new root is available as an empty directory.
    if !new_root.exists() {
        fs::create_dir_all(&new_root)?;
    }

    // Create C-friendly versions for our paths.
    let new_root_c = CString::new(new_root.as_os_str().as_bytes()).unwrap();

    // Create tmpfs mount for the new root, allowing pivot and ensuring directories
    // aren't created outside the sandbox.
    mount_tmpfs(&new_root_c)?;

    // Sort bind mounts by shortest length, to create parents before their children.
    let mut bind_mounts: Vec<_> = exceptions.bind_mounts.into_iter().collect();
    bind_mounts.sort_unstable_by(|(a_path, a_flags), (b_path, b_flags)| {
        match a_path.components().count().cmp(&b_path.components().count()) {
            Ordering::Equal => (a_path, a_flags).cmp(&(b_path, b_flags)),
            ord => ord,
        }
    });

    // Bind mount all allowed directories.
    for (path, flags) in bind_mounts {
        let src_c = CString::new(path.as_os_str().as_bytes()).unwrap();

        // Get bind mount destination.
        let unrooted_path = path.strip_prefix("/").unwrap();
        let dst = new_root.join(unrooted_path);
        let dst_c = CString::new(dst.as_os_str().as_bytes()).unwrap();

        // Create mount target.
        if let Err(err) = copy_tree(&path, &new_root) {
            log::error!("skipping birdcage exception {path:?}: {err}");
            continue;
        }

        // Bind path with full permissions.
        bind_mount(&src_c, &dst_c)?;

        // Remount to update permissions.
        update_mount_flags(&dst_c, flags | MountAttrFlags::NOSUID)?;
    }

    // Ensure original symlink paths are available.
    create_symlinks(&new_root, exceptions.symlinks)?;

    // Bind mount old procfs.
    let old_proc_c = CString::new("/proc").unwrap();
    let new_proc = new_root.join("proc");
    let new_proc_c = CString::new(new_proc.as_os_str().as_bytes()).unwrap();
    fs::create_dir_all(&new_proc)?;
    bind_mount(&old_proc_c, &new_proc_c)?;

    // Pivot root to `new_root`, placing the old root at the same location.
    pivot_root(&new_root_c, &new_root_c)?;

    // Remove old root mounted at /, leaving only the new root at the same location.
    let root_c = CString::new("/").unwrap();
    umount(&root_c)?;

    // Prevent child mount namespaces from accessing this namespace's mounts.
    deny_mount_propagation()?;

    Ok(())
}

/// Create missing symlinks.
///
/// If the parent directory of a symlink is mapped, we do not need to map the
/// symlink ourselves and it's not possible to mount on top of it anyway. So
/// here we make sure that symlinks are created if no bind mount was created for
/// their parent directory.
fn create_symlinks(new_root: &Path, symlinks: Vec<(PathBuf, PathBuf)>) -> io::Result<()> {
    for (symlink, target) in symlinks {
        // Ignore symlinks if a parent bind mount exists.
        let unrooted_path = symlink.strip_prefix("/").unwrap();
        let dst = new_root.join(unrooted_path);
        if dst.symlink_metadata().is_ok() {
            continue;
        }

        // Create all parent directories.
        let parent = match symlink.parent() {
            Some(parent) => parent,
            None => continue,
        };
        copy_tree(parent, new_root)?;

        // Create the symlink.
        unixfs::symlink(target, dst)?;
    }

    Ok(())
}

/// Replicate a directory tree under a different directory.
///
/// This will create all missing empty diretories and copy their permissions
/// from the source tree.
///
/// If `src` ends in a file, an empty file with matching permissions will be
/// created.
fn copy_tree(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    let mut dst = dst.as_ref().to_path_buf();
    let mut src_sub = PathBuf::new();
    let src = src.as_ref();

    for component in src.components() {
        // Append root only to source.
        if component == Component::RootDir {
            src_sub = src_sub.join(component);
            continue;
        }

        src_sub = src_sub.join(component);
        dst = dst.join(component);

        // Skip nodes that already exist.
        if dst.exists() {
            continue;
        }

        // Create target file/directory.
        let metadata = src_sub.metadata()?;
        if metadata.is_dir() {
            fs::create_dir(&dst)?;
        } else {
            File::create(&dst)?;
        }

        // Copy permissions.
        let permissions = metadata.permissions();
        fs::set_permissions(&dst, permissions)?;
    }

    Ok(())
}

/// Mount a new tmpfs.
fn mount_tmpfs(dst: &CStr) -> io::Result<()> {
    let flags = MountFlags::empty();
    let fstype = CString::new("tmpfs").unwrap();
    let res = unsafe {
        libc::mount(ptr::null(), dst.as_ptr(), fstype.as_ptr(), flags.bits(), ptr::null())
    };

    if res == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error())
    }
}

/// Mount a new procfs.
pub fn mount_proc(dst: &CStr) -> io::Result<()> {
    let flags = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
    let fstype = CString::new("proc").unwrap();
    let res = unsafe {
        libc::mount(fstype.as_ptr(), dst.as_ptr(), fstype.as_ptr(), flags.bits(), ptr::null())
    };

    if res == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error())
    }
}

/// Create a new bind mount.
fn bind_mount(src: &CStr, dst: &CStr) -> io::Result<()> {
    let flags = MountFlags::BIND | MountFlags::RECURSIVE;
    let res =
        unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), ptr::null(), flags.bits(), ptr::null()) };

    if res == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error())
    }
}

/// Remount an existing bind mount with a new set of mount flags.
fn update_mount_flags(mount: &CStr, flags: MountAttrFlags) -> io::Result<()> {
    let attrs = MountAttr { attr_set: flags.bits(), ..Default::default() };

    let res = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            mount.as_ptr(),
            libc::AT_RECURSIVE,
            &attrs as *const _,
            mem::size_of::<MountAttr>(),
        )
    };

    if res == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error())
    }
}

/// Recursively update the root to deny mount propagation.
fn deny_mount_propagation() -> io::Result<()> {
    let flags = MountFlags::PRIVATE | MountFlags::RECURSIVE;
    let root = CString::new("/").unwrap();
    let res =
        unsafe { libc::mount(ptr::null(), root.as_ptr(), ptr::null(), flags.bits(), ptr::null()) };

    if res == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error())
    }
}

/// Change root directory to `new_root` and mount the old root in `put_old`.
///
/// The `put_old` directory must be at or undearneath `new_root`.
fn pivot_root(new_root: &CStr, put_old: &CStr) -> io::Result<()> {
    // Get target working directory path.
    let working_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));

    let result =
        unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) };

    if result != 0 {
        return Err(IoError::last_os_error());
    }

    // Attempt to recover working directory, or switch to root.
    //
    // Without this, the user's working directory would stay the same, giving him
    // full access to it even if it is not bound.
    if env::set_current_dir(working_dir).is_err() {
        env::set_current_dir("/")?;
    }

    Ok(())
}

/// Unmount a filesystem.
fn umount(target: &CStr) -> io::Result<()> {
    let result = unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };

    match result {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

/// Create a new user namespace.
///
/// The parent and child UIDs and GIDs define the user and group mappings
/// between the parent namespace and the new user namespace.
pub fn create_user_namespace(
    child_uid: u32,
    child_gid: u32,
    extra_namespaces: Namespaces,
) -> io::Result<()> {
    // Get current user's EUID and EGID.
    let parent_uid = unsafe { libc::geteuid() };
    let parent_gid = unsafe { libc::getegid() };

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
fn unshare(namespaces: Namespaces) -> io::Result<()> {
    let result = unsafe { libc::unshare(namespaces.bits()) };
    match result {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

bitflags! {
    /// Mount syscall flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MountFlags: libc::c_ulong {
        /// Ignore suid and sgid bits.
        const NOSUID = libc::MS_NOSUID;
        /// Disallow access to device special files.
        const NODEV = libc::MS_NODEV;
        /// Disallow program execution.
        const NOEXEC = libc::MS_NOEXEC;
        /// Create a bind mount.
        const BIND = libc::MS_BIND;
        /// Used in conjuction with [`Self::BIND`] to create a recursive bind mount, and
        /// in conjuction with the propagation type flags to recursively change the
        /// propagation type of all of the mounts in a sub-tree.
        const RECURSIVE = libc::MS_REC;
        /// Make this mount private. Mount and unmount events do not propagate into or
        /// out of this mount.
        const PRIVATE = libc::MS_PRIVATE;
        /// Do not follow symbolic links when resolving paths.
        const NOSYMFOLLOW = 256;
    }
}

/// Parameter for the `mount_setattr` syscall.
#[repr(C)]
#[derive(Default)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

bitflags! {
    /// Flags for the `mount_setattr` syscall.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MountAttrFlags: u64 {
        /// Mount read-only.
        const RDONLY          = 0x00000001;
        /// Ignore suid and sgid bits.
        const NOSUID          = 0x00000002;
        /// Disallow access to device special files.
        const NODEV	          = 0x00000004;
        /// Disallow program execution.
        const NOEXEC          = 0x00000008;

        /// Setting on how atime should be updated.
        const _ATIME          = 0x00000070;
        /// - Update atime relative to mtime/ctime.
        const RELATI          = 0x00000000;
        /// - Do not update access times.
        const NOATIM          = 0x00000010;
        /// - Always perform atime updates.
        const STRICTATIME     = 0x00000020;

        /// Do not update directory access times.
        const NODIRATIME      = 0x00000080;
        /// Idmap mount to @userns_fd in struct mount_attr.
        const IDMAP           = 0x00100000;
        /// Do not follow symlinks.
        const NOSYMFOLLOW     = 0x00200000;
    }
}

bitflags! {
    /// Unshare system call namespace flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Namespaces: libc::c_int {
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
