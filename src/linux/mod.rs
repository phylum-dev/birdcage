//! Linux sandboxing.

use std::collections::HashMap;
use std::io::Error as IoError;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::{env, io};

use crate::error::{Error, Result};
use crate::linux::namespaces::MountAttrFlags;
use crate::linux::seccomp::SyscallFilter;
use crate::{Exception, Sandbox};

mod namespaces;
mod seccomp;

/// Linux sandboxing.
#[derive(Default)]
pub struct LinuxSandbox {
    env_exceptions: Vec<String>,
    path_exceptions: PathExceptions,
    allow_networking: bool,
    full_env: bool,
}

impl Sandbox for LinuxSandbox {
    fn new() -> Self {
        Self::default()
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        match exception {
            Exception::Read(path) => self.path_exceptions.update(path, false, false)?,
            Exception::WriteAndRead(path) => self.path_exceptions.update(path, true, false)?,
            Exception::ExecuteAndRead(path) => self.path_exceptions.update(path, false, true)?,
            Exception::Environment(key) => self.env_exceptions.push(key),
            Exception::FullEnvironment => self.full_env = true,
            Exception::Networking => self.allow_networking = true,
        }

        Ok(self)
    }

    fn lock(self) -> Result<()> {
        // Remove environment variables.
        if !self.full_env {
            crate::restrict_env_variables(&self.env_exceptions);
        }

        // Setup namespaces.
        namespaces::create_namespaces(self.allow_networking, self.path_exceptions)?;

        // Setup system call filters.
        SyscallFilter::apply()?;

        // Block suid/sgid.
        //
        // This is also blocked by our bind mount's MS_NOSUID flag, so we're just
        // doubling-down here.
        no_new_privs()?;

        Ok(())
    }
}

/// Path permissions required for the sandbox.
#[derive(Default)]
pub(crate) struct PathExceptions {
    bind_mounts: HashMap<PathBuf, MountAttrFlags>,
    symlinks: Vec<(PathBuf, PathBuf)>,
}

impl PathExceptions {
    /// Add or modify a path's exceptions.
    ///
    /// This will add a new bind mount for the canonical path with the specified
    /// permission if it does not exist already.
    ///
    /// If the bind mount already exists, it will *ADD* the additional
    /// permissions.
    fn update(&mut self, path: PathBuf, write: bool, execute: bool) -> Result<()> {
        // Use canonical path for indexing.
        //
        // This ensures that a symlink and its target are treated like the same path for
        // exceptions.
        //
        // If the home path cannot be accessed, we ignore the exception.
        let canonical_path = match path.canonicalize() {
            Ok(path) => path,
            Err(_) => return Err(Error::InvalidPath(path)),
        };

        // Store original symlink path to create it if necessary.
        if path_has_symlinks(&path) {
            // Normalize symlink's path.
            let absolute = absolute(&path)?;
            let normalized = normalize_path(&absolute);

            self.symlinks.push((normalized, canonical_path.clone()));
        }

        // Update bind mount's permission flags.

        let flags = self
            .bind_mounts
            .entry(canonical_path)
            .or_insert(MountAttrFlags::RDONLY | MountAttrFlags::NOEXEC);

        if write {
            flags.remove(MountAttrFlags::RDONLY);
        }

        if execute {
            flags.remove(MountAttrFlags::NOEXEC);
        }

        Ok(())
    }
}

/// Prevent suid/sgid.
fn no_new_privs() -> Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    match result {
        0 => Ok(()),
        _ => Err(IoError::last_os_error().into()),
    }
}

// Copied from Rust's STD:
// https://github.com/rust-lang/rust/blob/42faef503f3e765120ca0ef06991337668eafc32/library/std/src/sys/unix/path.rs#L23C1-L63C2
//
// Licensed under MIT:
// https://github.com/rust-lang/rust/blob/master/LICENSE-MIT
//
/// Make a POSIX path absolute without changing its semantics.
fn absolute(path: &Path) -> io::Result<PathBuf> {
    // This is mostly a wrapper around collecting `Path::components`, with
    // exceptions made where this conflicts with the POSIX specification.
    // See 4.13 Pathname Resolution, IEEE Std 1003.1-2017
    // https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html#tag_04_13

    // Get the components, skipping the redundant leading "." component if it
    // exists.
    let mut components = path.strip_prefix(".").unwrap_or(path).components();
    let path_os = path.as_os_str().as_bytes();

    let mut normalized = if path.is_absolute() {
        // "If a pathname begins with two successive <slash> characters, the
        // first component following the leading <slash> characters may be
        // interpreted in an implementation-defined manner, although more than
        // two leading <slash> characters shall be treated as a single <slash>
        // character."
        if path_os.starts_with(b"//") && !path_os.starts_with(b"///") {
            components.next();
            PathBuf::from("//")
        } else {
            PathBuf::new()
        }
    } else {
        env::current_dir()?
    };
    normalized.extend(components);

    // "Interfaces using pathname resolution may specify additional constraints
    // when a pathname that does not name an existing directory contains at
    // least one non- <slash> character and contains one or more trailing
    // <slash> characters".
    // A trailing <slash> is also meaningful if "a symbolic link is
    // encountered during pathname resolution".
    if path_os.ends_with(b"/") {
        normalized.push("");
    }

    Ok(normalized)
}

/// Normalize path components, stripping out `.` and `..`.
fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(_) => unreachable!("impl does not consider windows"),
            Component::RootDir => normalized.push("/"),
            Component::CurDir => continue,
            Component::ParentDir => {
                normalized.pop();
            },
            Component::Normal(segment) => normalized.push(segment),
        }
    }

    normalized
}

/// Check if a path contains any symlinks.
fn path_has_symlinks(path: &Path) -> bool {
    path.ancestors().any(|path| path.read_link().is_ok())
}
