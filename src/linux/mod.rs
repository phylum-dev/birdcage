//! Linux sandboxing.

use std::collections::HashMap;
use std::io::Error as IoError;
use std::path::PathBuf;

use crate::error::Result;
use crate::linux::namespaces::MountFlags;
use crate::linux::seccomp::SyscallFilter;
use crate::{Exception, Sandbox};

mod namespaces;
mod seccomp;

/// Linux sandboxing.
#[derive(Default)]
pub struct LinuxSandbox {
    bind_mounts: HashMap<PathBuf, MountFlags>,
    env_exceptions: Vec<String>,
    allow_networking: bool,
    full_env: bool,
}

impl LinuxSandbox {
    /// Add or modify a bind mount.
    ///
    /// This will add a new bind mount with the specified permission if it does
    /// not exist already.
    ///
    /// If the bind mount already exists, it will *ADD* the additional
    /// permissions.
    fn update_bind_mount(&mut self, path: PathBuf, write: bool, execute: bool) {
        let flags =
            self.bind_mounts.entry(path).or_insert(MountFlags::READONLY | MountFlags::NOEXEC);

        if write {
            flags.remove(MountFlags::READONLY);
        }

        if execute {
            flags.remove(MountFlags::NOEXEC);
        }
    }
}

impl Sandbox for LinuxSandbox {
    fn new() -> Self {
        Self::default()
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        match exception {
            Exception::Read(path) => self.update_bind_mount(path, false, false),
            Exception::Write(path) => self.update_bind_mount(path, true, false),
            Exception::ExecuteAndRead(path) => self.update_bind_mount(path, false, true),
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
        namespaces::create_namespaces(self.allow_networking, self.bind_mounts)?;

        // Setup seccomp filters.
        SyscallFilter::apply()?;

        // Block suid/sgid.
        //
        // This is also blocked by our bind mount's MS_NOSUID flag, so we're just
        // doubling-down here.
        no_new_privs()?;

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
