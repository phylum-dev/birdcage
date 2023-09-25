//! Linux sandboxing.
//!
//! This module implements sandboxing on Linux based on the Landlock LSM,
//! namespaces, and seccomp.

use std::collections::HashMap;
use std::path::PathBuf;

use landlock::{
    make_bitflags, Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI as LANDLOCK_ABI,
};

use crate::error::{Error, Result};
use crate::linux::seccomp::NetworkFilter;
use crate::{Exception, Sandbox};

mod namespaces;
mod seccomp;

/// Minimum landlock ABI version.
const ABI: LANDLOCK_ABI = LANDLOCK_ABI::V1;

/// Linux sandboxing.
pub struct LinuxSandbox {
    bind_mounts: HashMap<PathBuf, libc::c_ulong>,
    env_exceptions: Vec<String>,
    landlock: RulesetCreated,
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
        let flags = self.bind_mounts.entry(path).or_insert(libc::MS_RDONLY | libc::MS_NOEXEC);

        if write {
            *flags &= !libc::MS_RDONLY;
        }

        if execute {
            *flags &= !libc::MS_NOEXEC;
        }
    }
}

impl Sandbox for LinuxSandbox {
    fn new() -> Result<Self> {
        // Setup landlock filtering.
        let mut landlock = Ruleset::new()
            .set_best_effort(false)
            .handle_access(AccessFs::from_all(ABI))?
            .create()?;
        landlock.as_mut().set_no_new_privs(true);

        Ok(Self {
            landlock,
            allow_networking: false,
            full_env: false,
            env_exceptions: Default::default(),
            bind_mounts: Default::default(),
        })
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        let (path_fd, access) = match exception {
            Exception::Read(path) => {
                let path_fd = PathFd::new(&path)?;

                self.update_bind_mount(path, false, false);

                (path_fd, make_bitflags!(AccessFs::{ ReadFile | ReadDir }))
            },
            Exception::Write(path) => {
                let path_fd = PathFd::new(&path)?;

                self.update_bind_mount(path, true, false);

                (path_fd, AccessFs::from_write(ABI))
            },
            Exception::ExecuteAndRead(path) => {
                let path_fd = PathFd::new(&path)?;

                self.update_bind_mount(path, false, true);

                (path_fd, AccessFs::from_read(ABI))
            },
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

        let rule = PathBeneath::new(path_fd, access);

        self.landlock.as_mut().add_rule(rule)?;

        Ok(self)
    }

    fn lock(self) -> Result<()> {
        // Remove environment variables.
        if !self.full_env {
            crate::restrict_env_variables(&self.env_exceptions);
        }

        // Setup namespaces.
        let namespace_result =
            namespaces::create_namespaces(self.allow_networking, self.bind_mounts);

        // Setup seccomp network filter.
        if !self.allow_networking {
            let seccomp_result = NetworkFilter::apply();

            // Propagate failure if neither seccomp nor namespaces could isolate networking.
            if let (Err(_), Err(err)) = (&namespace_result, seccomp_result) {
                return Err(err);
            }
        }

        // Apply landlock rules.
        let landlock_result = self.landlock.restrict_self();

        // Ensure either landlock or namespaces are enforced.
        let status = match (landlock_result, namespace_result) {
            (Ok(status), _) => status,
            (Err(_), Ok(_)) => return Ok(()),
            (Err(err), _) => return Err(err.into()),
        };

        // Ensure all restrictions were properly applied.
        if status.no_new_privs && status.ruleset == RulesetStatus::FullyEnforced {
            Ok(())
        } else {
            Err(Error::ActivationFailed("sandbox could not be fully enforced".into()))
        }
    }
}
