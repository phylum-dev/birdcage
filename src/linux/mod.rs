//! Linux sandboxing.
//!
//! This module implements sandboxing on Linux based on the Landlock LSM,
//! combined with seccomp for anything other than the filesystem.

use landlock::{
    make_bitflags, Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI as LANDLOCK_ABI,
};

use crate::error::{Error, Result};
use crate::linux::seccomp::Filter;
use crate::{Exception, Sandbox};

mod seccomp;

/// Minimum landlock ABI version.
const ABI: LANDLOCK_ABI = LANDLOCK_ABI::V1;

/// Linux sandboxing based on Landlock and Seccomp.
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

        // Create and apply seccomp filter.
        let mut seccomp = Filter::new();
        if !self.allow_networking {
            seccomp.deny_networking()?;
        }
        seccomp.apply()?;

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
