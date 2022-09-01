//! Linux sandboxing.
//!
//! This module implements sandboxing on Linux based on the Landlock LSM,
//! combined with seccomp for anything other than the filesystem.

use landlock::{
    make_bitflags, Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetCreated,
    RulesetStatus, ABI as LANDLOCK_ABI,
};

use crate::error::{Error, Result};
use crate::linux::seccomp::Filter;
use crate::{Exception, Sandbox};

mod seccomp;

/// Minimum landlock ABI version.
const ABI: LANDLOCK_ABI = LANDLOCK_ABI::V1;

/// Linux sandboxing based on Landlock and Seccomp.
pub struct LinuxSandbox {
    landlock: RulesetCreated,
    seccomp: Filter,
}

impl Sandbox for LinuxSandbox {
    fn new() -> Result<Self> {
        // Setup landlock filtering.
        let mut landlock = Ruleset::new()
            .set_best_effort(false)
            .handle_access(AccessFs::from_all(ABI))?
            .create()?;
        landlock.set_no_new_privs(true);

        // Setup seccomp filtering.
        let mut seccomp = Filter::new();
        seccomp.allow_benign();

        // Always allow local I/O and execute since, this is handled by Landlock.
        seccomp.allow_sockets(true)?;
        seccomp.allow_exec();
        seccomp.allow_fs();

        Ok(Self { landlock, seccomp })
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        let (path, access) = match exception {
            Exception::Read(path) => (path, make_bitflags!(AccessFs::{ ReadFile | ReadDir })),
            Exception::Write(path) => (path, AccessFs::from_write(ABI)),
            Exception::ReadAndExecute(path) => (path, AccessFs::from_read(ABI)),
            Exception::Networking => {
                self.seccomp.allow_sockets(false)?;
                return Ok(self);
            },
        };

        let rule = PathBeneath::new(PathFd::new(path)?, access);

        self.landlock.add_rule(rule)?;

        Ok(self)
    }

    fn lock(self) -> Result<()> {
        let status = self.landlock.restrict_self()?;
        self.seccomp.apply()?;

        // Ensure all restrictions were properly applied.
        if status.no_new_privs && status.ruleset == RulesetStatus::FullyEnforced {
            Ok(())
        } else {
            Err(Error::ActivationFailed("sandbox could not be fully enforced".into()))
        }
    }
}
