//! Landlock sandbox.
//!
//! This module implements sandboxing on Linux based on the Landlock LSM.

use landlock::{
    Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetCreated, RulesetStatus,
    ABI as LANDLOCK_ABI,
};

use crate::error::Error;
use crate::{Exception, Sandbox};

/// Minimum landlock ABI version.
const ABI: LANDLOCK_ABI = LANDLOCK_ABI::V1;

/// Landlock sandbox state.
pub struct Landlock {
    ruleset: RulesetCreated,
}

impl Sandbox for Landlock {
    fn new() -> Result<Self, Error> {
        let mut ruleset = Ruleset::new()
            .set_best_effort(false)
            .handle_access(AccessFs::from_all(ABI))?
            .create()?;
        ruleset.set_no_new_privs(true);

        Ok(Self { ruleset })
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self, Error> {
        let (path, access) = match exception {
            Exception::Read(path) => (path, AccessFs::from_read(ABI)),
            Exception::Write(path) => (path, AccessFs::from_write(ABI)),
        };

        let rule = PathBeneath::new(PathFd::new(path)?, access);

        self.ruleset.add_rule(rule)?;

        Ok(self)
    }

    fn lock(self) -> Result<(), Error> {
        let status = self.ruleset.restrict_self()?;

        // Ensure all restrictions were properly applied.
        if status.no_new_privs && status.ruleset == RulesetStatus::FullyEnforced {
            Ok(())
        } else {
            Err(Error::PartialSupport)
        }
    }
}
