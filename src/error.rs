//! Sandboxing errors.

use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};

#[cfg(target_os = "linux")]
use landlock::{PathFdError, RulesetError};

/// Sandboxing error.
#[derive(Debug)]
pub enum Error {
    /// Landlock ruleset creation/modification error.
    #[cfg(target_os = "linux")]
    Ruleset(RulesetError),

    /// Invalid Landlock rule path.
    #[cfg(target_os = "linux")]
    PathFd(PathFdError),

    /// Platform lacks sandboxing support.
    #[cfg(target_os = "linux")]
    PartialSupport,
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ruleset(error) => write!(f, "landlock ruleset error: {error}"),
            Self::PathFd(error) => write!(f, "invalid path: {error}"),
            Self::PartialSupport => write!(f, "failed to initialize a complete sandbox"),
        }
    }
}

impl From<RulesetError> for Error {
    fn from(error: RulesetError) -> Self {
        Self::Ruleset(error)
    }
}

impl From<PathFdError> for Error {
    fn from(error: PathFdError) -> Self {
        Self::PathFd(error)
    }
}
