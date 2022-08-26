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
    Unsupported,
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(target_os = "linux")]
            Self::Ruleset(error) => write!(f, "landlock ruleset error: {error}"),
            #[cfg(target_os = "linux")]
            Self::PathFd(error) => write!(f, "invalid path: {error}"),
            Self::Unsupported => write!(f, "failed to initialize a sufficient sandbox"),
        }
    }
}

#[cfg(target_os = "linux")]
impl From<RulesetError> for Error {
    fn from(error: RulesetError) -> Self {
        Self::Ruleset(error)
    }
}

#[cfg(target_os = "linux")]
impl From<PathFdError> for Error {
    fn from(error: PathFdError) -> Self {
        Self::PathFd(error)
    }
}
