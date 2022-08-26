//! Sandboxing errors.

use std::error::Error as StdError;
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
#[cfg(target_os = "macos")]
use std::io::Error as IoError;

#[cfg(target_os = "linux")]
use landlock::{PathFdError, RulesetError};

/// Sandboxing error.
#[derive(Debug)]
pub enum Error {
    /// Landlock ruleset creation/modification error.
    #[cfg(target_os = "linux")]
    Ruleset(RulesetError),

    /// Invalid sandbox exception path.
    #[cfg(target_os = "linux")]
    InvalidPath(PathFdError),
    #[cfg(target_os = "macos")]
    InvalidPath(OsString),

    /// I/O error.
    #[cfg(target_os = "macos")]
    Io(IoError),

    /// Sandbox activation failed.
    ActivationFailed(String),
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(target_os = "linux")]
            Self::Ruleset(error) => write!(f, "landlock ruleset error: {error}"),
            #[cfg(target_os = "linux")]
            Self::InvalidPath(error) => write!(f, "invalid path: {error}"),
            #[cfg(target_os = "macos")]
            Self::InvalidPath(error) => write!(f, "invalid path: {error:?}"),
            #[cfg(target_os = "macos")]
            Self::Io(error) => write!(f, "input/output error: {error}"),
            Self::ActivationFailed(error) => {
                write!(f, "failed to initialize a sufficient sandbox: {error}")
            },
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
        Self::InvalidPath(error)
    }
}

#[cfg(target_os = "macos")]
impl From<OsString> for Error {
    fn from(error: OsString) -> Self {
        Self::InvalidPath(error)
    }
}

#[cfg(target_os = "macos")]
impl From<IoError> for Error {
    fn from(error: IoError) -> Self {
        Self::Io(error)
    }
}
