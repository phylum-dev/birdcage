//! Sandboxing errors.

use std::error::Error as StdError;
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::result::Result as StdResult;

#[cfg(target_os = "linux")]
use landlock::{PathFdError, RulesetError};
#[cfg(target_os = "linux")]
use seccompiler::{BackendError, Error as SeccompError};

/// Birdcage result type.
pub type Result<T> = StdResult<T, Error>;

/// Sandboxing error.
#[derive(Debug)]
pub enum Error {
    /// Landlock ruleset creation/modification error.
    #[cfg(target_os = "linux")]
    Ruleset(RulesetError),

    /// Seccomp errors.
    #[cfg(target_os = "linux")]
    Seccomp(SeccompError),

    /// Invalid sandbox exception path.
    #[cfg(target_os = "linux")]
    InvalidPath(PathFdError),
    #[cfg(target_os = "macos")]
    InvalidPath(InvalidPathError),

    /// I/O error.
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
            Self::Seccomp(error) => write!(f, "seccomp error: {error}"),
            #[cfg(target_os = "linux")]
            Self::InvalidPath(error) => write!(f, "invalid path: {error}"),
            #[cfg(target_os = "macos")]
            Self::InvalidPath(error) => write!(f, "invalid path: {error:?}"),
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
impl From<SeccompError> for Error {
    fn from(error: SeccompError) -> Self {
        Self::Seccomp(error)
    }
}

#[cfg(target_os = "linux")]
impl From<BackendError> for Error {
    fn from(error: BackendError) -> Self {
        Self::Seccomp(SeccompError::Backend(error))
    }
}

#[cfg(target_os = "linux")]
impl From<PathFdError> for Error {
    fn from(error: PathFdError) -> Self {
        Self::InvalidPath(error)
    }
}

#[cfg(target_os = "macos")]
impl From<InvalidPathError> for Error {
    fn from(error: InvalidPathError) -> Self {
        Self::InvalidPath(error)
    }
}

impl From<IoError> for Error {
    fn from(error: IoError) -> Self {
        Self::Io(error)
    }
}

/// Invalid sandbox exception path.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct InvalidPathError(String);

#[cfg(target_os = "macos")]
impl StdError for InvalidPathError {}

#[cfg(target_os = "macos")]
impl Display for InvalidPathError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "invalid path: {}", self.0)
    }
}

#[cfg(target_os = "macos")]
impl From<IoError> for InvalidPathError {
    fn from(error: IoError) -> Self {
        InvalidPathError(error.to_string())
    }
}

#[cfg(target_os = "macos")]
impl From<OsString> for InvalidPathError {
    fn from(error: OsString) -> Self {
        InvalidPathError(error.to_string_lossy().into_owned())
    }
}
