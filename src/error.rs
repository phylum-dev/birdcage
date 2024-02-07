//! Sandboxing errors.

use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
#[cfg(target_os = "linux")]
use std::io::ErrorKind as IoErrorKind;
use std::path::PathBuf;
use std::result::Result as StdResult;

#[cfg(target_os = "linux")]
use seccompiler::{BackendError, Error as SeccompError};

/// Birdcage result type.
pub type Result<T> = StdResult<T, Error>;

/// Sandboxing error.
#[derive(Debug)]
pub enum Error {
    /// Seccomp errors.
    #[cfg(target_os = "linux")]
    Seccomp(SeccompError),

    /// Invalid sandbox exception path.
    InvalidPath(PathBuf),

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
            Self::Seccomp(error) => write!(f, "seccomp error: {error}"),
            Self::InvalidPath(path) => write!(f, "invalid path: {path:?}"),
            #[cfg(target_os = "linux")]
            Self::Io(error) if error.kind() == IoErrorKind::Unsupported => {
                write!(
                    f,
                    "unsupported operation, please ensure Kernel version is at least 5.12: {error}"
                )
            },
            Self::Io(error) => write!(f, "input/output error: {error}"),
            Self::ActivationFailed(error) => {
                write!(f, "failed to initialize a sufficient sandbox: {error}")
            },
        }
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

impl From<IoError> for Error {
    fn from(error: IoError) -> Self {
        Self::Io(error)
    }
}
