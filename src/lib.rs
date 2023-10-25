//! Birdcage sandbox.
//!
//! This crate provides a cross-platform API for an embedded sandbox for macOS
//! and Linux.
//!
//! # Example
//!
//! ```rust
//! use std::fs;
//!
//! use birdcage::{Birdcage, Sandbox};
//! use tempfile::NamedTempFile;
//!
//! // Setup our test file.
//! let file = NamedTempFile::new().unwrap();
//!
//! // Reads without sandbox work.
//! fs::read_to_string(file.path()).unwrap();
//!
//! // Initialize the sandbox; by default everything is prohibited.
//! Birdcage::new().lock().unwrap();
//!
//! // Reads with sandbox should fail.
//! let result = fs::read_to_string(file.path());
//! assert!(result.is_err());
//! ```

use std::env;
use std::path::PathBuf;

use crate::error::Result;
#[cfg(target_os = "linux")]
use crate::linux::LinuxSandbox;
#[cfg(target_os = "macos")]
use crate::macos::MacSandbox;

pub mod error;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// Default platform sandbox.
///
/// This type will automatically pick the default sandbox for each available
/// platform.
#[cfg(target_os = "linux")]
pub type Birdcage = LinuxSandbox;

/// Default platform sandbox.
///
/// This type will automatically pick the default sandbox for each available
/// platform.
#[cfg(target_os = "macos")]
pub type Birdcage = MacSandbox;

pub trait Sandbox: Sized {
    /// Setup the sandboxing environment.
    fn new() -> Self;

    /// Add a new exception to the sandbox.
    ///
    /// This exception opens up the sandbox to allow access for the specified
    /// operation. Once an exception is added, it is **not** possible to
    /// prohibit access to this resource without creating a new sandbox.
    ///
    /// Exceptions added for symlinks will also automatically apply to the
    /// symlink's target.
    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self>;

    /// Apply the sandbox restrictions to the current process.
    ///
    /// # Errors
    ///
    /// Sandboxing will fail if the calling process is not single-threaded.
    ///
    /// Since sandboxing layers are applied in multiple steps, it is possible
    /// that after a failure some restrictions are still applied. While this
    /// never allows the process to do things it wasn't capable of doing
    /// before, it is still recommended to abort the sandboxing process if
    /// you want to continue operations without a sandbox in place.
    fn lock(self) -> Result<()>;
}

/// Sandboxing exception rule.
///
/// An exception excludes certain resources from the sandbox, allowing sandboxed
/// applications to still access these resources.
#[derive(Debug, Clone)]
pub enum Exception {
    /// Allow read access to the path and anything beneath it.
    Read(PathBuf),

    /// Allow writing and reading the path and anything beneath it.
    WriteAndRead(PathBuf),

    /// Allow executing and reading the path and anything beneath it.
    ///
    /// This is grouped with reading as a convenience, since execution will
    /// always also require read access.
    ExecuteAndRead(PathBuf),

    /// Allow reading an environment variable.
    Environment(String),

    /// Allow reading **all** environment variables.
    FullEnvironment,

    /// Allow networking.
    Networking,
}

/// Restrict access to environment variables.
pub(crate) fn restrict_env_variables(exceptions: &[String]) {
    // Invalid unicode will cause `env::vars()` to panic, so we don't have to worry
    // about them getting ignored.
    for (key, _) in env::vars().filter(|(key, _)| !exceptions.contains(key)) {
        env::remove_var(key);
    }
}
