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
//! Birdcage::new().unwrap().lock().unwrap();
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
    fn new() -> Result<Self>;

    /// Add a new exception to the sandbox.
    ///
    /// This exception opens up the sandbox to allow access for the specified
    /// operation. Once an exception is added, it is **not** possible to
    /// prohibit access to this resource without creating a new sandbox.
    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self>;

    /// Apply the sandbox restrictions to the current thread.
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

    /// Allow write access to the path and anything beneath it.
    Write(PathBuf),

    /// Allow executing and reading the path and anything beneath it.
    ///
    /// This is grouped with reading as a convenience, since execution will
    /// always also require read access.
    ExecuteAndRead(PathBuf),

    /// Allow reading an environment variable.
    Environment(String),

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
