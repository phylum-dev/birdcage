//! Birdcage sandbox.
//!
//! This crate provides a cross-platform API for an embedded sandbox for macOS
//! and Linux.
//!
//! # Example
//!
//! ```rust
//! use std::fs;
//! use std::process::Command;
//!
//! use birdcage::{Birdcage, Exception, Sandbox};
//! use tempfile::NamedTempFile;
//!
//! // Setup our test file.
//! let file = NamedTempFile::new().unwrap();
//!
//! // Reads without sandbox work.
//! fs::read_to_string(file.path()).unwrap();
//!
//! // Allow access to our test executable.
//! let mut sandbox = Birdcage::new();
//! sandbox.add_exception(Exception::ExecuteAndRead("/bin/cat".into())).unwrap();
//! let _ = sandbox.add_exception(Exception::ExecuteAndRead("/lib64".into()));
//! let _ = sandbox.add_exception(Exception::ExecuteAndRead("/lib".into()));
//!
//! // Initialize the sandbox; by default everything is prohibited.
//! let mut command = Command::new("/bin/cat");
//! command.arg(file.path());
//! let mut child = sandbox.spawn(command).unwrap();
//!
//! // Reads with sandbox should fail.
//! let status = child.wait().unwrap();
//! assert!(!status.success());
//! ```

use std::env;
use std::path::PathBuf;
use std::process::{Child, Command};

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
    /// Exceptions added for symlinks will also automatically apply to the
    /// symlink's target.
    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self>;

    /// Setup sandbox and spawn a new process.
    ///
    /// This will setup the sandbox in the **CURRENT** process, before launching
    /// the sandboxee. Since most of the restrictions will also be applied to
    /// the calling process, it is recommended to create a separate process
    /// before calling this method. The calling process is **NOT** fully
    /// sandboxed.
    ///
    /// # Errors
    ///
    /// Sandboxing will fail if the calling process is not single-threaded.
    ///
    /// After failure, the calling process might still be affected by partial
    /// sandboxing restrictions.
    fn spawn(self, sandboxee: Command) -> Result<Child>;
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
