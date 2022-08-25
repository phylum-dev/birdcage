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
//! fn main() {
//!     // Setup our test file.
//!     let file = NamedTempFile::new().unwrap();
//!
//!     // Reads without sandbox work.
//!     fs::read_to_string(file.path()).unwrap();
//!
//!     // Initialize the sandbox; by default everything is prohibited.
//!     Birdcage::new().unwrap().lock().unwrap();
//!
//!     // Reads with sandbox should fail.
//!     let result = fs::read_to_string(file.path());
//!     assert!(result.is_err());
//! }
//! ```

use std::path::PathBuf;

use crate::error::Error;
#[cfg(target_os = "linux")]
use crate::linux::Landlock;

mod error;
#[cfg(target_os = "linux")]
mod linux;

/// Default platform sandbox.
///
/// This type will automatically pick the default sandbox for each available
/// platform.
#[cfg(target_os = "linux")]
pub type Birdcage = Landlock;

pub trait Sandbox {
    /// Setup the sandboxing environment.
    fn new() -> Result<Self, Error>
    where
        Self: Sized;

    /// Add a new exception to the sandbox.
    ///
    /// This exception opens up the sandbox to allow access for the specified
    /// operation. Once an exception is added, it is **not** possible to
    /// prohibit access to this resource without creating a new sandbox.
    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self, Error>;

    /// Apply the sandbox restrictions to the current thread.
    fn lock(self) -> Result<(), Error>;
}

/// Sandboxing exception rule.
///
/// An exception excludes certain resources from the sandbox, allowing sandboxed
/// applications to still access these resources.
pub enum Exception {
    /// Allow read access to the path and anything beneath it.
    Read(PathBuf),

    /// Allow write access to the path and anything beneath it.
    Write(PathBuf),
}
