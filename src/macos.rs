//! Linux sandboxing.
//!
//! This module implements sandboxing on macOS using `sandbox_init`.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::{fs, ptr};

use bitflags::bitflags;

use crate::error::{Error, Result};
use crate::{Exception, Sandbox};

/// Deny-all fallback rule.
static DEFAULT_RULE: &[u8] = b"\
(version 1)
(import \"system.sb\")

(deny default)
(allow mach*)
(allow ipc*)
(allow signal (target others))
(allow process-fork)
(allow sysctl*)
(allow system*)
(allow file-read-metadata)
(system-network)
";

/// macOS sandboxing based on Seatbelt.
#[derive(Default)]
pub struct MacSandbox {
    path_exceptions: HashMap<String, PathException>,
    env_exceptions: Vec<String>,
    net_exception: bool,
    full_env: bool,
}

impl Sandbox for MacSandbox {
    fn new() -> Self {
        Self::default()
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        match exception {
            Exception::Read(path) => self.update_path_exceptions(path, PathException::READ)?,
            Exception::WriteAndRead(path) => {
                self.update_path_exceptions(path, PathException::WRITE | PathException::READ)?
            },
            Exception::ExecuteAndRead(path) => {
                self.update_path_exceptions(path, PathException::EXECUTE | PathException::READ)?
            },
            Exception::Networking => self.net_exception = true,
            Exception::Environment(key) => {
                self.env_exceptions.push(key);
                return Ok(self);
            },
            Exception::FullEnvironment => {
                self.full_env = true;
                return Ok(self);
            },
        }
        Ok(self)
    }

    fn lock(self) -> Result<()> {
        // Remove environment variables.
        if !self.full_env {
            crate::restrict_env_variables(&self.env_exceptions);
        }

        // Create the seatbelt sandbox profile.
        let profile = self.create_profile()?;
        let profile =
            CString::new(profile).map_err(|_| Error::ActivationFailed("invalid profile".into()))?;

        let mut error = ptr::null_mut();
        let result = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };

        if result == 0 {
            Ok(())
        } else {
            unsafe {
                let error_text = CStr::from_ptr(error)
                    .to_str()
                    .map_err(|_| Error::ActivationFailed("sandbox_init failed".into()))?
                    .to_owned();
                sandbox_free_error(error);

                Err(Error::ActivationFailed(error_text))
            }
        }
    }
}

impl MacSandbox {
    /// Add or modify a path's exceptions.
    fn update_path_exceptions(&mut self, path: PathBuf, exceptions: PathException) -> Result<()> {
        // Canonicalize all exception paths.
        //
        // Since the macOS sandbox only cares about permissions for symlink targets, due
        // to the `(allow file-read-metadata)` rule, we don't need to bother with
        // keeping the original paths.
        let escaped_path = escape_path(&path)?;

        let exception = self.path_exceptions.entry(escaped_path).or_insert(PathException::empty());
        exception.insert(exceptions);

        Ok(())
    }

    /// Create a seatbelt profile for the requested sandbox configuration.
    fn create_profile(&self) -> Result<Vec<u8>> {
        let mut profile = DEFAULT_RULE.to_vec();

        // Sort by component count to ensure parent paths appear before descendants.
        let mut path_exceptions: Vec<_> = self.path_exceptions.iter().collect();
        path_exceptions.sort_unstable_by(|a, b| a.0.len().cmp(&b.0.len()));

        for (path, exception) in path_exceptions {
            // Deny all access to clear existing permission grants.
            Self::revoke_path_access(&mut profile, path)?;

            if exception.contains(PathException::READ) {
                let rule = PathRule::new(RuleMode::Allow, "file-read*", path.into());
                rule.write_to(&mut profile)?;
            }
            if exception.contains(PathException::WRITE) {
                let rule = PathRule::new(RuleMode::Allow, "file-write*", path.into());
                rule.write_to(&mut profile)?;
            }
            if exception.contains(PathException::EXECUTE) {
                let rule = PathRule::new(RuleMode::Allow, "process-exec", path.into());
                rule.write_to(&mut profile)?;
            }
        }

        if self.net_exception {
            profile.write_all(b"(allow network*)\n")?;
        }

        Ok(profile)
    }

    /// Revoke all access permisisons for a path.
    ///
    /// This is necessary to grant more restrictive permissions to a child of a
    /// directory which was previously granted permissions.
    fn revoke_path_access(buffer: &mut Vec<u8>, path: &str) -> Result<()> {
        let rule = PathRule::new(RuleMode::Deny, "file-read*", path.into());
        rule.write_to(buffer)?;

        let rule = PathRule::new(RuleMode::Deny, "file-write*", path.into());
        rule.write_to(buffer)?;

        let rule = PathRule::new(RuleMode::Deny, "process-exec", path.into());
        rule.write_to(buffer)?;

        Ok(())
    }
}

struct PathRule {
    mode: RuleMode,
    access_type: &'static str,
    path: String,
}

impl PathRule {
    fn new(mode: RuleMode, access_type: &'static str, path: String) -> Self {
        Self { mode, access_type, path }
    }

    /// Write this rule to a profile.
    fn write_to(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_all(b"(")?;
        buffer.write_all(self.mode.as_str().as_bytes())?;
        buffer.write_all(b" ")?;

        buffer.write_all(self.access_type.as_bytes())?;

        buffer.write_all(b" (subpath ")?;
        buffer.write_all(self.path.as_bytes())?;
        buffer.write_all(b"))\n")?;

        Ok(())
    }
}

/// Mode for a seatbelt rule.
enum RuleMode {
    Allow,
    Deny,
}

impl RuleMode {
    fn as_str(&self) -> &str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

bitflags! {
    /// Types of sandbox filesystem exceptions.
    struct PathException: u8 {
        const EXECUTE = 0b0001;
        const WRITE   = 0b0010;
        const READ    = 0b0100;
    }
}

/// Escape a path: /tt/in\a"x -> "/tt/in\\a\"x"
fn escape_path(path: &Path) -> Result<String> {
    // Canonicalize the incoming path to support relative paths.
    // The `subpath` action only allows absolute paths.
    let canonical_path =
        fs::canonicalize(&path).map_err(|_| Error::InvalidPath(path.to_path_buf()))?;

    let mut path_str = canonical_path
        .into_os_string()
        .into_string()
        .map_err(|_| Error::InvalidPath(path.to_path_buf()))?;
    // Paths in `subpath` expressions must not end with /.
    while path_str.ends_with('/') && path_str != "/" {
        String::pop(&mut path_str);
    }
    path_str = path_str.replace('"', r#"\""#);
    path_str = path_str.replace('\\', r#"\\"#);
    Ok(format!("\"{path_str}\""))
}

extern "C" {
    fn sandbox_init(profile: *const i8, flags: u64, errorbuf: *mut *mut i8) -> i32;
    fn sandbox_free_error(errorbuf: *mut i8);
}
