//! Linux sandboxing.
//!
//! This module implements sandboxing on macOS using `sandbox_init`.

use std::ffi::{CStr, CString};
use std::io::Write;
use std::path::PathBuf;
use std::ptr;

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
(system-network)
";

/// macOS sandboxing based on Seatbelt.
pub struct MacSandbox {
    profile: Vec<u8>,
}

impl Sandbox for MacSandbox {
    fn new() -> Result<Self> {
        Ok(Self { profile: DEFAULT_RULE.to_vec() })
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        match exception {
            Exception::Read(path) => {
                self.profile.write_all(b"(allow file-read* (subpath ")?;
                let escaped_path = escape_path(path)?;
                self.profile.write_all(escaped_path.as_bytes())?;
                self.profile.write_all(b"))\n")?;
            },
            Exception::Write(path) => {
                self.profile.write_all(b"(allow file-write* (subpath ")?;
                let escaped_path = escape_path(path)?;
                self.profile.write_all(escaped_path.as_bytes())?;
                self.profile.write_all(b"))\n")?;
            },
            Exception::ExecuteAndRead(path) => {
                self.add_exception(Exception::Read(path.clone()))?;
                self.profile.write_all(b"(allow process-exec (subpath ")?;
                let escaped_path = escape_path(path)?;
                self.profile.write_all(escaped_path.as_bytes())?;
                self.profile.write_all(b"))\n")?;
            },
            Exception::Networking => {
                self.profile.write_all(b"(allow network*)\n")?;
            },
        }
        Ok(self)
    }

    fn lock(self) -> Result<()> {
        let profile = CString::new(self.profile)
            .map_err(|_| Error::ActivationFailed("invalid profile".into()))?;

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

/// Escape a path: /tt/in\a"x -> "/tt/in\\a\"x"
fn escape_path(path: PathBuf) -> Result<String> {
    let mut path = path.into_os_string().into_string()?;
    // Paths in `subpath` expressions must not end with /.
    while path.ends_with('/') {
        String::pop(&mut path);
    }
    path = path.replace('"', r#"\""#);
    path = path.replace('\\', r#"\\"#);
    Ok(format!("\"{path}\""))
}

extern "C" {
    fn sandbox_init(profile: *const i8, flags: u64, errorbuf: *mut *mut i8) -> i32;
    fn sandbox_free_error(errorbuf: *mut i8);
}
