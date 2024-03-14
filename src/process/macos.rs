//! macOS process implementation.

// We just re-export STD, since we can spawn this command directly.
pub use std::process::{
    Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio,
};
