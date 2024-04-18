//! Linux sandboxing.

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::{env, fs, io, ptr};

use rustix::pipe::pipe;
use rustix::process::{Gid, Pid, Uid, WaitOptions};

use crate::error::{Error, Result};
use crate::linux::namespaces::{MountAttrFlags, Namespaces};
use crate::linux::seccomp::SyscallFilter;
use crate::{Child, Command, Exception, Sandbox};

mod namespaces;
mod seccomp;

/// Linux sandboxing.
#[derive(Default)]
pub struct LinuxSandbox {
    env_exceptions: Vec<String>,
    path_exceptions: PathExceptions,
    allow_networking: bool,
    full_env: bool,
}

impl Sandbox for LinuxSandbox {
    fn new() -> Self {
        Self::default()
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        match exception {
            Exception::Read(path) => self.path_exceptions.update(path, false, false)?,
            Exception::WriteAndRead(path) => self.path_exceptions.update(path, true, false)?,
            Exception::ExecuteAndRead(path) => self.path_exceptions.update(path, false, true)?,
            Exception::Environment(key) => self.env_exceptions.push(key),
            Exception::FullEnvironment => self.full_env = true,
            Exception::Networking => self.allow_networking = true,
        }

        Ok(self)
    }

    fn spawn(self, sandboxee: Command) -> Result<Child> {
        // Ensure calling process is not multi-threaded.
        assert!(
            thread_count().unwrap_or(0) == 1,
            "`Sandbox::spawn` must be called from a single-threaded process"
        );

        // Remove environment variables.
        if !self.full_env {
            crate::restrict_env_variables(&self.env_exceptions);
        }

        // Create pipes to hook up init's stdio.
        let stdin_pipe = sandboxee.stdin.make_pipe(true)?;
        let stdout_pipe = sandboxee.stdout.make_pipe(false)?;
        let stderr_pipe = sandboxee.stderr.make_pipe(false)?;
        let exit_signal_pipe = pipe().map_err(IoError::from)?;

        // Spawn isolated sandbox PID 1.
        let allow_networking = self.allow_networking;
        let init_arg = ProcessInitArg::new(
            self,
            sandboxee,
            exit_signal_pipe,
            stdin_pipe,
            stdout_pipe,
            stderr_pipe,
        );
        let init_arg = spawn_sandbox_init(init_arg, allow_networking)?;

        // Deconstruct init args, dropping unused FDs.
        let (pid, stdin_tx, stdout_rx, stderr_rx, exit_signal_rx) = {
            let ProcessInitArg {
                // Extract used fields.
                pid,
                stdin_tx,
                stdout_rx,
                stderr_rx,
                exit_signal_rx,

                // Deconstruct all remaining fields to manually drop them.
                path_exceptions: _x0,
                exit_signal_tx: _x1,
                parent_euid: _x2,
                parent_egid: _x3,
                stdout_tx: _x4,
                stderr_tx: _x5,
                sandboxee: _x6,
                stdin_rx: _x7,
            } = init_arg;
            (pid, stdin_tx, stdout_rx, stderr_rx, exit_signal_rx)
        };

        let child = Child::new(pid, exit_signal_rx, stdin_tx, stdout_rx, stderr_rx)?;

        Ok(child)
    }
}

/// Create sandbox child process.
///
/// This function uses `clone` to setup the sandbox's init process with user
/// namespace isolations in place.
///
/// Returns PID of the child process if successful.
fn spawn_sandbox_init(init_arg: ProcessInitArg, allow_networking: bool) -> Result<ProcessInitArg> {
    unsafe {
        // Initialize child process stack memory.
        let stack_size = 1024 * 1024;
        let child_stack = libc::mmap(
            ptr::null_mut(),
            stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        );
        if child_stack == libc::MAP_FAILED {
            return Err(IoError::last_os_error().into());
        }

        // Stack grows downward on all relevant Linux processors.
        let stack_top = child_stack.add(stack_size);

        // Construct clone flags with required namespaces.
        let mut flags =
            libc::CLONE_NEWIPC | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWUSER;
        if !allow_networking {
            flags |= libc::CLONE_NEWNET;
        }

        // Spawn sandbox init process.
        let init_arg_raw = Box::into_raw(Box::new(init_arg));
        let init_pid =
            libc::clone(sandbox_init, stack_top, flags | libc::SIGCHLD, init_arg_raw as _);
        if init_pid == -1 {
            Err(IoError::last_os_error().into())
        } else {
            let mut init_arg = Box::from_raw(init_arg_raw);
            init_arg.pid = init_pid;
            Ok(*init_arg)
        }
    }
}

/// PID 1 inside the sandbox.
///
/// This function is the entry point for the process which is used to launch the
/// sandboxee and act as init system for the PID namespace.
extern "C" fn sandbox_init(arg: *mut libc::c_void) -> libc::c_int {
    let init_arg: Box<ProcessInitArg> = unsafe { Box::from_raw(arg as _) };

    match sandbox_init_inner(*init_arg) {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!("sandboxing failure: {err}");
            1
        },
    }
}

/// PID 1 inside the sandbox.
///
/// Wrapper to simplify error handling.
fn sandbox_init_inner(mut init_arg: ProcessInitArg) -> io::Result<libc::c_int> {
    // Close all unused FDs.
    init_arg.stdin_tx.take();
    init_arg.stdout_rx.take();
    init_arg.stderr_rx.take();
    drop(init_arg.exit_signal_rx);

    // Hook up stdio to parent process.
    if let Some(stdin_pipe) = &mut init_arg.stdin_rx {
        rustix::stdio::dup2_stdin(stdin_pipe)?;
    }
    if let Some(stdout_pipe) = &init_arg.stdout_tx {
        rustix::stdio::dup2_stdout(stdout_pipe)?;
    }
    if let Some(stderr_pipe) = &init_arg.stderr_tx {
        rustix::stdio::dup2_stderr(stderr_pipe)?;
    }

    // Map root UID and GID.
    namespaces::map_ids(init_arg.parent_euid.as_raw(), init_arg.parent_egid.as_raw(), 0, 0)?;

    // Isolate filesystem using a mount namespace.
    namespaces::setup_mount_namespace(init_arg.path_exceptions)?;

    // Create new procfs directory.
    let new_proc_c = CString::new("/proc")?;
    namespaces::mount_proc(&new_proc_c)?;

    // Drop root user mapping.
    namespaces::create_user_namespace(
        init_arg.parent_euid.as_raw(),
        init_arg.parent_egid.as_raw(),
        Namespaces::empty(),
    )?;

    // Setup system call filters.
    SyscallFilter::apply().map_err(|err| IoError::new(IoErrorKind::Other, err))?;

    // Block suid/sgid.
    //
    // This is also blocked by our bind mount's MS_NOSUID flag, so we're just
    // doubling-down here.
    rustix::thread::set_no_new_privs(true)?;

    // Spawn sandboxed process.
    let mut std_command = std::process::Command::from(init_arg.sandboxee);
    let child = std_command.spawn()?;

    // Reap zombie children.
    let child_pid = Pid::from_raw(child.id() as i32);
    loop {
        // Wait for any child to exit.
        match rustix::process::wait(WaitOptions::empty())? {
            Some((pid, status)) if Some(pid) == child_pid => match status.terminating_signal() {
                Some(signal) => {
                    // Send exit signal to parent.
                    rustix::io::write(init_arg.exit_signal_tx, &signal.to_le_bytes())?;
                    return Ok(1);
                },
                None => return Ok(status.exit_status().unwrap_or(1) as i32),
            },
            Some(_) => (),
            None => unreachable!("none without nohang"),
        }
    }
}

/// Init process argument passed to `clone`.
struct ProcessInitArg {
    path_exceptions: PathExceptions,

    sandboxee: Command,

    parent_euid: Uid,
    parent_egid: Gid,

    // FDs used by the child process.
    stdin_rx: Option<OwnedFd>,
    stdout_tx: Option<OwnedFd>,
    stderr_tx: Option<OwnedFd>,
    exit_signal_tx: OwnedFd,

    // FDs passed to the child for closing them.
    stdin_tx: Option<OwnedFd>,
    stdout_rx: Option<OwnedFd>,
    stderr_rx: Option<OwnedFd>,
    exit_signal_rx: OwnedFd,

    pid: i32,
}

impl ProcessInitArg {
    fn new(
        sandbox: LinuxSandbox,
        sandboxee: Command,
        exit_signal: (OwnedFd, OwnedFd),
        stdin: (Option<OwnedFd>, Option<OwnedFd>),
        stdout: (Option<OwnedFd>, Option<OwnedFd>),
        stderr: (Option<OwnedFd>, Option<OwnedFd>),
    ) -> Self {
        // Get EUID/EGID outside of the namespaces.
        let parent_euid = rustix::process::geteuid();
        let parent_egid = rustix::process::getegid();

        Self {
            parent_euid,
            parent_egid,
            sandboxee,
            path_exceptions: sandbox.path_exceptions,
            stdin_rx: stdin.0,
            stdout_tx: stdout.1,
            stderr_tx: stderr.1,
            exit_signal_tx: exit_signal.1,
            stdin_tx: stdin.1,
            stdout_rx: stdout.0,
            stderr_rx: stderr.0,
            exit_signal_rx: exit_signal.0,
            pid: -1,
        }
    }
}

/// Path permissions required for the sandbox.
#[derive(Default)]
pub(crate) struct PathExceptions {
    bind_mounts: HashMap<PathBuf, MountAttrFlags>,
    symlinks: Vec<(PathBuf, PathBuf)>,
}

impl PathExceptions {
    /// Add or modify a path's exceptions.
    ///
    /// This will add a new bind mount for the canonical path with the specified
    /// permission if it does not exist already.
    ///
    /// If the bind mount already exists, it will *ADD* the additional
    /// permissions.
    fn update(&mut self, path: PathBuf, write: bool, execute: bool) -> Result<()> {
        // Use canonical path for indexing.
        //
        // This ensures that a symlink and its target are treated like the same path for
        // exceptions.
        //
        // If the home path cannot be accessed, we ignore the exception.
        let canonical_path = match path.canonicalize() {
            Ok(path) => path,
            Err(_) => return Err(Error::InvalidPath(path)),
        };

        // Store original symlink path to create it if necessary.
        if path_has_symlinks(&path) {
            // Normalize symlink's path.
            let absolute = absolute(&path)?;
            let normalized = normalize_path(&absolute);

            self.symlinks.push((normalized, canonical_path.clone()));
        }

        // Update bind mount's permission flags.

        let flags = self
            .bind_mounts
            .entry(canonical_path)
            .or_insert(MountAttrFlags::RDONLY | MountAttrFlags::NOEXEC);

        if write {
            flags.remove(MountAttrFlags::RDONLY);
        }

        if execute {
            flags.remove(MountAttrFlags::NOEXEC);
        }

        Ok(())
    }
}

// Copied from Rust's STD:
// https://github.com/rust-lang/rust/blob/42faef503f3e765120ca0ef06991337668eafc32/library/std/src/sys/unix/path.rs#L23C1-L63C2
//
// Licensed under MIT:
// https://github.com/rust-lang/rust/blob/master/LICENSE-MIT
//
/// Make a POSIX path absolute without changing its semantics.
fn absolute(path: &Path) -> io::Result<PathBuf> {
    // This is mostly a wrapper around collecting `Path::components`, with
    // exceptions made where this conflicts with the POSIX specification.
    // See 4.13 Pathname Resolution, IEEE Std 1003.1-2017
    // https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html#tag_04_13

    // Get the components, skipping the redundant leading "." component if it
    // exists.
    let mut components = path.strip_prefix(".").unwrap_or(path).components();
    let path_os = path.as_os_str().as_bytes();

    let mut normalized = if path.is_absolute() {
        // "If a pathname begins with two successive <slash> characters, the
        // first component following the leading <slash> characters may be
        // interpreted in an implementation-defined manner, although more than
        // two leading <slash> characters shall be treated as a single <slash>
        // character."
        if path_os.starts_with(b"//") && !path_os.starts_with(b"///") {
            components.next();
            PathBuf::from("//")
        } else {
            PathBuf::new()
        }
    } else {
        env::current_dir()?
    };
    normalized.extend(components);

    // "Interfaces using pathname resolution may specify additional constraints
    // when a pathname that does not name an existing directory contains at
    // least one non- <slash> character and contains one or more trailing
    // <slash> characters".
    // A trailing <slash> is also meaningful if "a symbolic link is
    // encountered during pathname resolution".
    if path_os.ends_with(b"/") {
        normalized.push("");
    }

    Ok(normalized)
}

/// Normalize path components, stripping out `.` and `..`.
fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(_) => unreachable!("impl does not consider windows"),
            Component::RootDir => normalized.push("/"),
            Component::CurDir => continue,
            Component::ParentDir => {
                normalized.pop();
            },
            Component::Normal(segment) => normalized.push(segment),
        }
    }

    normalized
}

/// Check if a path contains any symlinks.
fn path_has_symlinks(path: &Path) -> bool {
    path.ancestors().any(|path| path.read_link().is_ok())
}

/// Get the number of threads used by the current process.
fn thread_count() -> io::Result<usize> {
    // Read process status from procfs.
    let status = fs::read_to_string("/proc/self/status")?;

    // Parse procfs output.
    let (_, threads_start) = status.split_once("Threads:").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "/proc/self/status missing \"Threads:\"")
    })?;
    let thread_count = threads_start.split_whitespace().next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "/proc/self/status output malformed")
    })?;

    // Convert to number.
    let thread_count = thread_count
        .parse::<usize>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    Ok(thread_count)
}
