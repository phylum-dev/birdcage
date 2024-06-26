//! Linux process implementation.
//!
//! Documentation in this module has been largely copied from [STD] and is
//! thus dual-licensed under MIT and Apache.
//!
//! [STD]: https://doc.rust-lang.org/std/process/index.html

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
pub use std::process::{ExitStatus, Output};

use rustix::fs::{Mode, OFlags};
use rustix::pipe::pipe;
use rustix::process::{Pid, Signal};

/// A process builder, providing fine-grained control
/// over how a new process should be spawned.
///
/// A default configuration can be generated using `Command::new(program)`,
/// where `program` gives a path to the program to be executed. Additional
/// builder methods allow the configuration to be changed (for example, by
/// adding arguments) prior to spawning:
///
/// ```no_run
/// use birdcage::process::Command;
///
/// Command::new("sh").arg("-c").arg("echo hello");
/// ```
pub struct Command {
    program: OsString,
    args: Vec<OsString>,
    pub(crate) stdin: Stdio,
    pub(crate) stdout: Stdio,
    pub(crate) stderr: Stdio,
}

impl Command {
    /// Constructs a new `Command` for launching the program at
    /// path `program`, with the following default configuration:
    ///
    /// * No arguments to the program
    /// * Inherit the current process's working directory
    /// * Inherit stdin/stdout/stderr
    ///
    /// Builder methods are provided to change these defaults and
    /// otherwise configure the process.
    ///
    /// If `program` is not an absolute path, the `PATH` will be searched in
    /// an OS-defined way.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::Command;
    ///
    /// Command::new("sh");
    /// ```
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        let program = program.as_ref().to_os_string();
        Self {
            program,
            stdout: Default::default(),
            stderr: Default::default(),
            stdin: Default::default(),
            args: Default::default(),
        }
    }

    /// Adds an argument to pass to the program.
    ///
    /// Only one argument can be passed per use. So instead of:
    ///
    /// ```no_run
    /// # birdcage::process::Command::new("sh")
    /// .arg("-C /path/to/repo")
    /// # ;
    /// ```
    ///
    /// usage would be:
    ///
    /// ```no_run
    /// # birdcage::process::Command::new("sh")
    /// .arg("-C")
    /// .arg("/path/to/repo")
    /// # ;
    /// ```
    ///
    /// To pass multiple arguments see [`args`].
    ///
    /// [`args`]: Command::args
    ///
    /// Note that the argument is not passed through a shell, but given
    /// literally to the program. This means that shell syntax like quotes,
    /// escaped characters, word splitting, glob patterns, variable
    /// substitution, etc. have no effect.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::Command;
    ///
    /// Command::new("ls").arg("-l").arg("-a");
    /// ```
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        let arg = arg.as_ref().to_os_string();
        self.args.push(arg);
        self
    }

    /// Adds multiple arguments to pass to the program.
    ///
    /// To pass a single argument see [`arg`].
    ///
    /// [`arg`]: Command::arg
    ///
    /// Note that the arguments are not passed through a shell, but given
    /// literally to the program. This means that shell syntax like quotes,
    /// escaped characters, word splitting, glob patterns, variable
    /// substitution, etc. have no effect.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::Command;
    ///
    /// Command::new("ls").args(["-l", "-a"]);
    /// ```
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            let arg = arg.as_ref().to_os_string();
            self.args.push(arg);
        }
        self
    }

    /// Configuration for the child process's standard input (stdin) handle.
    ///
    /// Defaults to [`inherit`].
    ///
    /// [`inherit`]: Stdio::inherit
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::{Command, Stdio};
    ///
    /// Command::new("ls").stdin(Stdio::null());
    /// ```
    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdin = cfg.into();
        self
    }

    /// Configuration for the child process's standard output (stdout) handle.
    ///
    /// Defaults to [`inherit`].
    ///
    /// [`inherit`]: Stdio::inherit
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::{Command, Stdio};
    ///
    /// Command::new("ls").stdout(Stdio::null());
    /// ```
    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdout = cfg.into();
        self
    }

    /// Configuration for the child process's standard error (stderr) handle.
    ///
    /// Defaults to [`inherit`].
    ///
    /// [`inherit`]: Stdio::inherit
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::{Command, Stdio};
    ///
    /// Command::new("ls").stderr(Stdio::null());
    /// ```
    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stderr = cfg.into();
        self
    }

    /// Returns the path to the program that was given to [`Command::new`].
    ///
    /// # Examples
    ///
    /// ```
    /// use birdcage::process::Command;
    ///
    /// let cmd = Command::new("echo");
    /// assert_eq!(cmd.get_program(), "echo");
    /// ```
    pub fn get_program(&self) -> &OsStr {
        OsStr::from_bytes(self.program.as_bytes())
    }
}

impl From<Command> for std::process::Command {
    fn from(command: Command) -> Self {
        let mut std_command = std::process::Command::new(command.program);
        std_command.args(command.args);

        let stdin: Option<std::process::Stdio> = command.stdin.into();
        if let Some(stdin) = stdin {
            std_command.stdin(stdin);
        }

        let stdout: Option<std::process::Stdio> = command.stdout.into();
        if let Some(stdout) = stdout {
            std_command.stdout(stdout);
        }

        let stderr: Option<std::process::Stdio> = command.stderr.into();
        if let Some(stderr) = stderr {
            std_command.stderr(stderr);
        }

        std_command
    }
}

/// Representation of a running or exited child process.
///
/// This structure is used to represent and manage child processes. A child
/// process is created via the [`Command`] struct, which configures the
/// spawning process and can itself be constructed using a builder-style
/// interface.
///
/// There is no implementation of [`Drop`] for child processes,
/// so if you do not ensure the `Child` has exited then it will continue to
/// run, even after the `Child` handle to the child process has gone out of
/// scope.
///
/// Calling [`wait`] (or other functions that wrap around it) will make
/// the parent process wait until the child has actually exited before
/// continuing.
///
/// # Warning
///
/// On some systems, calling [`wait`] or similar is necessary for the OS to
/// release resources. A process that terminated but has not been waited on is
/// still around as a "zombie". Leaving too many zombies around may exhaust
/// global resources (for example process IDs).
///
/// Birdcage does *not* automatically wait on child processes (not even if the
/// `Child` is dropped), it is up to the application developer to do so. As a
/// consequence, dropping `Child` handles without waiting on them first is not
/// recommended in long-running applications.
///
/// # Examples
///
/// ```should_panic
/// use birdcage::process::Command;
/// use birdcage::{Birdcage, Sandbox};
///
/// let mut cmd = Command::new("/bin/cat");
/// cmd.arg("file.txt");
/// let mut child = Birdcage::new().spawn(cmd).expect("failed to execute child");
///
/// let ecode = child.wait().expect("failed to wait on child");
///
/// assert!(ecode.success());
/// ```
///
/// [`wait`]: Child::wait
pub struct Child {
    /// The handle for writing to the child's standard input (stdin), if it
    /// has been captured. You might find it helpful to do
    ///
    /// ```compile_fail,E0425
    /// let stdin = child.stdin.take().unwrap();
    /// ```
    ///
    /// to avoid partially moving the `child` and thus blocking yourself from
    /// calling functions on `child` while using `stdin`.
    pub stdin: Option<ChildStdin>,

    /// The handle for reading from the child's standard output (stdout), if it
    /// has been captured. You might find it helpful to do
    ///
    /// ```compile_fail,E0425
    /// let stdout = child.stdout.take().unwrap();
    /// ```
    ///
    /// to avoid partially moving the `child` and thus blocking yourself from
    /// calling functions on `child` while using `stdout`.
    pub stdout: Option<ChildStdout>,

    /// The handle for reading from the child's standard error (stderr), if it
    /// has been captured. You might find it helpful to do
    ///
    /// ```compile_fail,E0425
    /// let stderr = child.stderr.take().unwrap();
    /// ```
    ///
    /// to avoid partially moving the `child` and thus blocking yourself from
    /// calling functions on `child` while using `stderr`.
    pub stderr: Option<ChildStderr>,

    exit_signal: OwnedFd,
    pid: u32,
}

impl Child {
    /// Create child from a process and its Stdio pipes.
    pub(crate) fn new(
        pid: i32,
        exit_signal: OwnedFd,
        stdin: Option<OwnedFd>,
        stdout: Option<OwnedFd>,
        stderr: Option<OwnedFd>,
    ) -> io::Result<Self> {
        Ok(Self {
            exit_signal,
            pid: pid as u32,
            stdin: stdin.map(ChildStdin::new).transpose()?,
            stdout: stdout.map(ChildStdout::new).transpose()?,
            stderr: stderr.map(ChildStderr::new).transpose()?,
        })
    }

    /// Forces the child process to exit. If the child has already exited,
    /// `Ok(())` is returned.
    ///
    /// The mapping to [`ErrorKind`]s is not part of the compatibility contract
    /// of the function.
    ///
    /// This is equivalent to sending a SIGKILL.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::Command;
    /// use birdcage::{Birdcage, Sandbox};
    ///
    /// let command = Command::new("yes");
    /// if let Ok(mut child) = Birdcage::new().spawn(command) {
    ///     child.kill().expect("command couldn't be killed");
    /// } else {
    ///     println!("yes command didn't start");
    /// }
    /// ```
    ///
    /// [`ErrorKind`]: io::ErrorKind
    /// [`InvalidInput`]: io::ErrorKind::InvalidInput
    pub fn kill(&mut self) -> io::Result<()> {
        let pid = Pid::from_raw(self.pid as i32).unwrap();
        rustix::process::kill_process(pid, Signal::Kill)?;
        Ok(())
    }

    /// Returns the OS-assigned process identifier associated with this child.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::Command;
    /// use birdcage::{Birdcage, Sandbox};
    ///
    /// let command = Command::new("ls");
    /// if let Ok(child) = Birdcage::new().spawn(command) {
    ///     println!("Child's ID is {}", child.id());
    /// } else {
    ///     println!("ls command didn't start");
    /// }
    /// ```
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Waits for the child to exit completely, returning the status that it
    /// exited with. This function will continue to have the same return value
    /// after it has been called at least once.
    ///
    /// The stdin handle to the child process, if any, will be closed
    /// before waiting. This helps avoid deadlock: it ensures that the
    /// child does not block waiting for input from the parent, while
    /// the parent waits for the child to exit.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::Command;
    /// use birdcage::{Birdcage, Sandbox};
    ///
    /// let mut command = Command::new("ls");
    /// if let Ok(mut child) = Birdcage::new().spawn(command) {
    ///     child.wait().expect("command wasn't running");
    ///     println!("Child has finished its execution!");
    /// } else {
    ///     println!("ls command didn't start");
    /// }
    /// ```
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        // Wait for child process to exit.
        unsafe {
            let mut status: libc::c_int = 0;
            if libc::waitpid(self.pid as i32, &mut status, 0) == -1 {
                Err(io::Error::last_os_error())
            } else {
                match self.exit_signal()? {
                    Some(exit_signal) => Ok(exit_signal),
                    None => Ok(ExitStatus::from_raw(status)),
                }
            }
        }
    }

    /// Attempts to collect the exit status of the child if it has already
    /// exited.
    ///
    /// This function will not block the calling thread and will only
    /// check to see if the child process has exited or not. If the child has
    /// exited then on Unix the process ID is reaped. This function is
    /// guaranteed to repeatedly return a successful exit status so long as the
    /// child has already exited.
    ///
    /// If the child has exited, then `Ok(Some(status))` is returned. If the
    /// exit status is not available at this time then `Ok(None)` is returned.
    /// If an error occurs, then that error is returned.
    ///
    /// Note that unlike `wait`, this function will not attempt to drop stdin.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use birdcage::process::Command;
    /// use birdcage::{Birdcage, Sandbox};
    ///
    /// let cmd = Command::new("ls");
    /// let mut child = Birdcage::new().spawn(cmd).unwrap();
    ///
    /// match child.try_wait() {
    ///     Ok(Some(status)) => println!("exited with: {status}"),
    ///     Ok(None) => {
    ///         println!("status not ready yet, let's really wait");
    ///         let res = child.wait();
    ///         println!("result: {res:?}");
    ///     },
    ///     Err(e) => println!("error attempting to wait: {e}"),
    /// }
    /// ```
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        // Wait for child process to exit.
        unsafe {
            let mut status: libc::c_int = 0;
            let pid = libc::waitpid(self.pid as i32, &mut status, libc::WNOHANG);
            if pid == -1 {
                Err(io::Error::last_os_error())
            } else if pid == 0 {
                Ok(None)
            } else {
                match self.exit_signal()? {
                    Some(exit_signal) => Ok(Some(exit_signal)),
                    None => Ok(Some(ExitStatus::from_raw(status))),
                }
            }
        }
    }

    /// Simultaneously waits for the child to exit and collect all remaining
    /// output on the stdout/stderr handles, returning an `Output`
    /// instance.
    ///
    /// The stdin handle to the child process, if any, will be closed
    /// before waiting. This helps avoid deadlock: it ensures that the
    /// child does not block waiting for input from the parent, while
    /// the parent waits for the child to exit.
    ///
    /// By default, stdin, stdout and stderr are inherited from the parent.
    /// In order to capture the output into this `Result<Output>` it is
    /// necessary to create new pipes between parent and child. Use
    /// `stdout(Stdio::piped())` or `stderr(Stdio::piped())`, respectively.
    ///
    /// # Examples
    ///
    /// ```should_panic
    /// use birdcage::process::{Command, Stdio};
    /// use birdcage::{Birdcage, Sandbox};
    ///
    /// let mut cmd = Command::new("/bin/cat");
    /// cmd.arg("file.txt");
    /// cmd.stdout(Stdio::piped());
    /// let child = Birdcage::new().spawn(cmd).expect("failed to execute child");
    ///
    /// let output = child.wait_with_output().expect("failed to wait on child");
    ///
    /// assert!(output.status.success());
    /// ```
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        // Drop stdin, to avoid deadlocks.
        let _ = self.stdin.take();

        // Collect stdio buffers.
        let reader = ChildReader::new(self.stdout.take(), self.stderr.take())?;
        let (stdout, stderr) = reader.read()?;

        // Wait for process termination.
        let status = self.wait()?;

        Ok(Output { status, stdout, stderr })
    }

    /// Get the child's exit signal.
    fn exit_signal(&self) -> io::Result<Option<ExitStatus>> {
        // Don't block when trying to read.
        rustix::fs::fcntl_setfl(&self.exit_signal, OFlags::NONBLOCK)?;

        // Read exit signal from pipe.
        let mut bytes = [0; mem::size_of::<u32>()];
        let read = match rustix::io::read(&self.exit_signal, &mut bytes) {
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        // Convert signal to exit status.
        if read == mem::size_of::<u32>() {
            let signal = u32::from_le_bytes(bytes);

            // Exit signal are the lowest 7 bits of wstatus:
            // https://github.com/torvalds/linux/blob/259f7d5e2baf87fcbb4fabc46526c9c47fed1914/tools/include/nolibc/types.h#L110
            assert!(signal <= 0x7f);

            Ok(Some(ExitStatus::from_raw(signal as i32)))
        } else {
            Ok(None)
        }
    }
}

/// Describes what to do with a standard I/O stream for a child process when
/// passed to the [`stdin`], [`stdout`], and [`stderr`] methods of [`Command`].
///
/// [`stdin`]: Command::stdin
/// [`stdout`]: Command::stdout
/// [`stderr`]: Command::stderr
#[derive(Default)]
pub struct Stdio {
    pub(crate) ty: StdioType,
}

impl Stdio {
    /// A new pipe should be arranged to connect the parent and child processes.
    ///
    /// # Examples
    ///
    /// With stdout:
    ///
    /// ```no_run
    /// use birdcage::process::{Command, Stdio};
    ///
    /// Command::new("echo").arg("Hello, world!").stdout(Stdio::piped());
    /// ```
    ///
    /// With stdin:
    ///
    /// ```no_run
    /// use std::io::Write;
    ///
    /// use birdcage::process::{Command, Stdio};
    /// use birdcage::{Birdcage, Sandbox};
    ///
    /// let mut cmd = Command::new("rev");
    /// cmd.stdin(Stdio::piped());
    /// cmd.stdout(Stdio::piped());
    /// let mut child = Birdcage::new().spawn(cmd).expect("Failed to spawn child process");
    ///
    /// let mut stdin = child.stdin.take().expect("Failed to open stdin");
    /// std::thread::spawn(move || {
    ///     stdin.write_all("Hello, world!".as_bytes()).expect("Failed to write to stdin");
    /// });
    ///
    /// let output = child.wait_with_output().expect("Failed to read stdout");
    /// assert_eq!(String::from_utf8_lossy(&output.stdout), "!dlrow ,olleH");
    /// ```
    ///
    /// Writing more than a pipe buffer's worth of input to stdin without also
    /// reading stdout and stderr at the same time may cause a deadlock.
    /// This is an issue when running any program that doesn't guarantee that it
    /// reads its entire stdin before writing more than a pipe buffer's
    /// worth of output. The size of a pipe buffer varies on different
    /// targets.
    pub fn piped() -> Self {
        Self { ty: StdioType::Piped }
    }

    /// The child inherits from the corresponding parent descriptor.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use birdcage::process::{Command, Stdio};
    ///
    /// let output = Command::new("echo").arg("Hello, world!").stdout(Stdio::inherit());
    /// ```
    pub fn inherit() -> Self {
        Self { ty: StdioType::Inherit }
    }

    /// This stream will be ignored. This is the equivalent of attaching the
    /// stream to `/dev/null`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use birdcage::process::{Command, Stdio};
    ///
    /// let output = Command::new("echo").arg("Hello, world!").stdout(Stdio::null());
    /// ```
    pub fn null() -> Self {
        Self { ty: StdioType::Null }
    }

    /// Create pipes necessary for the stdio type.
    ///
    /// This will return the corresponding read and write FDs.
    pub(crate) fn make_pipe(&self, stdin: bool) -> io::Result<(Option<OwnedFd>, Option<OwnedFd>)> {
        match self.ty {
            StdioType::Inherit | StdioType::Default => Ok((None, None)),
            StdioType::Piped => {
                let (rx, tx) = pipe()?;
                Ok((Some(rx), Some(tx)))
            },
            StdioType::Null => {
                let null_fd = rustix::fs::open("/dev/null", OFlags::RDWR, Mode::empty())?;
                if stdin {
                    Ok((Some(null_fd), None))
                } else {
                    Ok((None, Some(null_fd)))
                }
            },
        }
    }
}

impl From<Stdio> for Option<std::process::Stdio> {
    fn from(stdio: Stdio) -> Option<std::process::Stdio> {
        match stdio.ty {
            StdioType::Default => None,
            StdioType::Inherit => Some(std::process::Stdio::inherit()),
            StdioType::Piped => Some(std::process::Stdio::piped()),
            StdioType::Null => Some(std::process::Stdio::null()),
        }
    }
}

/// Type of parent/child I/O coupling.
#[derive(Default, Copy, Clone)]
pub(crate) enum StdioType {
    #[default]
    Default,
    Piped,
    Inherit,
    Null,
}

/// A handle to a child process's standard input (stdin).
///
/// This struct is used in the [`stdin`] field on [`Child`].
///
/// When an instance of `ChildStdin` is [dropped], the `ChildStdin`'s underlying
/// file handle will be closed. If the child process was blocked on input prior
/// to being dropped, it will become unblocked after dropping.
///
/// [`stdin`]: Child::stdin
/// [dropped]: Drop
pub struct ChildStdin {
    fd: OwnedFd,
}

impl ChildStdin {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self { fd })
    }
}

impl Write for ChildStdin {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        rustix::io::write(&self.fd, buf).map_err(io::Error::from)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A handle to a child process's standard output (stdout).
///
/// This struct is used in the [`stdout`] field on [`Child`].
///
/// When an instance of `ChildStdout` is [dropped], the `ChildStdout`'s
/// underlying file handle will be closed.
///
/// [`stdout`]: Child::stdout
/// [dropped]: Drop
pub struct ChildStdout {
    fd: OwnedFd,
}

impl ChildStdout {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self { fd })
    }
}

impl Read for ChildStdout {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        rustix::io::read(&self.fd, buf).map_err(io::Error::from)
    }
}

/// A handle to a child process's stderr.
///
/// This struct is used in the [`stderr`] field on [`Child`].
///
/// When an instance of `ChildStderr` is [dropped], the `ChildStderr`'s
/// underlying file handle will be closed.
///
/// [`stderr`]: Child::stderr
/// [dropped]: Drop
pub type ChildStderr = ChildStdout;

struct ChildReader {
    poll_fds: Vec<libc::pollfd>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    stdout_buffer: Vec<u8>,
    stderr_buffer: Vec<u8>,
}

impl ChildReader {
    fn new(stdout: Option<ChildStdout>, stderr: Option<ChildStderr>) -> io::Result<Self> {
        let mut poll_fds = Vec::new();

        if let Some(stdout) = &stdout {
            rustix::fs::fcntl_setfl(&stdout.fd, OFlags::NONBLOCK)?;
            let fd = stdout.fd.as_raw_fd();
            poll_fds.push(libc::pollfd { fd, events: libc::POLLIN, revents: 0 });
        }

        if let Some(stderr) = &stderr {
            rustix::fs::fcntl_setfl(&stderr.fd, OFlags::NONBLOCK)?;
            let fd = stderr.fd.as_raw_fd();
            poll_fds.push(libc::pollfd { fd, events: libc::POLLIN, revents: 0 });
        }

        Ok(Self {
            poll_fds,
            stdout,
            stderr,
            stdout_buffer: Default::default(),
            stderr_buffer: Default::default(),
        })
    }

    /// Read stdout and stderr into buffers.
    fn read(mut self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        while !self.poll_fds.is_empty() {
            // Block for next FD readiness.
            let result = unsafe { libc::poll(self.poll_fds.as_mut_ptr(), 2, -1) };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }

            // Read from all FDs.
            for i in (0..self.poll_fds.len()).rev() {
                // Ignore FDs that aren't ready.
                let poll_fd = &self.poll_fds[i];
                if poll_fd.revents == 0 {
                    continue;
                }

                // Get stdio/buffer corresponding to the FD.
                let (stdio, buffer) = self.stdio_from_fd(poll_fd.fd);

                // Read all available data.
                match stdio.read_to_end(buffer) {
                    Ok(_) => {
                        self.poll_fds.remove(i);
                    },
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => (),
                    Err(err) => return Err(err),
                }
            }
        }

        Ok((self.stdout_buffer, self.stderr_buffer))
    }

    /// Get the stdio handles corresponding to a FD.
    fn stdio_from_fd(&mut self, fd: RawFd) -> (&mut ChildStdout, &mut Vec<u8>) {
        match (self.stdout.as_mut(), self.stderr.as_mut()) {
            (Some(stdout), _) if stdout.fd.as_raw_fd() == fd => (stdout, &mut self.stdout_buffer),
            (_, Some(stderr)) if stderr.fd.as_raw_fd() == fd => (stderr, &mut self.stderr_buffer),
            _ => unreachable!(),
        }
    }
}
