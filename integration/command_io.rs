use std::io::Write;
use std::os::unix::process::ExitStatusExt;

use birdcage::process::{Command, Stdio};
use birdcage::{Birdcage, Exception, Sandbox};

// macOs uses `std::process` and thus does not require explicit testing. This
// allows running multiple tests in the same process rather than having to add
// multiple integeration tests.
#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
fn main() {
    pipe_stdin_to_stdout();
    exit_signal();
}

#[cfg(target_os = "linux")]
fn pipe_stdin_to_stdout() {
    // Setup echo-back command.
    let mut cmd = Command::new("cat");
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());

    // Spawn sandbox child.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::ExecuteAndRead("/".into())).unwrap();
    sandbox.add_exception(Exception::WriteAndRead("/".into())).unwrap();
    let mut child = sandbox.spawn(cmd).unwrap();

    // Write test data to stdin.
    let expected = b"test\n";
    child.stdin.as_mut().unwrap().write_all(expected).unwrap();

    // Read stdout.
    let output = child.wait_with_output().unwrap();
    assert_eq!(&output.stdout, expected);
}

#[cfg(target_os = "linux")]
fn exit_signal() {
    // Setup echo-back command.
    let cmd = Command::new("cat");

    // Spawn sandbox child.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::ExecuteAndRead("/".into())).unwrap();
    sandbox.add_exception(Exception::WriteAndRead("/".into())).unwrap();
    let mut child = sandbox.spawn(cmd).unwrap();

    // Kill the child.
    child.kill().unwrap();

    // Read stdout.
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
}
