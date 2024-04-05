use std::io::Write;
use std::os::unix::process::ExitStatusExt;

use birdcage::process::{Command, Stdio};
use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    pipe_stdin_to_stdout();
    exit_signal();
}

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
    let _ = child.stdin.as_mut().unwrap().write(expected).unwrap();

    // Read stdout.
    let output = child.wait_with_output().unwrap();
    assert_eq!(&output.stdout, expected);
}

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
