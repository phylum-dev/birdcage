use std::io::Write;

use birdcage::process::{Command, Stdio};
use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
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
    child.stdin.as_mut().unwrap().write(expected).unwrap();

    // Read stdout.
    let output = child.wait_with_output().unwrap();
    assert_eq!(&output.stdout, expected);
}
