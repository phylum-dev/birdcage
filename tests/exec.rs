use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn execution() {
    let mut bc = Birdcage::new().unwrap();

    bc.add_exception(Exception::ExecuteAndRead("/bin/ls".into())).unwrap();
    fs::canonicalize("/tmp").ok().map(|path| bc.add_exception(Exception::Read(path)));
    fs::canonicalize("/bin").ok().map(|path| bc.add_exception(Exception::ExecuteAndRead(path)));
    fs::canonicalize("/lib").ok().map(|path| bc.add_exception(Exception::ExecuteAndRead(path)));

    bc.lock().unwrap();

    // Check for success when executing `ls` against a permitted path.
    let cmd = Command::new("/bin/ls").arg("/tmp/").status().unwrap();
    assert!(cmd.success());

    // Check for errors when executing `ls` against a restricted path.
    let cmd = Command::new("/bin/ls").arg("/dev/").status().unwrap();
    assert!(!cmd.success());

    // Check for success on reading the `ls` file.
    let cmd_file = fs::read("/bin/ls");
    assert!(cmd_file.is_ok());
}
