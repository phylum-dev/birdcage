use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn execution() {
    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::ExecuteAndRead("/bin/ls".into())).unwrap();
    bc.add_exception(Exception::Read("/tmp".into())).unwrap();
    #[cfg(target_os = "macos")]
    bc.add_exception(Exception::Read("/private/tmp".into())).unwrap();
    bc.lock().unwrap();

    let cmd = Command::new("/bin/ls").arg("/tmp/").status().unwrap();
    println!("{:?}", cmd);
    assert!(cmd.success());

    let cmd = Command::new("/bin/ls").arg("/dev/").status();
    println!("{:?}", cmd);

    // When the child gets locked by the sandbox, on Linux, `cmd` is Err(_).
    #[cfg(target_os = "linux")]
    assert!(cmd.is_err());
    // On MacOS, `cmd` is Ok(ExitStatus(256)) instead.
    #[cfg(target_os = "macos")]
    assert!(!cmd.unwrap().success());

    let cmd_file = fs::read("/bin/ls");
    assert!(cmd_file.is_ok());
}
