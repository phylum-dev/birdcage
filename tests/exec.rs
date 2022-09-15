use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn execution() {
    let tmp_path = std::fs::canonicalize("/tmp").unwrap();
    let bin_path = std::fs::canonicalize("/bin").unwrap();
    let lib_path = std::fs::canonicalize("/lib").ok();

    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::ExecuteAndRead("/bin/ls".into())).unwrap();
    bc.add_exception(Exception::Read(tmp_path)).unwrap();
    bc.add_exception(Exception::Read(bin_path)).unwrap();
    lib_path.map(|lib_path| bc.add_exception(Exception::Read(lib_path)).unwrap());
    bc.lock().unwrap();

    // Check for success when executing `ls` against a permitted path.
    let cmd = Command::new("/bin/ls").arg("/tmp/").status().unwrap();
    assert!(cmd.success());

    // Check for errors when executing `ls` against a restricted path.
    let cmd = Command::new("/bin/ls").arg("/dev/").status();

    // When the child gets locked by the sandbox, on Linux, `cmd` is Err(_).
    #[cfg(target_os = "linux")]
    assert!(cmd.is_err());

    // On MacOS, `cmd` is Ok(ExitStatus(256)) instead.
    #[cfg(target_os = "macos")]
    assert!(!cmd.unwrap().success());

    // Check for success on reading the `ls` file.
    let cmd_file = fs::read("/bin/ls");
    assert!(cmd_file.is_ok());
}
