use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn execution() {
    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::ExecuteAndRead("/bin/ls".into())).unwrap();
    bc.add_exception(Exception::Read("/tmp".into())).unwrap();
    bc.lock().unwrap();

    let cmd = Command::new("/bin/ls").arg("/tmp").spawn();
    assert!(cmd.is_ok());

    let cmd_file = fs::read("/bin/ls");
    assert!(cmd_file.is_ok());
}
