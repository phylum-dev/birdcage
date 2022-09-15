use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn execution() {
    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::ExecuteAndRead("/bin/ls".into())).unwrap();
    bc.add_exception(Exception::Read("/dev/null".into())).unwrap();
    bc.lock().unwrap();

    let cmd = Command::new("/bin/ls").arg("/dev/null").status().unwrap();
    println!("{:?}", cmd);
    assert!(cmd.success());

    let cmd = Command::new("/bin/ls").arg("/tmp/").status().unwrap();
    println!("{:?}", cmd);
    assert!(!cmd.success());

    let cmd_file = fs::read("/bin/ls");
    assert!(cmd_file.is_ok());
}
