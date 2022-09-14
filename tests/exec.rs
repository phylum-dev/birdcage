use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn execution() {
    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::ExecuteAndRead("/bin/echo".into())).unwrap();
    bc.lock().unwrap();

    let cmd = Command::new("/bin/echo").arg("hello world").status();
    println!("{:?}", cmd);
    assert!(cmd.is_ok());

    let cmd_file = fs::read("/bin/echo");
    assert!(cmd_file.is_ok());
}
