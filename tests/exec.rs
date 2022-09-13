use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn it_blocks_execution() {
    let cmd = Command::new("/bin/ls").arg("/tmp").spawn();
    assert!(cmd.is_ok());

    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::ExecuteAndRead("/bin/ls".into())).unwrap();
    bc.lock().unwrap();

    let cmd = Command::new("/bin/ls").arg("/tmp").spawn();
    assert!(cmd.is_err());
}
