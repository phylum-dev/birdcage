use std::path::PathBuf;
use std::net::TcpStream;

use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup(_tempdir: PathBuf) -> TestSetup {
    // Setup sandbox exceptions.
    let mut sandbox = Birdcage::new();
    sandbox.add_exception(Exception::Networking).unwrap();

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    let result = TcpStream::connect("8.8.8.8:443");
    assert!(result.is_ok());
}
