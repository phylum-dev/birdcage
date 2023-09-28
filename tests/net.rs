use std::net::TcpStream;

use birdcage::{Birdcage, Exception, Sandbox};

fn main() {
    let mut birdcage = Birdcage::new();
    birdcage.add_exception(Exception::Networking).unwrap();
    birdcage.lock().unwrap();

    let result = TcpStream::connect("8.8.8.8:443");
    assert!(result.is_ok());
}
