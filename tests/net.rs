use std::net::{TcpListener, TcpStream};

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn network() {
    Birdcage::new().unwrap().add_exception(Exception::Networking).unwrap().lock().unwrap();

    TcpStream::connect("8.8.8.8:443").unwrap();
    TcpListener::bind("127.0.0.1:31337").unwrap();
}
