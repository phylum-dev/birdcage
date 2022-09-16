use std::net::{TcpListener, TcpStream};

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn network() {
    let resolv_conf_path = std::fs::canonicalize("/etc/resolv.conf").unwrap();

    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::Networking).unwrap();
    bc.add_exception(Exception::Read(resolv_conf_path)).unwrap();
    bc.lock().unwrap();

    TcpStream::connect("example.org:80").unwrap();
    TcpListener::bind("127.0.0.1:31337").unwrap();
}
