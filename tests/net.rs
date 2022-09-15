use std::net::{TcpListener, TcpStream};

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn network() {
    let resolv_conf_path = std::fs::canonicalize("/etc/resolv.conf").unwrap();

    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::Networking).unwrap();
    bc.add_exception(Exception::Read(resolv_conf_path)).unwrap();
    bc.lock().unwrap();

    let stream = TcpStream::connect("phylum.io:443");
    println!("{:?}", stream);
    assert!(stream.is_ok());
    drop(stream);

    let listener = TcpListener::bind("127.0.0.1:31337");
    assert!(listener.is_ok());
    drop(listener);
}
