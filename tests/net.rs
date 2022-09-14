use std::net::{TcpListener, TcpStream};

use birdcage::{Birdcage, Sandbox};

#[test]
fn it_blocks_network() {
    let listener = TcpListener::bind("127.0.0.1:31337");
    assert!(listener.is_ok());
    drop(listener);

    let stream = TcpStream::connect("www.google.com:443");
    assert!(stream.is_ok());
    drop(stream);

    Birdcage::new().unwrap().lock().unwrap();

    let listener = TcpListener::bind("127.0.0.1:31337");
    assert!(listener.is_err());
    drop(listener);

    let stream = TcpStream::connect("www.google.com:443");
    assert!(stream.is_err());
    drop(stream);
}
