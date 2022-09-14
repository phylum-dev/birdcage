use std::net::{TcpListener, TcpStream};

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
fn network() {
    let mut bc = Birdcage::new().unwrap();
    bc.add_exception(Exception::Networking).unwrap();
    bc.add_exception(Exception::Read("/etc/resolv.conf".into())).unwrap();
    bc.add_exception(Exception::Read("/var/run/resolv.conf".into())).unwrap();
    bc.add_exception(Exception::Read("/etc/ca-certificates".into())).unwrap();
    bc.add_exception(Exception::Read("/etc/ssl".into())).unwrap();
    bc.lock().unwrap();

    let stream = TcpStream::connect("phylum.io:443");
    println!("{:?}", stream);
    assert!(stream.is_ok());
    drop(stream);

    let listener = TcpListener::bind("127.0.0.1:31337");
    assert!(listener.is_ok());
    drop(listener);

}
