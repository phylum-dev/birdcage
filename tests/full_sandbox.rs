use std::fs;
use std::net::{TcpListener, TcpStream};
use std::process::Command;

use birdcage::{Birdcage, Sandbox};
use tempfile::NamedTempFile;

#[test]
fn full_sandbox() {
    const FILE_CONTENT: &str = "expected content";

    // Create testfile.
    let path = fs::canonicalize(NamedTempFile::new().unwrap()).unwrap();

    // Ensure non-sandboxed write works.
    fs::write(&path, FILE_CONTENT.as_bytes()).unwrap();

    // Ensure non-sandboxed read works.
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Ensure non-sandboxed socket bind works.
    let listener = TcpListener::bind("127.0.0.1:31337");
    assert!(listener.is_ok());
    drop(listener);

    // Ensure non-sandboxed socket connect works.
    let stream = TcpStream::connect("phylum.io:443");
    assert!(stream.is_ok());
    drop(stream);

    // Ensure non-sandboxed execution works.
    let cmd = Command::new("/bin/echo").arg("hello world").spawn();
    assert!(cmd.is_ok());

    // Activate our sandbox.
    Birdcage::new().unwrap().lock().unwrap();

    // Ensure sandboxed write is blocked.
    let result = fs::write(&path, b"x");
    assert!(result.is_err());

    // Ensure sandboxed read is blocked.
    let result = fs::read_to_string(path);
    assert!(result.is_err());

    // Ensure sandboxed socket bind is blocked.
    let listener = TcpListener::bind("127.0.0.1:31337");
    assert!(listener.is_err());
    drop(listener);

    // Ensure sandboxed socket connect is blocked.
    let stream = TcpStream::connect("phylum.io:443");
    assert!(stream.is_err());
    drop(stream);

    // Ensure sandboxed execution is blocked.
    let cmd = Command::new("/bin/echo").arg("hello world").spawn();
    assert!(cmd.is_err());
}
