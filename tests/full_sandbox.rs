use std::net::TcpStream;
use std::process::Command;
use std::{env, fs};

use birdcage::{Birdcage, Sandbox};
use tempfile::NamedTempFile;

fn main() {
    const FILE_CONTENT: &str = "expected content";

    // Create testfile.
    let path = NamedTempFile::new().unwrap();

    // Ensure non-sandboxed write works.
    fs::write(&path, FILE_CONTENT.as_bytes()).unwrap();

    // Ensure non-sandboxed read works.
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, FILE_CONTENT);

    // Ensure non-sandboxed socket connect works.
    let stream = TcpStream::connect("phylum.io:443");
    assert!(stream.is_ok());
    drop(stream);

    // Ensure non-sandboxed execution works.
    let cmd = Command::new("/usr/bin/true").status();
    assert!(cmd.is_ok());

    // Ensure non-sandboxed env access works.
    env::set_var("TEST", "value");
    assert_eq!(env::var("TEST"), Ok("value".into()));

    // Activate our sandbox.
    Birdcage::new().lock().unwrap();

    // Ensure sandboxed write is blocked.
    let result = fs::write(&path, b"x");
    assert!(result.is_err());

    // Ensure sandboxed read is blocked.
    let result = fs::read_to_string(path);
    assert!(result.is_err());

    // Ensure sandboxed socket connect is blocked.
    let stream = TcpStream::connect("phylum.io:443");
    assert!(stream.is_err());
    drop(stream);

    // Ensure sandboxed execution is blocked.
    let cmd = Command::new("/usr/bin/true").status();
    assert!(cmd.is_err());

    // Ensure sandboxed env access is blocked.
    assert_eq!(env::var_os("TEST"), None);
}
