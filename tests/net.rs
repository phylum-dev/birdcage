#[cfg(target_os = "linux")]
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use std::net::{TcpListener, TcpStream};

use birdcage::{Birdcage, Exception, Sandbox};
#[cfg(target_os = "linux")]
use libc;

#[test]
fn network() {
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Networking).unwrap();
    birdcage.lock().unwrap();

    TcpStream::connect("8.8.8.8:443").unwrap();
    TcpListener::bind("127.0.0.1:31337").unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn allow_io_uring() {
    let mut birdcage = Birdcage::new().unwrap();
    birdcage.add_exception(Exception::Networking).unwrap();
    birdcage.lock().unwrap();

    let mut io_uring_params =
        vec![IoUringParams { flags: 1, sq_entries: 32, cq_entries: 32, ..Default::default() }];

    let result = unsafe {
        libc::syscall(libc::SYS_io_uring_setup, io_uring_params.len(), io_uring_params.as_mut_ptr())
    };

    assert_eq!(result >= 0);
}

#[cfg(target_os = "linux")]
#[test]
fn block_io_uring() {
    let birdcage = Birdcage::new().unwrap();
    birdcage.lock().unwrap();

    let mut io_uring_params =
        vec![IoUringParams { flags: 1, sq_entries: 32, cq_entries: 32, ..Default::default() }];

    let result = unsafe {
        libc::syscall(libc::SYS_io_uring_setup, io_uring_params.len(), io_uring_params.as_mut_ptr())
    };

    assert_eq!(result, -1);
    assert_eq!(IoError::last_os_error().kind(), IoErrorKind::PermissionDenied);
}

#[repr(C)]
#[derive(Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoSqringOffsets,
}

#[repr(C)]
#[derive(Default)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv: [u32; 3],
}
