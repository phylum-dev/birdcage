use birdcage::{Birdcage, Sandbox};
use serde::{Deserialize, Serialize};

use crate::TestSetup;

#[derive(Serialize, Deserialize)]
struct TestData {
    uid: u32,
    gid: u32,
    euid: u32,
    egid: u32,
}

pub fn setup() -> TestSetup {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    let sandbox = Birdcage::new();

    // Serialize test data.
    let data = TestData { uid, gid, euid, egid };
    let data = serde_json::to_string(&data).unwrap();

    TestSetup { sandbox, data }
}

pub fn validate(data: String) {
    // Deserialize test data.
    let data: TestData = serde_json::from_str(&data).unwrap();

    assert_eq!(data.uid, unsafe { libc::getuid() });
    assert_eq!(data.gid, unsafe { libc::getgid() });
    assert_eq!(data.euid, unsafe { libc::geteuid() });
    assert_eq!(data.egid, unsafe { libc::getegid() });
}
