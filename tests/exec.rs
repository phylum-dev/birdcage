// This has to be run with --test-threads 1: the activation of the sandbox is
// irreversible in the current process, and the interleaving of threads may
// make it so one thread doesn't have the privilege to execute some code
// because of the sandbox that has been set up in the other.

use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

#[test]
#[cfg(unix)]
fn it_blocks_child_with_pre_exec() {
    use std::os::unix::process::CommandExt;

    let bc = Birdcage::new().unwrap();

    // Lock the sandbox in the `pre_exec` callback. This will run in the child
    // process, just before the `execvp` syscall. The parent process will not be
    // affected.
    //
    // See this: <https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.pre_exec>
    let cmd = unsafe {
        Command::new("/bin/ls")
            .pre_exec(move || {
                let bc = bc.clone();
                bc.lock().unwrap();
                Ok(())
            })
            .arg("/tmp")
            .spawn()
    };
    assert!(cmd.is_err());

    // Make sure the same command without sandbox is still able to run, and the
    // parent (i.e. current) process is not affected by the sandbox.
    let cmd = Command::new("/bin/ls").arg("/tmp").spawn();
    assert!(cmd.is_ok());
}

#[test]
fn it_blocks_execution() {
    let cmd = Command::new("/bin/ls").arg("/tmp").spawn();
    assert!(cmd.is_ok());

    let mut bc = Birdcage::new().unwrap();

    bc.add_exception(Exception::ExecuteAndRead("/bin/ls".into())).unwrap();

    bc.lock().unwrap();

    let cmd = Command::new("/bin/ls").arg("/tmp").spawn();
    assert!(cmd.is_err());
}
