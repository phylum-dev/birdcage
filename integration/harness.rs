use std::process::{self, Command, Stdio};

use birdcage::{Birdcage, Exception, Sandbox};

test_mods! {
    mod canonicalize;
    #[cfg(target_os = "linux")]
    mod consistent_id_mappings;
    mod delete_before_lockdown;
    mod env;
    mod exec;
    mod exec_symlinked_dir;
    mod exec_symlinked_dirs_exec;
    mod exec_symlinked_file;
    mod fs;
    mod fs_broken_symlink;
    mod fs_null;
    mod fs_readonly;
    mod fs_restrict_child;
    mod fs_symlink;
    mod fs_symlink_dir;
    mod fs_symlink_dir_separate_perms;
    mod fs_write_also_read;
    mod full_env;
    mod full_sandbox;
    mod missing_exception;
    mod net;
    #[cfg(target_os = "linux")]
    mod seccomp;
}

/// Integration test directory.
const TEST_DIR: &str = "integration";

/// Test setup state.
pub struct TestSetup {
    pub sandbox: Birdcage,
    pub data: String,
}

fn main() {
    let mut args = std::env::args().skip(1);

    // Get test name or spawn all the tests.
    let test_name = match args.next() {
        Some(test_name) => test_name,
        None => {
            spawn_tests();
            return;
        },
    };

    // Find test matching the name.
    let test = match TESTS.iter().find(|(cmd, ..)| cmd == &test_name) {
        Some(test) => test,
        None => unreachable!("invalid test module name: {test_name:?}"),
    };

    // Run setup or test validation.
    match args.next() {
        Some(test_data) => test.2(test_data),
        None => run_setup(&test_name, &test.1),
    }
}

/// Reexecute binary to launch tests as separate processes.
///
/// Returns `true` on success.
fn spawn_tests() {
    eprintln!("\nrunning {} tests", TESTS.len());

    // Spawn child processes for all tests.
    let current_exe = std::env::current_exe().unwrap();
    let children: Vec<_> = TESTS
        .iter()
        .map(|(cmd, ..)| {
            let child =
                Command::new(&current_exe).args([cmd]).stderr(Stdio::piped()).spawn().unwrap();
            (cmd, child)
        })
        .collect();

    // Check results for each test.
    let mut passed = 0;
    for (name, child) in children {
        let output = match child.wait_with_output() {
            Ok(output) => output,
            Err(err) => {
                eprintln!("test {TEST_DIR}/{name}.rs ... \x1b[31mHARNESS FAILURE\x1b[0m: {err}");
                continue;
            },
        };

        // Report individual test results.
        if !output.status.success() {
            eprintln!("test {TEST_DIR}/{name}.rs ... \x1b[31mFAILED\x1b[0m");

            // Print stderr on failure if there is some.
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                eprintln!("\n---- {TEST_DIR}/{name}.rs stderr ----\n{}\n", stderr.trim());
            }
        } else {
            eprintln!("test {TEST_DIR}/{name}.rs ... \x1b[32mok\x1b[0m");
            passed += 1;
        }
    }

    // Print total results.
    let failed = TESTS.len() - passed;
    if failed > 0 {
        eprintln!("\ntest result: \x1b[31mFAILED\x1b[0m. {} passed; {} failed", passed, failed);
    } else {
        eprintln!("\ntest result: \x1b[32mok\x1b[0m. {} passed; {} failed", passed, failed);
    }

    eprintln!();
}

/// Run test's setup step and spawn validation child.
fn run_setup(test_name: &str, setup: &fn() -> TestSetup) {
    // Run test setup.
    let mut test_setup = setup();

    // Add exceptions to allow self-execution.
    let current_exe = std::env::current_exe().unwrap();
    for path in [current_exe.clone(), "/usr/lib".into(), "/lib64".into(), "/lib".into()] {
        if path.exists() {
            test_setup.sandbox.add_exception(Exception::ExecuteAndRead(path)).unwrap();
        }
    }

    // Reexecute test with sandbox enabled.
    let mut command = Command::new(current_exe);
    command.args([test_name, &test_setup.data.as_str()]);
    let child = test_setup.sandbox.spawn(command).unwrap();

    // Validate test results.
    let output = child.wait_with_output().unwrap();
    if !output.status.success() {
        process::exit(output.status.code().unwrap_or(1));
    }
}

#[macro_export]
macro_rules! test_mods {
    ($($(#[$cfg:meta])? mod $mod:ident);*;) => {
        $(
            $( #[$cfg] )?
            mod $mod;
        )*

        const TESTS: &[(&str, fn() -> $crate::TestSetup, fn(String))] = &[$(
            $( #[$cfg] )?
            (stringify!($mod), $mod :: setup, $mod :: validate),
        )*];
    };
}
