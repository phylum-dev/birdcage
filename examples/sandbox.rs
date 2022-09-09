//! Sandbox arbitrary executables.

use std::error::Error;
use std::path::PathBuf;
use std::process::{self, Command};

use birdcage::{Birdcage, Exception, Sandbox};
use clap::{Parser, ValueHint};

#[derive(Parser)]
#[clap(author, about)]
struct Cli {
    /// Allowed read paths.
    #[clap(short = 'r', long, value_name = "PATH", value_hint = ValueHint::AnyPath)]
    allow_read: Vec<PathBuf>,

    /// Allowed write paths.
    #[clap(short = 'w', long, value_name = "PATH", value_hint = ValueHint::AnyPath)]
    allow_write: Vec<PathBuf>,

    /// Allowed read and execute paths.
    #[clap(short = 'e', long, value_name = "PATH", value_hint = ValueHint::AnyPath)]
    allow_execute: Vec<PathBuf>,

    /// Allow networking.
    #[clap(short = 'n', long)]
    allow_networking: bool,

    /// Command to be executed in the sandbox.
    cmd: String,

    /// Arguments for the sandboxed command.
    #[clap(allow_hyphen_values = true, multiple_values = true)]
    args: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // Setup sandbox and its exceptions.
    let mut birdcage = Birdcage::new()?;
    for path in cli.allow_read {
        birdcage.add_exception(Exception::Read(path))?;
    }
    for path in cli.allow_write {
        birdcage.add_exception(Exception::Write(path))?;
    }
    for path in cli.allow_execute {
        birdcage.add_exception(Exception::ExecuteAndRead(path))?;
    }
    if cli.allow_networking {
        birdcage.add_exception(Exception::Networking)?;
    }

    // Activate sandbox.
    birdcage.lock().unwrap();

    // Run the command.
    let status = Command::new(cli.cmd).args(&cli.args).spawn()?.wait()?;
    let exit_code = status.code().unwrap_or(111);

    process::exit(exit_code);
}
