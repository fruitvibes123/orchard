use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    match grocer::run(grocer::Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("grocer: {e}");
            ExitCode::FAILURE
        }
    }
}
