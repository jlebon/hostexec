// Entrypoint

mod client;
mod protocol;
mod serve;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "hostexec")]
struct Cli {
    /// Log all requests (not just warnings and errors).
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute a command on the host.
    Run {
        /// Path to the daemon socket.
        #[arg(long, env = "HOSTEXEC_SOCKET")]
        socket: PathBuf,
        /// Command and arguments to run.
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Fire a named hook on the host.
    Notify {
        /// Path to the daemon socket.
        #[arg(long, env = "HOSTEXEC_SOCKET")]
        socket: PathBuf,
        /// Hook name (e.g. "idle", "busy").
        hook: String,
    },
    /// Start the host execution daemon.
    Serve {
        /// Write the created socket path to this file.
        #[arg(long)]
        write_socket_path_to: Option<PathBuf>,
        /// Auto-approve all commands (for testing only).
        #[arg(long)]
        dangerously_approve_all: bool,
    },
    /// Show interactive approval prompt (internal, used by tmux popup).
    Prompt,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let level = if cli.verbose {
        Level::INFO
    } else {
        Level::WARN
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(level.into())
                .from_env_lossy(),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let result: anyhow::Result<ExitCode> = match cli.command {
        Command::Run { socket, cmd } => client::cmd_run(&socket, &cmd),
        Command::Notify { socket, hook } => client::cmd_notify(&socket, &hook),
        Command::Serve {
            write_socket_path_to,
            dangerously_approve_all,
        } => serve::cmd_serve(write_socket_path_to.as_deref(), dangerously_approve_all)
            .map(|()| ExitCode::SUCCESS),
        Command::Prompt => serve::cmd_prompt(),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
