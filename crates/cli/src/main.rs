//! The command-line program of AEGIS.
//!
//! | Command | Function |
//! | --- | --- |
//! | `aegis run --config <file>` | Runs the service until SIGINT or SIGTERM. |
//! | `aegis init --dir <dir>` | Writes a working starter directory. |
//! | `aegis demo [--dir <dir>]` | Replays the recorded attack log in a new starter directory. |
//! | `aegis replay --config <file> --events <jsonl>` | Examines an event file and prints the report. |
//! | `aegis monitor --events <jsonl> [--config <file>]` | Prints each detection and incident of an event file. Takes no action. |
//! | `aegis audit verify --path <file>` | Checks the hash chain of an audit log file. |
//! | `aegis audit show --path <file> [--limit N]` | Prints the newest records of an audit log file. |
//! | `aegis config check --config <file>` | Reports each problem of a configuration. Starts nothing. |
//!
//! Each command writes its report to the standard output stream and its log to the
//! standard error stream. A command that fails writes the cause to the standard error
//! stream and exits with a status that is not zero.

mod commands;
mod output;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

/// The format of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Text for a person.
    Text,
    /// JSON for a program.
    Json,
}

/// AEGIS: a defensive agentic security framework.
#[derive(Debug, Parser)]
#[command(name = "aegis", version, about, long_about = None)]
struct Cli {
    /// The format of the report on the standard output stream.
    #[arg(long, global = true, value_enum, default_value = "text")]
    format: Format,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the service until SIGINT or SIGTERM.
    Run {
        /// The configuration file. A relative path in it starts at its directory.
        #[arg(long)]
        config: PathBuf,
    },
    /// Write a working starter directory: the configuration, the detection pack, the
    /// default policy, and the sample playbooks. The command replaces no file.
    Init {
        /// The directory to write to. The command makes it if it does not exist.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Replay the recorded attack log in a new starter directory, as a dry run with no
    /// model. Print the detections, the incident, the actions, and the audit result.
    Demo {
        /// The directory for the starter files. The default is a new temporary directory.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Examine an event file in the process and print the report.
    Replay {
        /// The configuration file.
        #[arg(long)]
        config: PathBuf,
        /// The event file: one normalized event in each line (JSON Lines).
        #[arg(long)]
        events: PathBuf,
        /// Make each action a dry run, also when the configuration permits changes.
        #[arg(long)]
        dry_run: bool,
        /// Write the audit log to this file, in place of the audit log of the
        /// configuration. One process writes one audit file.
        #[arg(long)]
        audit_file: Option<PathBuf>,
    },
    /// Read an event file through the bus and the detection engine. Print each detection
    /// and each incident when it occurs. Take no action.
    Monitor {
        /// The event file: one normalized event in each line (JSON Lines).
        #[arg(long)]
        events: PathBuf,
        /// The configuration file for the rule pack and the detection settings. The
        /// default is the starter configuration. The session does not use the bus, the
        /// storage, or the audit log of the configuration.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Examine an audit log file.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Examine a configuration file.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Check the hash chain of an audit log file. The exit status is not zero if the
    /// chain is not valid.
    Verify {
        /// The audit log file.
        #[arg(long)]
        path: PathBuf,
    },
    /// Print the newest records of an audit log file.
    Show {
        /// The audit log file.
        #[arg(long)]
        path: PathBuf,
        /// The largest number of records to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Build the application from the configuration and report each problem. The command
    /// starts nothing.
    Check {
        /// The configuration file.
        #[arg(long)]
        config: PathBuf,
    },
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let format = cli.format;
    match cli.command {
        Command::Run { config } => commands::run(&config, format).await,
        Command::Init { dir } => commands::init(&dir, format),
        Command::Demo { dir } => commands::demo(dir, format).await,
        Command::Replay {
            config,
            events,
            dry_run,
            audit_file,
        } => commands::replay(&config, &events, dry_run, audit_file, format).await,
        Command::Monitor { events, config } => {
            commands::monitor(&events, config.as_deref(), format).await
        }
        Command::Audit { command } => match command {
            AuditCommand::Verify { path } => commands::audit_verify(&path, format),
            AuditCommand::Show { path, limit } => commands::audit_show(&path, limit, format),
        },
        Command::Config { command } => match command {
            ConfigCommand::Check { config } => commands::config_check(&config, format).await,
        },
    }
}

fn main() -> ExitCode {
    // All TLS connections of the process use the `aws-lc-rs` provider. A second install
    // is not possible, so the result of a later call does not matter.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start the asynchronous runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(dispatch(cli));
    // A component can leave a blocking task behind. Do not wait for it.
    runtime.shutdown_background();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
