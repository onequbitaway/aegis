//! The command-line program of AEGIS.
//!
//! | Command | Function |
//! | --- | --- |
//! | `aegis run --config <file>` | Runs the service until SIGINT or SIGTERM. With the module `api`, it also runs the operator API. |
//! | `aegis init --dir <dir>` | Writes a working starter directory. |
//! | `aegis demo [--dir <dir>]` | Replays the recorded attack log in a new starter directory. |
//! | `aegis replay --config <file> --events <jsonl>` | Examines an event file and prints the report. |
//! | `aegis monitor --events <jsonl> [--config <file>]` | Prints each detection and incident of an event file. Takes no action. |
//! | `aegis audit verify --path <file>` | Checks the hash chain of an audit log file. |
//! | `aegis audit show --path <file> [--limit N]` | Prints the newest records of an audit log file. |
//! | `aegis config check --config <file>` | Reports each problem of a configuration. Starts nothing. |
//! | `aegis report abuse --config <file> --incident <id> --out <dir>` | Writes the abuse reports of one incident. Sends nothing. |
//! | `aegis indicators export --config <file> --format stix\|csv\|pack --tlp <level> --out <file>` | Writes the indicators of the evidence archive. Sends nothing. |
//! | `aegis reverts list\|confirm\|extend\|cancel` | Shows and decides the timed reverts of a running service, through its operator API. Cargo feature `api`. |
//!
//! Each command writes its report to the standard output stream and its log to the
//! standard error stream. A command that fails writes the cause to the standard error
//! stream and exits with a status that is not zero.

#[cfg(feature = "api")]
mod client;
mod commands;
mod output;
#[cfg(feature = "api")]
mod reverts;
mod share;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

/// The format of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Text for a person.
    Text,
    /// JSON for a program.
    Json,
}

/// The values of the option `--format`.
///
/// `text` and `json` are the formats of the report of each command. `stix`, `csv`, and
/// `pack` are the document formats of `aegis indicators export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatOption {
    /// Text for a person.
    Text,
    /// JSON for a program.
    Json,
    /// Only for `indicators export`: one STIX 2.1 bundle.
    Stix,
    /// Only for `indicators export`: CSV text.
    Csv,
    /// Only for `indicators export`: an indicator file for a rule pack, from the
    /// detections of decoys.
    Pack,
}

impl FormatOption {
    /// Returns the report format of a command that writes no indicator document.
    fn report(self) -> anyhow::Result<Format> {
        match self {
            Self::Text => Ok(Format::Text),
            Self::Json => Ok(Format::Json),
            Self::Stix | Self::Csv | Self::Pack => anyhow::bail!(
                "the formats stix, csv, and pack are document formats of `aegis indicators \
                 export`. Use --format text or --format json with this command"
            ),
        }
    }

    /// Returns the document format of `aegis indicators export`.
    fn indicators(self) -> anyhow::Result<share::IndicatorFormat> {
        match self {
            Self::Stix => Ok(share::IndicatorFormat::Stix),
            Self::Csv => Ok(share::IndicatorFormat::Csv),
            Self::Pack => Ok(share::IndicatorFormat::Pack),
            Self::Text | Self::Json => anyhow::bail!(
                "select the format of the indicator document with --format stix, --format \
                 csv, or --format pack"
            ),
        }
    }
}

/// The values of the option `--tlp`: the Traffic Light Protocol level of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TlpOption {
    /// No limit on disclosure. TLP 2.0 names this level CLEAR.
    White,
    /// Disclosure in the community of the receiver.
    Green,
    /// Disclosure in the organization of the receiver, and to its clients if they must
    /// know.
    Amber,
    /// No disclosure outside the named receivers.
    Red,
}

impl From<TlpOption> for aegis_app::sharing::Tlp {
    fn from(level: TlpOption) -> Self {
        match level {
            TlpOption::White => Self::White,
            TlpOption::Green => Self::Green,
            TlpOption::Amber => Self::Amber,
            TlpOption::Red => Self::Red,
        }
    }
}

/// AEGIS: a defensive agentic security framework.
#[derive(Debug, Parser)]
#[command(name = "aegis", version, about, long_about = None)]
struct Cli {
    /// The format of the report on the standard output stream: text or json. For
    /// `indicators export`, the format of the document: stix, csv, or pack.
    #[arg(long, global = true, value_enum, default_value = "text")]
    format: FormatOption,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the service until SIGINT or SIGTERM. With `api` in `[modules]`, the command
    /// also runs the operator API: the REST API, the web console, and ChatOps.
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
    /// Write a report for a different organization. The command sends nothing.
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Write indicators for other defenders. The command sends nothing.
    Indicators {
        #[command(subcommand)]
        command: IndicatorsCommand,
    },
    /// Show and decide the timed reverts of a running service. A timed revert is a
    /// containment action that AEGIS reverts at a set time, unless a person confirms it.
    ///
    /// These commands call the operator API of the running service. They do not read the
    /// revert store file: one scheduler uses one store. The service must run with the
    /// module `api`. The token comes from an environment variable, and its principal
    /// needs the permission `approve_actions`.
    #[cfg(feature = "api")]
    Reverts {
        #[command(flatten)]
        api: ApiOptions,
        #[command(subcommand)]
        command: RevertsCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    /// Write the abuse reports of one incident: one directory for each attacker address,
    /// with report.md, report.json, evidence.jsonl, and manifest.json. The command reads
    /// the incident, the audit log, and the evidence archive. It needs the networks of
    /// your organization in `[share] operator_networks`, so that no report names an
    /// address of your own. It sends nothing.
    Abuse {
        /// The configuration file.
        #[arg(long)]
        config: PathBuf,
        /// The identifier of the incident.
        #[arg(long)]
        incident: String,
        /// The directory for the reports. The command makes it. It replaces no file.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum IndicatorsCommand {
    /// Write the indicators of the evidence archive to one file. With --format stix or
    /// --format csv, the file is for other defenders, and --tlp sets its marking. With
    /// --format pack, the file holds the detections of decoys as indicators for your own
    /// rule pack. The command needs `[share] operator_networks`. It sends nothing.
    Export {
        /// The configuration file.
        #[arg(long)]
        config: PathBuf,
        /// The TLP level of the document. It is necessary for stix and csv. There is no
        /// default level.
        #[arg(long, value_enum)]
        tlp: Option<TlpOption>,
        /// The file to write. With stix and csv, the command replaces no file. With pack,
        /// an existing indicator file keeps its indicators and gets the new ones.
        #[arg(long)]
        out: PathBuf,
        /// Use only the detections of this incident.
        #[arg(long)]
        incident: Option<String>,
    },
}

/// How a command finds the operator API of the running service.
#[cfg(feature = "api")]
#[derive(Debug, clap::Args)]
struct ApiOptions {
    /// The address of the operator API. The default is the value of the environment
    /// variable AEGIS_API_URL, or http://127.0.0.1:8080. Use https for an address that is
    /// not a loopback address.
    #[arg(long, global = true)]
    url: Option<String>,
    /// The NAME of the environment variable that holds the API token. The token itself is
    /// never an argument.
    #[arg(long, global = true, default_value = client::DEFAULT_TOKEN_VARIABLE)]
    token_env: String,
}

#[cfg(feature = "api")]
#[derive(Debug, Subcommand)]
enum RevertsCommand {
    /// List the timed reverts that wait, with the earliest revert time first.
    List,
    /// Confirm an action. The containment stays, and AEGIS does not revert it.
    Confirm {
        /// The identifier of the action, from `aegis reverts list`.
        action_id: String,
    },
    /// Move the revert time of an action.
    Extend {
        /// The identifier of the action, from `aegis reverts list`.
        action_id: String,
        /// The time to add: a number of seconds, or a number with the unit s, m, h, or
        /// d, for example 4h.
        #[arg(long)]
        by: String,
    },
    /// Revert an action now, before its revert time. The revert goes through the policy
    /// of the service.
    Cancel {
        /// The identifier of the action, from `aegis reverts list`.
        action_id: String,
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
    let selected = cli.format;
    let format = match &cli.command {
        // The option `--format` selects the document of this command. Its report is text.
        Command::Indicators { .. } => Format::Text,
        _ => selected.report()?,
    };
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
        Command::Report { command } => match command {
            ReportCommand::Abuse {
                config,
                incident,
                out,
            } => share::report_abuse(&config, &incident, &out, format).await,
        },
        Command::Indicators { command } => match command {
            IndicatorsCommand::Export {
                config,
                tlp,
                out,
                incident,
            } => {
                share::indicators_export(
                    &config,
                    incident.as_deref(),
                    selected.indicators()?,
                    tlp.map(Into::into),
                    &out,
                    format,
                )
                .await
            }
        },
        #[cfg(feature = "api")]
        Command::Reverts { api, command } => {
            let client = client::ApiClient::from_environment(api.url.as_deref(), &api.token_env)?;
            match command {
                RevertsCommand::List => reverts::list(&client, format).await,
                RevertsCommand::Confirm { action_id } => {
                    reverts::confirm(&client, &action_id, format).await
                }
                RevertsCommand::Extend { action_id, by } => {
                    reverts::extend(&client, &action_id, &by, format).await
                }
                RevertsCommand::Cancel { action_id } => {
                    reverts::cancel(&client, &action_id, format).await
                }
            }
        }
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
