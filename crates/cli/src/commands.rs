//! The commands of the program.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aegis_app::report::ReplayReport;
use aegis_app::{App, RunOptions, Service, preflight, starter};
use aegis_contracts::Detection;
use aegis_contracts::audit::{AuditRecord, ChainVerification};
use aegis_contracts::bus::{BusStream, subject};
use aegis_contracts::incident::Incident;
use aegis_core::{Config, Module, ModuleSet, Shutdown, TelemetryConfig, TelemetryGuard, telemetry};
use aegis_ingest::{FileSource, FileSourceConfig};
use aegis_policy::FileAuditLog;
use anyhow::{Context as _, anyhow, bail};
use futures::StreamExt;
use serde_json::json;
use tokio::sync::watch;

use crate::Format;
use crate::output::{
    audit_line, chain_lines, detection_line, incident_lines, print, print_json, print_json_line,
    replay_text,
};

/// The time that `monitor` waits for the bus to deliver the last detections.
const DELIVERY_LIMIT: Duration = Duration::from_secs(30);

/// The name of the source connector of `monitor`.
const MONITOR_SOURCE: &str = "events";

/// Returns the directory that the relative paths of a configuration file start at.
fn base_dir(config_file: &Path) -> anyhow::Result<PathBuf> {
    let absolute = std::path::absolute(config_file).with_context(|| {
        format!(
            "cannot find the directory of the configuration file {}",
            config_file.display()
        )
    })?;
    Ok(absolute
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf))
}

/// Reads a configuration file and applies the `AEGIS__` environment variables.
fn load(config_file: &Path) -> anyhow::Result<Config> {
    Ok(Config::load_with_env(config_file)?)
}

/// Installs the log subscriber that the `[telemetry]` section describes.
fn start_telemetry(config: &Config) -> anyhow::Result<TelemetryGuard> {
    let settings = TelemetryConfig::from_config(config)?;
    Ok(telemetry::init(&settings)?)
}

/// Reads an event file: one normalized event in each line.
fn read_events(path: &Path) -> anyhow::Result<Vec<aegis_contracts::Event>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the event file {}", path.display()))?;
    starter::events_from_jsonl(&text)
        .with_context(|| format!("the event file {} is not valid", path.display()))
}

/// Returns the components that run with the application in `aegis run`.
///
/// The module `api` gives the operator API. The function checks the `[api]` section with
/// its secrets and opens the listener. Thus a configuration that is not usable stops the
/// command before the application starts its sources.
///
/// This is the place to start one more long-running component from the services of the
/// application. Give the component the module that it implements with
/// [`Service::for_module`].
async fn services(app: &Arc<App>) -> aegis_contracts::Result<Vec<Service>> {
    // The module `api` needs the Cargo feature `api`, the `[api]` section, and an agent.
    app.settings().check_api_module()?;
    #[cfg(feature = "api")]
    if app.modules().contains(Module::Api) {
        return Ok(vec![aegis_app::api::service(app).await?]);
    }
    Ok(Vec::new())
}

/// Returns the address in `api.bind` if `aegis run` starts the operator API, or `off`.
fn api_address(app: &App) -> String {
    if !app.modules().contains(Module::Api) {
        return "off".to_owned();
    }
    #[cfg(feature = "api")]
    if let Some(api) = &app.settings().api {
        return api.bind.to_string();
    }
    "off".to_owned()
}

/// `aegis run`: runs the service until SIGINT or SIGTERM.
pub async fn run(config_file: &Path, format: Format) -> anyhow::Result<()> {
    let config = load(config_file)?;
    let telemetry = start_telemetry(&config)?;
    let app = Arc::new(
        App::builder(&config)
            .base_dir(base_dir(config_file)?)
            .build()
            .await?,
    );
    let shutdown = Shutdown::new();
    shutdown.listen_for_signals()?;

    let result = match services(&app).await {
        Ok(services) => {
            tracing::info!(config = %config_file.display(), "AEGIS runs. Send SIGINT or SIGTERM to stop.");
            let options = RunOptions {
                stop_when_sources_end: false,
                services,
            };
            app.run_with(shutdown, options).await
        }
        Err(error) => Err(error),
    };
    app.close().await;
    let summary = result?;
    match format {
        Format::Json => print_json(&summary)?,
        Format::Text => {
            let progress = summary.progress;
            print(&format!(
                "AEGIS stopped. Events examined: {}. Detections: {}. Incident changes: {}. \
                 Playbook runs: {}.\n",
                progress.events_processed,
                progress.detections,
                progress.incident_updates,
                progress.playbook_runs
            ))?;
        }
    }
    drop(telemetry);
    Ok(())
}

/// `aegis init`: writes the starter directory.
pub fn init(directory: &Path, format: Format) -> anyhow::Result<()> {
    let written = starter::write(directory)?;
    let config = directory.join(starter::CONFIG_FILE);
    match format {
        Format::Json => print_json(&json!({
            "directory": directory,
            "config": config,
            "files": written,
        })),
        Format::Text => {
            let mut text = format!(
                "Wrote {} files to {}:\n",
                written.len(),
                directory.display()
            );
            for path in &written {
                text.push_str(&format!("  {}\n", path.display()));
            }
            text.push_str(&format!(
                "\nNext steps:\n  aegis config check --config {0}\n  aegis run --config {0}\n",
                config.display()
            ));
            print(&text)
        }
    }
}

/// Prints a replay report. Fails if the audit chain is not valid.
fn finish_replay(
    title: &str,
    report: &ReplayReport,
    audit_file: Option<&Path>,
    format: Format,
) -> anyhow::Result<()> {
    match format {
        Format::Json => print_json(report)?,
        Format::Text => print(&replay_text(title, report, audit_file))?,
    }
    if !report.audit.verification.valid {
        bail!(
            "the hash chain of the audit log is not valid: {}",
            invalid_chain(&report.audit.verification)
        );
    }
    Ok(())
}

fn invalid_chain(verification: &ChainVerification) -> String {
    format!(
        "the first invalid sequence is {}: {}",
        verification
            .first_invalid_sequence
            .map_or_else(|| "not known".to_owned(), |sequence| sequence.to_string()),
        verification.reason.as_deref().unwrap_or("no reason given")
    )
}

/// `aegis demo`: replays the recorded attack log in a new starter directory.
pub async fn demo(directory: Option<PathBuf>, format: Format) -> anyhow::Result<()> {
    let directory = match directory {
        Some(directory) => directory,
        // The directory stays after the command, so that the operator can read the
        // configuration and the audit log of the demonstration.
        None => tempfile::Builder::new()
            .prefix("aegis-demo-")
            .tempdir()
            .context("cannot make a temporary directory for the demonstration")?
            .keep(),
    };
    starter::write(&directory)?;
    // The demonstration does not read the environment: it is always a dry run with no
    // model, on the in-process bus and the in-memory storage.
    let config = Config::load(directory.join(starter::CONFIG_FILE))?;
    let telemetry = start_telemetry(&config)?;
    let app = App::builder(&config)
        .base_dir(&directory)
        .force_dry_run()
        .build()
        .await?;
    let report = app.replay(starter::attack_events()?).await?;
    let audit_file = app.audit_path().map(Path::to_path_buf);
    drop(app);

    // The chain must also verify from the file on the disk, with no open log.
    if let Some(path) = &audit_file {
        let from_file = FileAuditLog::verify_file(path)?;
        if !from_file.valid {
            bail!(
                "the audit log file {} does not verify: {}",
                path.display(),
                invalid_chain(&from_file)
            );
        }
    }
    finish_replay(
        "AEGIS demonstration: replay of the recorded attack log",
        &report,
        audit_file.as_deref(),
        format,
    )?;
    if format == Format::Text {
        print(&format!(
            "\nThe starter directory is {}.\nRun the service with: aegis run --config {}\n",
            directory.display(),
            directory.join(starter::CONFIG_FILE).display()
        ))?;
    }
    drop(telemetry);
    Ok(())
}

/// `aegis replay`: examines an event file and prints the report.
pub async fn replay(
    config_file: &Path,
    events_file: &Path,
    dry_run: bool,
    audit_file: Option<PathBuf>,
    format: Format,
) -> anyhow::Result<()> {
    let config = load(config_file)?;
    let telemetry = start_telemetry(&config)?;
    let events = read_events(events_file)?;
    let mut builder = App::builder(&config).base_dir(base_dir(config_file)?);
    if dry_run {
        builder = builder.force_dry_run();
    }
    if let Some(audit_file) = audit_file {
        // The path of the command line starts at the working directory.
        builder =
            builder.audit_file(std::path::absolute(&audit_file).with_context(|| {
                format!("cannot use the audit file path {}", audit_file.display())
            })?);
    }
    let app = builder.build().await?;
    let result = app.replay(events).await;
    let audit_path = app.audit_path().map(Path::to_path_buf);
    app.close().await;
    drop(app);
    let report = result?;
    finish_replay("AEGIS replay", &report, audit_path.as_deref(), format)?;
    drop(telemetry);
    Ok(())
}

/// What `monitor` prints for one bus message.
enum Seen {
    Detection(Box<Detection>),
    Incident(Box<Incident>),
}

fn print_seen(seen: &Seen, format: Format) -> anyhow::Result<()> {
    match (seen, format) {
        (Seen::Detection(detection), Format::Json) => {
            print_json_line(&json!({ "type": "detection", "detection": detection }))
        }
        (Seen::Incident(incident), Format::Json) => {
            print_json_line(&json!({ "type": "incident", "incident": incident }))
        }
        (Seen::Detection(detection), Format::Text) => {
            print(&format!("DETECTION  {}\n", detection_line(detection)))
        }
        (Seen::Incident(incident), Format::Text) => {
            let mut text = String::new();
            for (index, line) in incident_lines(incident).lines().enumerate() {
                let prefix = if index == 0 {
                    "INCIDENT   "
                } else {
                    "           "
                };
                text.push_str(prefix);
                text.push_str(line.trim_start_matches("    "));
                text.push('\n');
            }
            print(&text)
        }
    }
}

/// Prints each detection and each incident when the bus delivers it.
///
/// The function returns when `expected` holds the numbers of detections and incident
/// states of the session, and it printed that many.
async fn print_from_bus(
    mut detections: BusStream,
    mut incidents: BusStream,
    mut expected: watch::Receiver<Option<(u64, u64)>>,
    format: Format,
) -> anyhow::Result<(u64, u64)> {
    let (mut detection_count, mut incident_count) = (0_u64, 0_u64);
    loop {
        if let Some((wanted_detections, wanted_incidents)) = *expected.borrow_and_update()
            && detection_count >= wanted_detections
            && incident_count >= wanted_incidents
        {
            return Ok((detection_count, incident_count));
        }
        tokio::select! {
            item = detections.next() => {
                let message = item.ok_or_else(|| anyhow!("the bus closed the detection subscription"))??;
                let detection: Detection = message.decode()?;
                detection_count += 1;
                print_seen(&Seen::Detection(Box::new(detection)), format)?;
            }
            item = incidents.next() => {
                let message = item.ok_or_else(|| anyhow!("the bus closed the incident subscription"))??;
                let incident: Incident = message.decode()?;
                incident_count += 1;
                print_seen(&Seen::Incident(Box::new(incident)), format)?;
            }
            changed = expected.changed() => {
                changed.context("the monitoring session stopped before it gave its counts")?;
            }
        }
    }
}

/// `aegis monitor`: a monitoring-only session on an event file.
pub async fn monitor(
    events_file: &Path,
    config_file: Option<&Path>,
    format: Format,
) -> anyhow::Result<()> {
    // Fail before the session starts if the file is not readable. The source connector
    // reports a line that is not an event.
    std::fs::metadata(events_file)
        .with_context(|| format!("cannot read the event file {}", events_file.display()))?;
    let events_file = std::path::absolute(events_file)
        .with_context(|| format!("cannot use the event file path {}", events_file.display()))?;

    // The session keeps its audit log in a temporary directory. With no configuration
    // file, the starter files go there too.
    let session = tempfile::Builder::new()
        .prefix("aegis-monitor-")
        .tempdir()
        .context("cannot make a temporary directory for the monitoring session")?;
    let (config, base) = match config_file {
        Some(file) => (load(file)?, base_dir(file)?),
        None => {
            let directory = session.path().join("starter");
            starter::write(&directory)?;
            (
                Config::load(directory.join(starter::CONFIG_FILE))?,
                directory,
            )
        }
    };
    let telemetry = start_telemetry(&config)?;
    let source = FileSource::new(FileSourceConfig::new(MONITOR_SOURCE, events_file))?;
    let app = App::builder(&config)
        .base_dir(base)
        // The in-process bus, the in-memory storage, and an audit log of the session: the
        // session does not touch the systems of the configuration.
        .local_session(session.path().join("audit.jsonl"))
        // Ingestion, detection, and the Monitor agent. No component can take an action.
        .modules(ModuleSet::monitoring_only())
        .force_dry_run()
        .without_configured_sources()
        .source(Arc::new(source))
        .build()
        .await?;

    let bus = app.bus();
    let detections = bus
        .subscribe(&format!("{}.>", subject::DETECTIONS), None)
        .await?;
    let incidents = bus.subscribe(subject::INCIDENTS, None).await?;
    let (expected, expected_receiver) = watch::channel(None);
    let printer = tokio::spawn(print_from_bus(
        detections,
        incidents,
        expected_receiver,
        format,
    ));

    let options = RunOptions {
        stop_when_sources_end: true,
        services: Vec::new(),
    };
    let shutdown = Shutdown::new();
    shutdown.listen_for_signals()?;
    let result = app.run_with(shutdown, options).await;
    let summary = match result {
        Ok(summary) => summary,
        Err(error) => {
            printer.abort();
            return Err(error.into());
        }
    };
    let progress = summary.progress;
    // The printer can stop when it printed all that the session made. If the receiver is
    // gone, the printer failed, and the join below gives its error.
    let _ = expected.send(Some((progress.detections, progress.incident_updates)));
    let (printed_detections, printed_incidents) = tokio::time::timeout(DELIVERY_LIMIT, printer)
        .await
        .context("the bus did not deliver all detections and incidents in time")?
        .context("the output task stopped")??;

    let actions = app.actions().total();
    match format {
        Format::Json => print_json_line(&json!({
            "type": "summary",
            "events": progress.events_processed,
            "detections": printed_detections,
            "incident_states": printed_incidents,
            "actions": actions,
            "sources": summary.sources,
        }))?,
        Format::Text => print(&format!(
            "\nMonitoring session complete: {} events, {} detections, {} incident states. \
             Actions taken: {}.\n",
            progress.events_processed, printed_detections, printed_incidents, actions
        ))?,
    }
    drop(app);
    drop(telemetry);
    Ok(())
}

/// `aegis audit verify`: checks the hash chain of an audit log file.
pub fn audit_verify(path: &Path, format: Format) -> anyhow::Result<()> {
    let verification = FileAuditLog::verify_file(path)?;
    match format {
        Format::Json => print_json(&json!({ "path": path, "verification": verification }))?,
        Format::Text => print(&format!(
            "Audit log {}\n{}",
            path.display(),
            chain_lines(&verification)
        ))?,
    }
    if !verification.valid {
        bail!(
            "the hash chain of the audit log {} is not valid: {}",
            path.display(),
            invalid_chain(&verification)
        );
    }
    Ok(())
}

/// Reads the records of an audit log file. Does not open the log for append.
fn read_records(path: &Path) -> anyhow::Result<Vec<AuditRecord>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the audit log {}", path.display()))?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord = serde_json::from_str(line).map_err(|error| {
            anyhow!(
                "line {} of the audit log {} is not an audit record ({:?} problem at column {}). \
                 Run `aegis audit verify` to examine the file",
                index + 1,
                path.display(),
                error.classify(),
                error.column()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

/// `aegis audit show`: prints the newest records of an audit log file.
pub fn audit_show(path: &Path, limit: usize, format: Format) -> anyhow::Result<()> {
    let records = read_records(path)?;
    let total = records.len();
    let shown = &records[total.saturating_sub(limit)..];
    let verification = FileAuditLog::verify_file(path)?;
    match format {
        Format::Json => print_json(&json!({
            "path": path,
            "total": total,
            "records": shown,
            "verification": verification,
        })),
        Format::Text => {
            let mut text = format!(
                "Audit log {}: the newest {} of {} records\n",
                path.display(),
                shown.len(),
                total
            );
            for record in shown {
                text.push_str(&audit_line(record));
                text.push('\n');
            }
            text.push_str(&chain_lines(&verification));
            print(&text)
        }
    }
}

/// `aegis config check`: reports each problem of a configuration.
pub async fn config_check(config_file: &Path, format: Format) -> anyhow::Result<()> {
    let config = load(config_file)?;
    let base = base_dir(config_file)?;
    // First the problems that need no connection: all of them, not only the first one.
    let mut problems: Vec<String> = preflight(&config, &base, &[])
        .await
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut summary = serde_json::Value::Null;
    if problems.is_empty() {
        // Then the full build: it connects to the bus and to the storage, and it opens
        // the audit log. It starts no source, no detection, and no agent.
        match App::builder(&config).base_dir(&base).build().await {
            Ok(app) => {
                let app = Arc::new(app);
                // The operator API that `aegis run` would start: the check reads each
                // secret that the `[api]` section names. It opens no socket.
                #[cfg(feature = "api")]
                if app.modules().contains(Module::Api)
                    && let Err(error) =
                        aegis_app::api::OperatorApi::new(&app).and_then(|api| api.check())
                {
                    problems.push(error.to_string());
                }
                // The summary is for a configuration that has no problem.
                if problems.is_empty() {
                    let modules: Vec<&str> =
                        app.modules().iter().map(|module| module.name()).collect();
                    summary = json!({
                        "modules": modules,
                        "api": api_address(&app),
                        "bus": if app.settings().bus.kind == aegis_app::settings::BusKind::Memory {
                            "memory"
                        } else {
                            "nats"
                        },
                        "storage": app.settings().storage.kind(),
                        "model": app.has_model(),
                        "dispatcher_dry_run": app.dispatcher().dry_run(),
                        "agents_dry_run": app.settings().agents.runtime.dry_run,
                        "playbook_mode": app.settings().response.playbooks,
                        "rule_pack": app.engine().pack().manifest().name,
                        "rules": app.engine().pack().rules().len(),
                        "playbooks": app.playbooks().names(),
                        "connectors": app.action_registry().names(),
                        "sources": app.sources().names(),
                    });
                }
                app.close().await;
            }
            Err(error) => problems.push(error.to_string()),
        }
    }
    match format {
        Format::Json => print_json(&json!({
            "config": config_file,
            "valid": problems.is_empty(),
            "problems": problems,
            "summary": summary,
        }))?,
        Format::Text => {
            let mut text = String::new();
            if problems.is_empty() {
                text.push_str(&format!(
                    "The configuration {} is valid.\n",
                    config_file.display()
                ));
                if let Some(fields) = summary.as_object() {
                    for (key, value) in fields {
                        let shown = match value {
                            serde_json::Value::String(text) => text.clone(),
                            serde_json::Value::Array(items) => items
                                .iter()
                                .map(|item| {
                                    item.as_str()
                                        .map_or_else(|| item.to_string(), str::to_owned)
                                })
                                .collect::<Vec<_>>()
                                .join(", "),
                            other => other.to_string(),
                        };
                        text.push_str(&format!("  {key}: {shown}\n"));
                    }
                }
            } else {
                text.push_str(&format!(
                    "The configuration {} has {} problems:\n",
                    config_file.display(),
                    problems.len()
                ));
                for (index, problem) in problems.iter().enumerate() {
                    text.push_str(&format!("  {}. {problem}\n", index + 1));
                }
            }
            print(&text)?;
        }
    }
    if !problems.is_empty() {
        bail!(
            "the configuration {} is not valid: {}",
            config_file.display(),
            problems.join("; ")
        );
    }
    Ok(())
}
