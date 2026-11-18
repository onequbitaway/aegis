//! The sharing commands: abuse reports and indicator exports.
//!
//! The commands write documents that the operator can send to other defenders. They send
//! nothing. The operator reads each document and decides if it leaves the organization,
//! to whom, and on which channel.
//!
//! The commands read the configuration, the audit log, and the evidence archive. They do
//! not build the application and they open no file of the service for a write, so they
//! are safe while the service runs.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use aegis_app::settings::Settings;
use aegis_app::sharing::{self, DocumentFile, EvidenceUsed, Tlp};
use aegis_contracts::common::IncidentId;
use anyhow::{Context as _, bail};
use serde_json::json;

use crate::Format;
use crate::commands::{base_dir, load};
use crate::output::{print, print_json};

/// The format of an indicator export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorFormat {
    /// One STIX 2.1 bundle.
    Stix,
    /// CSV text.
    Csv,
    /// An indicator file for a rule pack of the operator: the detections of decoys.
    Pack,
}

/// The sentence that each sharing command prints last.
const NOT_SENT: &str = "AEGIS sent nothing. Read each document before you send it.";

/// Reads the settings of a configuration file. The function builds no application.
fn settings(config_file: &Path) -> anyhow::Result<Settings> {
    let config = load(config_file)?;
    let base = base_dir(config_file)?;
    Ok(Settings::from_config(&config, &base, &[])?)
}

fn incident_id(text: &str) -> anyhow::Result<IncidentId> {
    text.trim()
        .parse()
        .ok()
        .context("the incident identifier is not a valid UUID")
}

/// Makes a new file and writes `content` to it. The function replaces no file. On Unix,
/// only the owner can read the file: a document holds log data.
fn write_new(path: &Path, content: &str) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        if path.exists() {
            format!(
                "the file {} exists already, and AEGIS does not replace a file",
                path.display()
            )
        } else {
            format!("cannot make the file {}", path.display())
        }
    })?;
    file.write_all(content.as_bytes())
        .and_then(|()| file.flush())
        .with_context(|| format!("cannot write the file {}", path.display()))
}

fn evidence_json(evidence: &EvidenceUsed) -> serde_json::Value {
    json!({
        "used": evidence,
        "statements": evidence.statements(),
    })
}

fn evidence_text(evidence: &EvidenceUsed) -> String {
    let mut text = String::from("Evidence that the command had:\n");
    for statement in evidence.statements() {
        text.push_str("  ");
        text.push_str(&statement);
        text.push('\n');
    }
    text
}

/// `aegis report abuse`: writes the abuse reports of one incident to a directory.
pub async fn report_abuse(
    config_file: &Path,
    incident: &str,
    out: &Path,
    format: Format,
) -> anyhow::Result<()> {
    let settings = settings(config_file)?;
    let id = incident_id(incident)?;
    let bundle = sharing::abuse_report(&settings, id, chrono::Utc::now()).await?;
    let notes = bundle.notes();
    let files = bundle.files()?;
    if files.is_empty() {
        let mut message = format!(
            "the incident {id} gives no report, and AEGIS wrote no file. A report needs an \
             attacker address that is not an address of your organization, with log records \
             in the evidence archive"
        );
        for note in &notes {
            message.push_str(". ");
            message.push_str(note.trim_end_matches('.'));
        }
        bail!(message);
    }

    // Check each path before the first write, so that the command writes all files or no
    // file.
    let targets: Vec<(PathBuf, &DocumentFile)> = files
        .iter()
        .map(|file| (out.join(&file.path), file))
        .collect();
    for (path, _) in &targets {
        if path.exists() {
            bail!(
                "the file {} exists already, and AEGIS does not replace a file. Use a new \
                 output directory",
                path.display()
            );
        }
    }
    for (path, file) in &targets {
        if let Some(directory) = path.parent() {
            std::fs::create_dir_all(directory)
                .with_context(|| format!("cannot make the directory {}", directory.display()))?;
        }
        write_new(path, &file.content)?;
    }

    let written: Vec<&Path> = targets.iter().map(|(path, _)| path.as_path()).collect();
    match format {
        Format::Json => print_json(&json!({
            "incident": id,
            "reports": bundle.package.reports.len(),
            "files": written,
            "evidence": evidence_json(&bundle.evidence),
            "notes": notes,
            "sent": false,
        })),
        Format::Text => {
            let mut text = format!(
                "Wrote {} reports for the incident {id} to {}:\n",
                bundle.package.reports.len(),
                out.display()
            );
            for path in &written {
                text.push_str(&format!("  {}\n", path.display()));
            }
            text.push('\n');
            text.push_str(&evidence_text(&bundle.evidence));
            if !notes.is_empty() {
                text.push_str("\nWhat the reports leave out (do not send these notes):\n");
                for note in &notes {
                    text.push_str(&format!("  {note}\n"));
                }
            }
            text.push_str(&format!(
                "\nEach report directory has a manifest. Check the evidence file against it:\n  \
                 shasum -a 256 <directory>/evidence.jsonl\n\n{NOT_SENT}\n"
            ));
            print(&text)
        }
    }
}

/// `aegis indicators export`: writes the indicators of the evidence archive to one file.
pub async fn indicators_export(
    config_file: &Path,
    incident: Option<&str>,
    export_format: IndicatorFormat,
    tlp: Option<Tlp>,
    out: &Path,
    format: Format,
) -> anyhow::Result<()> {
    let settings = settings(config_file)?;
    let incident = incident.map(incident_id).transpose()?;
    let tlp = match (export_format, tlp) {
        (IndicatorFormat::Stix | IndicatorFormat::Csv, None) => bail!(
            "select the TLP level of the document with --tlp white, green, amber, or red. \
             There is no default level"
        ),
        (_, tlp) => tlp,
    };
    let bundle = sharing::indicators(&settings, incident).await?;

    let (content, count, merged) = match (export_format, tlp) {
        (IndicatorFormat::Stix, Some(tlp)) => (
            bundle.stix(
                tlp,
                chrono::Utc::now(),
                sharing::IndicatorBundle::producer(&settings),
            )?,
            bundle.shared.indicators.len(),
            false,
        ),
        (IndicatorFormat::Csv, Some(tlp)) => {
            (bundle.csv(tlp), bundle.shared.indicators.len(), false)
        }
        (IndicatorFormat::Pack, _) => {
            // A pack must not have one indicator two times. An existing file keeps its
            // indicators, and the export adds the new ones.
            let existing = out.is_file().then_some(out);
            let (text, count) = bundle.pack_yaml(existing)?;
            (text, count, existing.is_some())
        }
        (IndicatorFormat::Stix | IndicatorFormat::Csv, None) => {
            bail!("select the TLP level of the document with --tlp")
        }
    };
    if count == 0 {
        let mut message = String::from(
            "the evidence gives no indicator for this format, and AEGIS wrote no file",
        );
        for line in bundle.skipped() {
            message.push_str(". ");
            message.push_str(line.trim_end_matches('.'));
        }
        if export_format == IndicatorFormat::Pack {
            message.push_str(". The format pack uses only the detections of decoys");
        }
        bail!(message);
    }

    if let Some(directory) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(directory)
            .with_context(|| format!("cannot make the directory {}", directory.display()))?;
    }
    if merged {
        // Write a new file and then put it in the place of the old file, so that the
        // pack never has a file that is not complete.
        let mut temporary = out.as_os_str().to_owned();
        temporary.push(".new");
        let temporary = PathBuf::from(temporary);
        write_new(&temporary, &content)?;
        std::fs::rename(&temporary, out)
            .with_context(|| format!("cannot replace the indicator file {}", out.display()))?;
    } else {
        write_new(out, &content)?;
    }

    let skipped = bundle.skipped();
    let format_name = match export_format {
        IndicatorFormat::Stix => "stix",
        IndicatorFormat::Csv => "csv",
        IndicatorFormat::Pack => "pack",
    };
    let marking = match (export_format, tlp) {
        (IndicatorFormat::Pack, _) => None,
        (_, tlp) => tlp.map(Tlp::label),
    };
    match format {
        Format::Json => print_json(&json!({
            "file": out,
            "format": format_name,
            "tlp": marking,
            "indicators": count,
            "merged_with_existing_file": merged,
            "evidence": evidence_json(&bundle.evidence),
            "left_out": skipped,
            "false_positive_incidents": bundle.false_positive_incidents,
            "sent": false,
        })),
        Format::Text => {
            let mut text = format!(
                "Wrote {count} indicators to {} (format {format_name}",
                out.display()
            );
            match marking {
                Some(label) => text.push_str(&format!(", {label}).\n")),
                None => text.push_str(", no TLP marking: the file is for your own rule pack).\n"),
            }
            if merged {
                text.push_str(
                    "The file existed. It keeps its indicators, and it has the new ones.\n",
                );
            }
            text.push('\n');
            text.push_str(&evidence_text(&bundle.evidence));
            if bundle.false_positive_incidents > 0 {
                text.push_str(&format!(
                    "  {} incidents have the state false_positive. Their detections give no \
                     indicator.\n",
                    bundle.false_positive_incidents
                ));
            }
            if !skipped.is_empty() && export_format != IndicatorFormat::Pack {
                text.push_str("\nWhat the export leaves out:\n");
                for line in &skipped {
                    text.push_str(&format!("  {line}\n"));
                }
            }
            if export_format == IndicatorFormat::Pack {
                text.push_str(
                    "\nExamine the file before you add it to a rule pack. A decoy shows what a \
                     client did. It does not show who the client is.\n",
                );
            }
            text.push_str(&format!("\n{NOT_SENT}\n"));
            print(&text)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn write_new_makes_a_file_and_replaces_no_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.md");
        write_new(&path, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let error = write_new(&path, "second").unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "the file {} exists already, and AEGIS does not replace a file",
                path.display()
            )
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
    }

    #[test]
    fn an_incident_identifier_is_a_uuid() {
        let id = "508657f7-d921-8cb3-add4-c2bd62528abd";
        assert_eq!(incident_id(&format!(" {id}\n")).unwrap().to_string(), id);
        let error = incident_id("the-last-one").unwrap_err().to_string();
        assert_eq!(error, "the incident identifier is not a valid UUID");
    }
}
