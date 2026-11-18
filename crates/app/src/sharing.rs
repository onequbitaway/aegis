//! Documents for other defenders: abuse reports and indicator exports.
//!
//! This module joins `aegis-share` to the data of one configuration. It reads the
//! incident, the audit log, and the evidence archive, and it returns documents. It sends
//! nothing, and it writes no file. The operator reads each document and decides if it
//! leaves the organization.
//!
//! | Function | Result |
//! | --- | --- |
//! | [`abuse_report`] | The abuse reports of one incident, and the evidence that the function had. |
//! | [`indicators`] | The indicators of the archive for STIX and CSV, and the decoy indicators for a rule pack. |
//!
//! # Where the data comes from
//!
//! | Data | Source |
//! | --- | --- |
//! | The incident | The incident store, if `storage.kind` is `postgres`. If not, the last state in the evidence archive. |
//! | The log records | The evidence archive: the events that caused a detection. |
//! | The audit records | The audit log of the configuration. The functions only read it. |
//!
//! The functions do not build the application, and they open no file for a write. Thus
//! they are safe while a service runs with the same configuration.
//!
//! # Fail closed
//!
//! - With no `operator_networks` in the `[share]` section, each function refuses. An
//!   address of the operator must not be in a document for a different organization, and
//!   only the operator knows its networks.
//! - An audit log with a chain that does not verify is not evidence. The function stops.
//! - An incident in the state `false_positive` gives no report, and its detections give
//!   no indicator.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use aegis_contracts::audit::{AuditKind, AuditRecord, ChainVerification};
use aegis_contracts::common::{DetectionId, EventId, EvidenceKind, IncidentId};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::{Detection, Error, Result};
use aegis_policy::FileAuditLog;
use aegis_share::{
    AbuseReport, AbuseReportOptions, AbuseReportPackage, HostingNetwork, IndicatorOptions,
    IndicatorSet, NetworkMap, Reporter,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::evidence::{EvidenceData, read_archive};
use crate::settings::{AuditSettings, SHARE_SECTION, Settings, StorageSettings};

/// The largest size of an audit log file that a sharing function reads: 1 GiB.
const MAX_AUDIT_BYTES: u64 = 1024 * 1024 * 1024;

/// The loopback networks. The indicator file for a rule pack never names an address in
/// them.
const LOOPBACK_NETWORKS: [&str; 2] = ["127.0.0.0/8", "::1/128"];

/// Where a sharing function found the incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSource {
    /// The incident store of the configuration.
    IncidentStore,
    /// The last state of the incident in the evidence archive.
    EvidenceArchive,
}

/// The evidence that a sharing function had. Show it to the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceUsed {
    /// Where the incident comes from. `None` for an export that uses no single incident.
    pub incident_source: Option<IncidentSource>,
    /// The files of the evidence archive that the function read, oldest first.
    pub archive_files: Vec<PathBuf>,
    /// The detections that the function used.
    pub detections: usize,
    /// The log records of the archive that the function gave to the document builder.
    pub events: usize,
    /// The events that the used detections name and that the archive does not hold. The
    /// archive keeps a limited number of events for one detection, and its size limit
    /// removes the oldest records.
    pub events_not_in_archive: usize,
    /// The detections of the incident that the archive does not hold.
    pub detections_not_in_archive: usize,
    /// The lines of the archive that are not records.
    pub invalid_archive_lines: usize,
    /// The audit records that seal a used detection.
    pub audit_records: usize,
    /// The number of records in the audit log, after the check of its chain.
    pub audit_records_checked: u64,
}

impl EvidenceUsed {
    /// Returns the evidence as sentences for the operator.
    #[must_use]
    pub fn statements(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match self.incident_source {
            Some(IncidentSource::IncidentStore) => {
                lines.push("The incident comes from the incident store.".to_owned());
            }
            Some(IncidentSource::EvidenceArchive) => lines.push(
                "The incident comes from the evidence archive: the incident store of this \
                 configuration is in the memory of the service."
                    .to_owned(),
            ),
            None => {}
        }
        if self.archive_files.is_empty() {
            lines.push(
                "The evidence archive has no file. The command had no log records.".to_owned(),
            );
        } else {
            lines.push(format!(
                "The evidence archive gave {} detections and {} log records. The archive holds \
                 only the events that caused a detection, not all events of an address.",
                self.detections, self.events
            ));
        }
        if self.events_not_in_archive > 0 {
            lines.push(format!(
                "The detections name {} events that the archive does not hold.",
                self.events_not_in_archive
            ));
        }
        if self.detections_not_in_archive > 0 {
            lines.push(format!(
                "The incident has {} detections that the archive does not hold. The size limit \
                 of the archive removed them.",
                self.detections_not_in_archive
            ));
        }
        if self.invalid_archive_lines > 0 {
            lines.push(format!(
                "The archive has {} lines that are not records. The command ignored them.",
                self.invalid_archive_lines
            ));
        }
        lines.push(format!(
            "The audit log has {} records, and its hash chain verifies. {} of them seal a \
             detection of this document.",
            self.audit_records_checked, self.audit_records
        ));
        lines
    }
}

/// The abuse reports of one incident, and the evidence behind them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbuseReportBundle {
    /// The incident of the reports.
    pub incident_id: IncidentId,
    /// The reports, and the notes of the builder for the operator. Do not send the notes.
    pub package: AbuseReportPackage,
    /// The evidence that the function had.
    pub evidence: EvidenceUsed,
}

/// The indicators of the evidence archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndicatorBundle {
    /// The indicators for a STIX bundle or a CSV file, and the values that the export
    /// left out. The list of the values that were left out is for the operator.
    pub shared: IndicatorSet,
    /// The detections of decoys, as indicators for a rule pack of the operator.
    pub decoy: Vec<aegis_detect::Indicator>,
    /// The evidence that the function had.
    pub evidence: EvidenceUsed,
    /// The incidents with the state `false_positive`. The export does not use their
    /// detections.
    pub false_positive_incidents: usize,
}

/// Refuses a sharing function if the configuration names no network of the operator.
///
/// # Errors
///
/// Returns [`Error::Config`] with the reason and the key to set.
pub fn require_operator_networks(settings: &Settings) -> Result<()> {
    if settings.share.has_operator_networks() {
        return Ok(());
    }
    Err(Error::Config(format!(
        "the section `{SHARE_SECTION}` has no `operator_networks`. A document for a different \
         organization must not name an address of your organization, and only you know your \
         networks. Add all public networks of your organization, for example: [share] \
         operator_networks = [\"198.51.100.0/24\"]. AEGIS wrote no document"
    )))
}

/// Reads the records of an audit log file. The function does not open the file for a
/// write.
fn read_audit_file(path: &Path) -> Result<Vec<AuditRecord>> {
    let unavailable = |error: std::io::Error| {
        let message = format!("cannot read the audit log {}: {error}", path.display());
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::NotFound(message)
        } else {
            Error::Unavailable(message)
        }
    };
    let size = std::fs::metadata(path).map_err(unavailable)?.len();
    if size > MAX_AUDIT_BYTES {
        return Err(Error::Unsupported(format!(
            "the audit log {} has {size} bytes. The sharing commands read a file of {MAX_AUDIT_BYTES} \
             bytes at most",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(path).map_err(unavailable)?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        // The message has no text of the line.
        let record = serde_json::from_str::<AuditRecord>(line).map_err(|error| {
            Error::Integrity(format!(
                "line {} of the audit log {} is not an audit record: {:?} problem at column {}",
                index + 1,
                path.display(),
                error.classify(),
                error.column()
            ))
        })?;
        records.push(record);
    }
    Ok(records)
}

fn invalid_chain(verification: &ChainVerification) -> Error {
    Error::Integrity(format!(
        "the hash chain of the audit log is not valid at the sequence {}: {}. A changed audit \
         log is not evidence. AEGIS wrote no document",
        verification.first_invalid_sequence.map_or_else(
            || "that is not known".to_owned(),
            |sequence| sequence.to_string()
        ),
        verification.reason.as_deref().unwrap_or("no reason given")
    ))
}

/// The data that the stores of the configuration give to a sharing function.
struct StoreData {
    /// The incident from the incident store, if the store is durable and has it.
    incident: Option<Incident>,
    /// The detection records of the audit log.
    audit: Vec<AuditRecord>,
    /// The number of records in the audit log.
    checked: u64,
}

/// Returns `true` if the record seals a detection.
fn is_detection_record(record: &AuditRecord) -> bool {
    record.kind == AuditKind::Detection
}

/// Reads the audit log and, for a durable incident store, the incident.
async fn read_stores(settings: &Settings, incident: Option<IncidentId>) -> Result<StoreData> {
    #[cfg(feature = "postgres")]
    if let StorageSettings::Postgres(config) = &settings.storage {
        use aegis_contracts::audit::AuditLog as _;
        use aegis_contracts::incident::IncidentStore as _;

        let store = aegis_storage::PgStore::connect(config)
            .await
            .map_err(|error| crate::settings::section_error("storage", error))?;
        let result = async {
            let found = match incident {
                Some(id) => store.incidents().get(id).await?,
                None => None,
            };
            let (audit, checked) = match &settings.audit {
                AuditSettings::File(file) => file_audit(file.path.clone()).await?,
                AuditSettings::Postgres => {
                    let log = store.audit();
                    let verification = log.verify().await?;
                    if !verification.valid {
                        return Err(invalid_chain(&verification));
                    }
                    let mut records = Vec::new();
                    let mut next = 1_u64;
                    loop {
                        let page = log.read(next, 1000).await?;
                        let Some(last) = page.last() else {
                            break;
                        };
                        next = last.sequence + 1;
                        records.extend(page.into_iter().filter(is_detection_record));
                    }
                    (records, verification.checked)
                }
            };
            Ok(StoreData {
                incident: found,
                audit,
                checked,
            })
        }
        .await;
        store.close().await;
        return result;
    }
    let _ = incident;
    match (&settings.storage, &settings.audit) {
        (StorageSettings::Memory, AuditSettings::File(file)) => {
            let (audit, checked) = file_audit(file.path.clone()).await?;
            Ok(StoreData {
                incident: None,
                audit,
                checked,
            })
        }
        // The settings reject the audit table of PostgreSQL with the memory storage.
        _ => Err(Error::Config(
            "the section `audit` is not valid: kind = \"postgres\" needs storage.kind = \
             \"postgres\""
                .to_owned(),
        )),
    }
}

/// Checks the chain of an audit log file and returns its detection records.
async fn file_audit(path: PathBuf) -> Result<(Vec<AuditRecord>, u64)> {
    tokio::task::spawn_blocking(move || {
        let verification = FileAuditLog::verify_file(&path)?;
        if !verification.valid {
            return Err(invalid_chain(&verification));
        }
        let records = read_audit_file(&path)?
            .into_iter()
            .filter(is_detection_record)
            .collect();
        Ok((records, verification.checked))
    })
    .await
    .map_err(|error| Error::other("read the audit log", error))?
}

/// Reads the evidence archive of the configuration. With no `[evidence]` section, the
/// archive has no records.
async fn archive(settings: &Settings) -> Result<EvidenceData> {
    let Some(evidence) = &settings.evidence else {
        return Ok(EvidenceData::default());
    };
    let path = evidence.path.clone();
    tokio::task::spawn_blocking(move || read_archive(&path))
        .await
        .map_err(|error| Error::other("read the evidence archive", error))?
}

/// Returns the audit records that seal one of `detections`.
fn sealing_records(audit: Vec<AuditRecord>, detections: &[Detection]) -> Vec<AuditRecord> {
    let wanted: HashSet<String> = detections
        .iter()
        .map(|detection| detection.id.to_string())
        .collect();
    audit
        .into_iter()
        .filter(|record| {
            record
                .evidence
                .iter()
                .any(|link| link.kind == EvidenceKind::Detection && wanted.contains(&link.id))
        })
        .collect()
}

/// Counts the events that `detections` name and that `known` does not hold.
fn missing_events(detections: &[Detection], known: &HashSet<EventId>) -> usize {
    let named: HashSet<EventId> = detections
        .iter()
        .flat_map(|detection| detection.event_ids.iter().copied())
        .collect();
    named.difference(known).count()
}

fn share_options(settings: &Settings, generated_at: DateTime<Utc>) -> AbuseReportOptions {
    let share = &settings.share;
    let mut networks = NetworkMap::new();
    for network in &share.networks {
        let mut hosting = HostingNetwork::new(network.name.trim());
        if let Some(contact) = network
            .abuse_contact
            .as_deref()
            .map(str::trim)
            .filter(|contact| !contact.is_empty())
        {
            hosting = hosting.with_abuse_contact(contact);
        }
        networks = networks.with_prefix(network.prefix, hosting);
    }
    let mut options = AbuseReportOptions::new(generated_at)
        .with_addresses(share.addresses.clone())
        .with_networks(networks);
    if let Some(reporter) = &share.reporter {
        options = options.with_reporter(Reporter {
            name: reporter.name.trim().to_owned(),
            contact: reporter
                .contact
                .as_deref()
                .map(str::trim)
                .filter(|contact| !contact.is_empty())
                .map(str::to_owned),
        });
    }
    options
}

/// Makes the abuse reports of the incident `incident_id`.
///
/// `generated_at` is the time of the reports. The function does not read the clock, so
/// the same data gives the same reports.
///
/// The package can have no report, for example if each address of the incident is an
/// address of the operator. The notes of the package then give the cause.
///
/// # Errors
///
/// - [`Error::Config`]: the `[share]` section has no `operator_networks`.
/// - [`Error::NotFound`]: the incident is not in the incident store and not in the
///   evidence archive.
/// - [`Error::InvalidInput`]: the incident has the state `false_positive`.
/// - [`Error::Integrity`]: the hash chain of the audit log does not verify.
/// - The error of a store or a file that the function cannot read.
pub async fn abuse_report(
    settings: &Settings,
    incident_id: IncidentId,
    generated_at: DateTime<Utc>,
) -> Result<AbuseReportBundle> {
    require_operator_networks(settings)?;
    let data = archive(settings).await?;
    let stores = read_stores(settings, Some(incident_id)).await?;

    let (incident, source) = match stores.incident {
        Some(incident) => (incident, IncidentSource::IncidentStore),
        None => match data.incident(incident_id) {
            Some(incident) => (incident.clone(), IncidentSource::EvidenceArchive),
            None => return Err(incident_not_found(settings, incident_id, &data)),
        },
    };
    let known: HashSet<EventId> = data.events.iter().map(|event| event.id).collect();
    let detections_not_in_archive = match source {
        IncidentSource::EvidenceArchive => data
            .missing_detections
            .get(&incident_id)
            .copied()
            .unwrap_or(0),
        IncidentSource::IncidentStore => {
            let archived: HashSet<DetectionId> = data
                .detections
                .iter()
                .map(|detection| detection.id)
                .collect();
            incident
                .detections
                .iter()
                .filter(|detection| !archived.contains(&detection.id))
                .count()
        }
    };
    let audit = sealing_records(stores.audit, &incident.detections);
    let options = share_options(settings, generated_at);
    let package = AbuseReport::build(&incident, &data.events, &audit, &options)?;
    Ok(AbuseReportBundle {
        incident_id,
        package,
        evidence: EvidenceUsed {
            incident_source: Some(source),
            archive_files: data.files.clone(),
            detections: incident.detections.len(),
            events: data.events.len(),
            events_not_in_archive: missing_events(&incident.detections, &known),
            detections_not_in_archive,
            invalid_archive_lines: data.invalid_lines,
            audit_records: audit.len(),
            audit_records_checked: stores.checked,
        },
    })
}

/// Makes the error for an incident that no source has. The message says where the
/// function looked.
fn incident_not_found(settings: &Settings, incident_id: IncidentId, data: &EvidenceData) -> Error {
    let store = match &settings.storage {
        StorageSettings::Memory => {
            "The incident store of this configuration is in the memory of the service, so a \
             command cannot read it"
        }
        #[cfg(feature = "postgres")]
        StorageSettings::Postgres(_) => "The incident store does not have the incident",
    };
    let archive = match &settings.evidence {
        None => "The configuration has no `[evidence]` section, so no evidence archive \
                 exists. Add the section before the service examines the events"
            .to_owned(),
        Some(evidence) if data.files.is_empty() => format!(
            "The evidence archive {} does not exist",
            evidence.path.display()
        ),
        Some(evidence) => format!(
            "The evidence archive {} holds {} incidents, and this incident is not one of them",
            evidence.path.display(),
            data.incidents.len()
        ),
    };
    Error::NotFound(format!(
        "the incident {incident_id} was not found. {store}. {archive}"
    ))
}

/// Collects the indicators of the evidence archive.
///
/// With `incident`, the function uses only the detections of that incident. The
/// detections of an incident with the state `false_positive` are never used.
///
/// # Errors
///
/// - [`Error::Config`]: the `[share]` section has no `operator_networks`, or an operator
///   domain is not a DNS name.
/// - [`Error::NotFound`]: `incident` is not in the evidence archive.
/// - [`Error::Integrity`]: the hash chain of the audit log does not verify.
/// - The error of a file that the function cannot read.
pub async fn indicators(
    settings: &Settings,
    incident: Option<IncidentId>,
) -> Result<IndicatorBundle> {
    require_operator_networks(settings)?;
    let data = archive(settings).await?;
    // The audit log is the proof that the detections occurred. An export from a log that
    // does not verify is refused.
    let stores = read_stores(settings, None).await?;

    let false_positive: Vec<&Incident> = data
        .incidents
        .iter()
        .filter(|state| state.status == IncidentStatus::FalsePositive)
        .collect();
    let excluded: HashSet<DetectionId> = false_positive
        .iter()
        .flat_map(|state| state.detections.iter().map(|detection| detection.id))
        .collect();
    let detections: Vec<Detection> = match incident {
        Some(id) => {
            let Some(found) = data.incident(id) else {
                return Err(incident_not_found(settings, id, &data));
            };
            if found.status == IncidentStatus::FalsePositive {
                return Err(Error::InvalidInput(format!(
                    "the state of the incident {id} is false_positive. Its detections give no \
                     indicator"
                )));
            }
            found.detections.clone()
        }
        None => data
            .detections
            .iter()
            .filter(|detection| !excluded.contains(&detection.id))
            .cloned()
            .collect(),
    };

    let share = &settings.share;
    let options = IndicatorOptions {
        addresses: share.addresses.clone(),
        operator_domains: share.operator_domains.clone(),
        include_suspicious: false,
    };
    // The export gives a value only if evidence links it to an attack. An event of an
    // incident that is a false positive is not such evidence.
    let excluded_events: HashSet<EventId> = false_positive
        .iter()
        .flat_map(|state| state.detections.iter())
        .flat_map(|detection| detection.event_ids.iter().copied())
        .collect();
    let used_events: HashSet<EventId> = detections
        .iter()
        .flat_map(|detection| detection.event_ids.iter().copied())
        .collect();
    let events: Vec<aegis_contracts::Event> = data
        .events
        .iter()
        .filter(|event| match incident {
            Some(_) => used_events.contains(&event.id),
            None => !excluded_events.contains(&event.id) || used_events.contains(&event.id),
        })
        .cloned()
        .collect();
    let shared = IndicatorSet::collect(&detections, &events, &options)
        .map_err(|error| crate::settings::section_error(SHARE_SECTION, error.into()))?;

    // The indicators for a rule pack of the operator. The networks of the operator are
    // never in the file. A loopback address is the host of the decoy itself, for example
    // in a test of the decoy. As an indicator, it would match each local client.
    let export = aegis_detect::ExportOptions {
        excluded_networks: share
            .addresses
            .operator_networks
            .iter()
            .map(ToString::to_string)
            .chain(
                LOOPBACK_NETWORKS
                    .iter()
                    .map(|network| (*network).to_owned()),
            )
            .collect(),
        ..aegis_detect::ExportOptions::default()
    };
    let decoy = aegis_detect::export_decoy_indicators(&detections, &export)
        .map_err(|error| crate::settings::section_error(SHARE_SECTION, error.into()))?;

    let known: HashSet<EventId> = data.events.iter().map(|event| event.id).collect();
    let audit = sealing_records(stores.audit, &detections);
    Ok(IndicatorBundle {
        shared,
        decoy,
        evidence: EvidenceUsed {
            incident_source: incident.map(|_| IncidentSource::EvidenceArchive),
            archive_files: data.files.clone(),
            detections: detections.len(),
            events: events.len(),
            events_not_in_archive: missing_events(&detections, &known),
            detections_not_in_archive: incident
                .and_then(|id| data.missing_detections.get(&id).copied())
                .unwrap_or(0),
            invalid_archive_lines: data.invalid_lines,
            audit_records: audit.len(),
            audit_records_checked: stores.checked,
        },
        false_positive_incidents: false_positive.len(),
    })
}

pub use aegis_share::Tlp;

/// One file of a document set: the path below the output directory, and the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentFile {
    /// The path of the file below the output directory.
    pub path: PathBuf,
    /// The text of the file.
    pub content: String,
}

/// Returns the directory name of one report. The name holds no text from a log record
/// and no text of the configuration: an address in a safe form, or a number.
fn report_directory(report: &AbuseReport, network_number: &mut usize) -> String {
    match &report.subject {
        aegis_share::ReportSubject::Address { address } => {
            // An IPv6 address has colons, which a file name must not have on each system.
            format!("address-{}", address.to_string().replace(':', "-"))
        }
        aegis_share::ReportSubject::Network { .. } => {
            *network_number += 1;
            format!("network-{network_number}")
        }
    }
}

impl AbuseReportBundle {
    /// Returns the files of all reports: one directory for each report, with `report.md`,
    /// `report.json`, `evidence.jsonl`, and `manifest.json`.
    ///
    /// The directory of an address report is `address-` and the address. The directory of
    /// a network report is `network-` and a number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if a report cannot be encoded.
    pub fn files(&self) -> Result<Vec<DocumentFile>> {
        let mut files = Vec::new();
        let mut network_number = 0_usize;
        for report in &self.package.reports {
            let directory = PathBuf::from(report_directory(report, &mut network_number));
            for file in report.files()? {
                files.push(DocumentFile {
                    path: directory.join(file.name),
                    content: file.content,
                });
            }
        }
        Ok(files)
    }

    /// Returns the notes of the report builder as sentences for the operator. A note says
    /// what the builder left out, and why. Do not send the notes.
    #[must_use]
    pub fn notes(&self) -> Vec<String> {
        use aegis_share::BuildNote;

        self.package
            .notes
            .iter()
            .map(|note| match note {
                BuildNote::AddressExcluded { address, class } => format!(
                    "No report names the address {address}: its class is {}.",
                    wire_name(class)
                ),
                BuildNote::EntityNotAnAddress { detection } => format!(
                    "The detection {detection} names an address entity that is not an IP \
                     address."
                ),
                BuildNote::DetectionNotUsed { detection, verdict } => format!(
                    "The detection {detection} was not used: its verdict is {}.",
                    wire_name(verdict)
                ),
                BuildNote::AddressWithoutRecords { address } => format!(
                    "No report names the address {address}: the evidence archive has no log \
                     record from it."
                ),
                BuildNote::DetectionWithoutEvidence { address, detection } => format!(
                    "The report for {address} has no claim for the detection {detection}: the \
                     claim has no evidence item."
                ),
                BuildNote::ActivityWithoutEvidence { address, records } => format!(
                    "The report for {address} has no claim for {records} records: the evidence \
                     limit left the claim no evidence item."
                ),
                BuildNote::EvidenceLimited {
                    address,
                    records,
                    included,
                } => format!(
                    "The address {address} has {records} records. The report holds {included} \
                     of them."
                ),
            })
            .collect()
    }
}

/// Returns the wire name of a value that serializes as one string.
fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unknown".to_owned(),
    }
}

impl IndicatorBundle {
    /// Returns the indicators as one STIX 2.1 bundle with the TLP marking `tlp`.
    ///
    /// `generated_at` is the time of the export. `producer` is the name of the
    /// organization that makes the bundle. With `None`, the bundle names no producer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if the bundle cannot be encoded.
    pub fn stix(
        &self,
        tlp: Tlp,
        generated_at: DateTime<Utc>,
        producer: Option<&str>,
    ) -> Result<String> {
        let mut options = aegis_share::StixOptions::new(tlp, generated_at);
        if let Some(producer) = producer.map(str::trim).filter(|name| !name.is_empty()) {
            options = options.with_producer(producer);
        }
        Ok(self.shared.to_stix_string(&options)?)
    }

    /// Returns the indicators as CSV text. Each row has the TLP label of `tlp`.
    #[must_use]
    pub fn csv(&self, tlp: Tlp) -> String {
        self.shared.to_csv(tlp)
    }

    /// Returns the decoy indicators as the YAML text of an indicator file for a rule
    /// pack.
    ///
    /// With `existing`, the function reads that indicator file first and adds the new
    /// indicators to its indicators. A pack must not have one indicator two times.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the existing file is not a valid indicator file, or if
    /// the indicators cannot be written as YAML.
    pub fn pack_yaml(&self, existing: Option<&Path>) -> Result<(String, usize)> {
        let all = match existing {
            Some(path) => aegis_detect::export::merge_indicators(
                aegis_detect::ioc::load_indicators(path).map_err(Error::from)?,
                self.decoy.clone(),
            ),
            None => self.decoy.clone(),
        };
        let origin = existing.and_then(Path::file_name).map_or_else(
            || "decoy.yml".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        let text = aegis_detect::ioc::indicators_to_yaml(&all, &origin).map_err(Error::from)?;
        Ok((text, all.len()))
    }

    /// Returns the values that the export left out, as one sentence for each reason. The
    /// sentences name no value.
    #[must_use]
    pub fn skipped(&self) -> Vec<String> {
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for skipped in &self.shared.skipped {
            *counts.entry(wire_name(&skipped.reason)).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(reason, count)| format!("{count} values were left out: {reason}."))
            .collect()
    }

    /// Returns the name of the producer of the configuration: the reporter of the
    /// `[share]` section.
    #[must_use]
    pub fn producer(settings: &Settings) -> Option<&str> {
        settings
            .share
            .reporter
            .as_ref()
            .map(|reporter| reporter.name.as_str())
    }
}
