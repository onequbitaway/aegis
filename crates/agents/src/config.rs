//! The configuration of the agent runtime and of the agents.
//!
//! All structures have defaults. A configuration file gives only the values that it changes.

use std::collections::BTreeSet;
use std::time::Duration;

use aegis_contracts::{AgentRole, Error, Result};
use serde::{Deserialize, Serialize};

/// The seven roles that this crate implements, in hand-off order.
pub const BUILT_IN_ROLES: [AgentRole; 7] = [
    AgentRole::Supervisor,
    AgentRole::Monitor,
    AgentRole::Hunter,
    AgentRole::Analyst,
    AgentRole::Responder,
    AgentRole::Deception,
    AgentRole::Reporter,
];

/// The largest permitted value for a time in seconds: 365 days.
pub const MAX_SECONDS: u64 = 31_536_000;

/// The configuration of the [`AgentRuntime`](crate::AgentRuntime).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    /// With `true`, the runtime sets `dry_run` on each proposed action before dispatch.
    ///
    /// The default is `true`. A new installation changes nothing until the operator sets
    /// this value to `false`.
    pub dry_run: bool,
    /// The roles that can receive tasks. The runtime rejects a task for a different role.
    pub enabled_roles: Vec<AgentRole>,
    /// The time between two `Tick` tasks, in seconds. The value 0 stops the `Tick` tasks.
    /// The largest permitted value is [`MAX_SECONDS`].
    pub tick_interval_seconds: u64,
    /// The durable consumer name for the bus subscriptions.
    ///
    /// With a name, the runtime continues after its last message when it starts again.
    /// With `None`, the runtime gets only new messages.
    pub bus_consumer: Option<String>,
    /// The guard rails of the runtime.
    pub limits: RuntimeLimits,
    /// The configuration of the Monitor.
    pub monitor: MonitorConfig,
    /// The configuration of the Hunter.
    pub hunter: HunterConfig,
    /// The configuration of the Analyst.
    pub analyst: AnalystConfig,
    /// The configuration of the Responder.
    pub responder: ResponderConfig,
    /// The configuration of the Deception agent.
    pub deception: DeceptionConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            dry_run: true,
            enabled_roles: BUILT_IN_ROLES.to_vec(),
            tick_interval_seconds: 60,
            bus_consumer: Some("aegis-agents".to_owned()),
            limits: RuntimeLimits::default(),
            monitor: MonitorConfig::default(),
            hunter: HunterConfig::default(),
            analyst: AnalystConfig::default(),
            responder: ResponderConfig::default(),
            deception: DeceptionConfig::default(),
        }
    }
}

impl RuntimeConfig {
    /// Checks the values. A value that is not valid gives [`Error::Config`].
    pub fn validate(&self) -> Result<()> {
        let limits = &self.limits;
        let positive = [
            (
                "limits.max_steps_per_incident",
                limits.max_steps_per_incident,
            ),
            ("limits.max_task_depth", limits.max_task_depth),
            ("limits.max_concurrency", limits.max_concurrency),
            ("limits.max_queued_tasks", limits.max_queued_tasks),
            ("limits.max_actions_per_task", limits.max_actions_per_task),
            ("limits.task_timeout_seconds", limits.task_timeout_seconds),
        ];
        if let Some((name, _)) = positive.iter().find(|(_, value)| *value == 0) {
            return Err(Error::Config(format!("{name} must be larger than 0")));
        }
        let times = [
            ("tick_interval_seconds", self.tick_interval_seconds),
            ("limits.task_timeout_seconds", limits.task_timeout_seconds),
        ];
        if let Some((name, _)) = times.iter().find(|(_, value)| *value > MAX_SECONDS) {
            return Err(Error::Config(format!(
                "{name} must not be larger than {MAX_SECONDS}"
            )));
        }
        let confidence = self.analyst.false_positive_min_confidence;
        if !(0.0..=1.0).contains(&confidence) {
            return Err(Error::Config(
                "analyst.false_positive_min_confidence must be between 0 and 1".to_owned(),
            ));
        }
        if self
            .bus_consumer
            .as_deref()
            .is_some_and(|name| name.is_empty() || name.contains(['.', '*', '>', ' ']))
        {
            return Err(Error::Config(
                "bus_consumer must be one token with no '.', '*', '>', or space".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the enabled roles as a set.
    #[must_use]
    pub fn enabled(&self) -> BTreeSet<AgentRole> {
        self.enabled_roles.iter().cloned().collect()
    }

    /// Returns the time between two `Tick` tasks. `None` means that `Tick` tasks are off.
    #[must_use]
    pub fn tick_interval(&self) -> Option<Duration> {
        (self.tick_interval_seconds > 0).then(|| Duration::from_secs(self.tick_interval_seconds))
    }
}

/// The guard rails of the runtime. Each value must be larger than 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeLimits {
    /// The maximum number of tasks for one incident that one external input can cause.
    ///
    /// An external input is a task from the operator, from the bus, or from the timer. The
    /// count starts again for each external input. Tasks with no incident share one count.
    pub max_steps_per_incident: u64,
    /// The maximum length of a chain of tasks. An external input has the depth 0.
    pub max_task_depth: u64,
    /// The maximum number of tasks that run at the same time.
    pub max_concurrency: u64,
    /// The maximum number of tasks that wait in the queue.
    pub max_queued_tasks: u64,
    /// The maximum number of actions that the runtime dispatches for one task.
    pub max_actions_per_task: u64,
    /// The maximum time for one task, in seconds. The same limit applies to one answer of
    /// the dispatcher. The largest permitted value is [`MAX_SECONDS`].
    pub task_timeout_seconds: u64,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_steps_per_incident: 64,
            max_task_depth: 16,
            max_concurrency: 4,
            max_queued_tasks: 10_000,
            max_actions_per_task: 16,
            task_timeout_seconds: 120,
        }
    }
}

/// The configuration of the [`Monitor`](crate::agents::Monitor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorConfig {
    /// The maximum number of open incidents that one sweep gives to the Analyst.
    pub sweep_limit: usize,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self { sweep_limit: 50 }
    }
}

/// The configuration of the [`Hunter`](crate::agents::Hunter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HunterConfig {
    /// With `true`, a hunt request in natural language uses the model and the graph tools.
    pub model_guided: bool,
    /// The maximum number of model calls in one model-guided hunt.
    pub max_tool_steps: usize,
    /// The maximum number of graph nodes that one hunt reads for each node type.
    pub scan_limit: usize,
    /// The maximum number of new findings that one task records.
    pub max_findings: usize,
    /// The ports that make an internet-exposed asset a finding.
    ///
    /// The Hunter compares these ports with the inventory data in the graph. It does not
    /// connect to an asset.
    pub management_ports: Vec<u16>,
}

impl Default for HunterConfig {
    fn default() -> Self {
        Self {
            model_guided: true,
            max_tool_steps: 6,
            scan_limit: 500,
            max_findings: 25,
            management_ports: vec![
                22, 23, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017,
            ],
        }
    }
}

/// The configuration of the [`Analyst`](crate::agents::Analyst).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalystConfig {
    /// The minimum model confidence that can close an incident as a false positive.
    pub false_positive_min_confidence: f64,
    /// The maximum number of entities for which the Analyst reads graph context.
    pub max_context_entities: usize,
}

impl Default for AnalystConfig {
    fn default() -> Self {
        Self {
            false_positive_min_confidence: 0.8,
            max_context_entities: 20,
        }
    }
}

/// The configuration of the [`Responder`](crate::agents::Responder).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponderConfig {
    /// With `true`, the Responder asks the model which optional actions to add.
    pub refine_with_model: bool,
    /// The maximum number of actions that the Responder proposes for one task.
    pub max_actions_per_incident: usize,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            refine_with_model: true,
            max_actions_per_incident: 12,
        }
    }
}

/// The configuration of the [`Deception`](crate::agents::Deception) agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeceptionConfig {
    /// The maximum number of honeytokens that one task proposes.
    pub max_honeytokens_per_task: usize,
    /// The maximum number of graph nodes and incidents that one task reads.
    pub scan_limit: usize,
}

impl Default for DeceptionConfig {
    fn default() -> Self {
        Self {
            max_honeytokens_per_task: 3,
            scan_limit: 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_default_configuration_is_valid_and_is_a_dry_run() {
        let config = RuntimeConfig::default();
        config.validate().unwrap();
        assert!(config.dry_run);
        assert_eq!(config.enabled().len(), 7);
        assert_eq!(config.tick_interval(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn a_partial_document_keeps_the_other_defaults() {
        let config: RuntimeConfig = serde_json::from_value(json!({
            "dry_run": false,
            "enabled_roles": ["monitor", "analyst"],
            "tick_interval_seconds": 0,
            "limits": { "max_concurrency": 2 },
            "responder": { "refine_with_model": false }
        }))
        .unwrap();
        assert!(!config.dry_run);
        assert_eq!(
            config.enabled_roles,
            [AgentRole::Monitor, AgentRole::Analyst]
        );
        assert_eq!(config.tick_interval(), None);
        assert_eq!(config.limits.max_concurrency, 2);
        assert_eq!(config.limits.max_task_depth, 16);
        assert!(!config.responder.refine_with_model);
        assert_eq!(config.responder.max_actions_per_incident, 12);
        let round_trip: RuntimeConfig =
            serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
        assert_eq!(round_trip, config);
    }

    #[test]
    fn a_custom_role_is_a_map_with_its_name() {
        let config: RuntimeConfig = serde_json::from_value(json!({
            "enabled_roles": ["responder", { "custom": "triage" }],
            "bus_consumer": null
        }))
        .unwrap();
        assert_eq!(
            config.enabled_roles,
            [AgentRole::Responder, AgentRole::Custom("triage".to_owned())]
        );
        assert_eq!(config.bus_consumer, None);
        config.validate().unwrap();
        assert_eq!(config.enabled().len(), 2);
    }

    #[test]
    fn an_unknown_key_is_an_error() {
        let error = serde_json::from_value::<RuntimeConfig>(json!({ "dryrun": true })).unwrap_err();
        assert!(
            error.to_string().contains("unknown field `dryrun`"),
            "{error}"
        );
    }

    #[test]
    fn validate_names_the_value_that_is_not_valid() {
        let mut config = RuntimeConfig::default();
        config.limits.max_task_depth = 0;
        let error = config.validate().unwrap_err();
        assert!(
            matches!(&error, Error::Config(message) if message == "limits.max_task_depth must be larger than 0"),
            "{error}"
        );

        let mut config = RuntimeConfig::default();
        config.analyst.false_positive_min_confidence = 1.5;
        let error = config.validate().unwrap_err();
        assert!(
            matches!(&error, Error::Config(message) if message.starts_with("analyst.false_positive_min_confidence")),
            "{error}"
        );

        let config = RuntimeConfig {
            tick_interval_seconds: MAX_SECONDS + 1,
            ..RuntimeConfig::default()
        };
        let error = config.validate().unwrap_err();
        assert!(
            matches!(&error, Error::Config(message) if message == "tick_interval_seconds must not be larger than 31536000"),
            "{error}"
        );
        let mut config = RuntimeConfig {
            tick_interval_seconds: MAX_SECONDS,
            ..RuntimeConfig::default()
        };
        config.limits.task_timeout_seconds = MAX_SECONDS;
        config.validate().unwrap();
        config.limits.task_timeout_seconds = u64::MAX;
        let error = config.validate().unwrap_err();
        assert!(
            matches!(&error, Error::Config(message) if message == "limits.task_timeout_seconds must not be larger than 31536000"),
            "{error}"
        );

        let config = RuntimeConfig {
            bus_consumer: Some("aegis.agents".to_owned()),
            ..RuntimeConfig::default()
        };
        let error = config.validate().unwrap_err();
        assert!(
            matches!(&error, Error::Config(message) if message.starts_with("bus_consumer")),
            "{error}"
        );
    }
}
