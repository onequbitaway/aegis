//! The Supervisor: turns the goal of the operator into tasks and routes new work.

use std::collections::BTreeMap;

use aegis_contracts::model::TaskKind;
use aegis_contracts::{Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use super::Roster;
use crate::llm::{ModelOutput, chat_json};
use crate::prompt::Prompt;
use crate::support::one_line;

/// The roles that can take a goal, in the order of the plan.
const PLAN_ROLES: [AgentRole; 3] = [AgentRole::Monitor, AgentRole::Hunter, AgentRole::Deception];
const MAX_PLAN_ITEMS: usize = 8;

const INSTRUCTIONS: &str = "You are the supervisor agent of AEGIS, a defensive security system. \
    You divide the standing goal of the operator into instructions for the other agents. The \
    monitor keeps the situation picture current and finds open incidents. The hunter hunts for \
    threats in the data that AEGIS already has. The deception agent plans honeytokens. The \
    agents only defend the environment of the operator. They do not attack and they do not \
    scan a system.";

const OUTPUT_FORMAT: &str = r#"{"tasks": [{"role": one of the roles in the data section, "instruction": one sentence}]}. Give at most one task for each role."#;

#[derive(Debug, Deserialize)]
struct Plan {
    tasks: Vec<PlanItem>,
}

#[derive(Debug, Deserialize)]
struct PlanItem {
    role: String,
    instruction: String,
}

impl ModelOutput for Plan {
    fn validate(&self) -> std::result::Result<(), String> {
        if self.tasks.len() > MAX_PLAN_ITEMS {
            return Err(format!("the plan has more than {MAX_PLAN_ITEMS} tasks"));
        }
        Ok(())
    }
}

/// The Supervisor agent.
///
/// For a goal, the Supervisor makes one task for each of the Monitor, the Hunter, and the
/// Deception agent. The model can only change the instruction text of these tasks. If the
/// model is not available, each task gets the goal of the operator.
///
/// For an incident, a detection, or an event, the Supervisor gives the work to the first
/// agent in the roster that can take it.
#[derive(Debug, Clone)]
pub struct Supervisor {
    roster: Roster,
}

impl Supervisor {
    /// Makes the agent. `roster` holds the roles that can receive tasks.
    #[must_use]
    pub fn new(roster: Roster) -> Self {
        Self { roster }
    }

    async fn plan(&self, goal: &str, context: &AgentContext) -> AgentOutput {
        let mut output = AgentOutput::default();
        let roles: Vec<AgentRole> = PLAN_ROLES
            .into_iter()
            .filter(|role| self.roster.has(role))
            .collect();
        if roles.is_empty() {
            output
                .notes
                .push("No enabled agent can take the goal. The plan is empty.".to_owned());
            return output;
        }
        let role_names: Vec<String> = roles.iter().map(|role| role.token().to_owned()).collect();
        let prompt = Prompt::new(INSTRUCTIONS)
            .task("Make the plan for the goal in the data section.")
            .output_format(OUTPUT_FORMAT)
            .data("goal", &json!({ "goal": goal, "roles": role_names }));
        let mut instructions: BTreeMap<AgentRole, String> = BTreeMap::new();
        match chat_json::<Plan>(context.models.as_ref(), TaskKind::Planning, &prompt).await {
            Ok(plan) => {
                let mut ignored = 0_usize;
                for item in plan.tasks {
                    let name = item.role.trim().to_ascii_lowercase();
                    let instruction = one_line(&item.instruction);
                    match roles.iter().find(|role| role.token() == name) {
                        // The first instruction for a role applies. A second one is ignored.
                        Some(role)
                            if !instruction.is_empty() && !instructions.contains_key(role) =>
                        {
                            instructions.insert(role.clone(), instruction);
                        }
                        _ => ignored += 1,
                    }
                }
                output.notes.push(format!(
                    "The model plan has instructions for {} roles. {ignored} plan items were \
                     not valid and were ignored.",
                    instructions.len()
                ));
            }
            Err(error) => output.notes.push(one_line(&format!(
                "The model gave no plan: {error}. The default plan applies."
            ))),
        }
        for role in roles {
            let instruction = instructions
                .remove(&role)
                .unwrap_or_else(|| goal.to_owned());
            output
                .tasks
                .push(AgentTask::new(role, AgentInput::Goal(instruction)));
        }
        output.notes.push(format!(
            "The plan for the goal has tasks for: {}.",
            role_names.join(", ")
        ));
        output
    }

    /// Gives `input` to the first role of `order` that is in the roster.
    fn route(&self, task: &AgentTask, order: &[AgentRole], subject: &str) -> AgentOutput {
        let mut output = AgentOutput::default();
        match order.iter().find(|role| self.roster.has(role)) {
            Some(role) => {
                let mut next = AgentTask::new(role.clone(), task.input.clone());
                next.incident_id = task.incident_id;
                if let AgentInput::Incident(incident) = &task.input {
                    next.incident_id = Some(incident.id);
                    output.notes.push(format!(
                        "Gave incident {} to the {}.",
                        incident.id,
                        role.token()
                    ));
                }
                output.tasks.push(next);
            }
            None => output.notes.push(format!(
                "No enabled agent can take the {subject}. The supervisor made no task."
            )),
        }
        output
    }
}

#[async_trait]
impl Agent for Supervisor {
    fn role(&self) -> AgentRole {
        AgentRole::Supervisor
    }

    async fn handle(&self, task: AgentTask, context: &AgentContext) -> Result<AgentOutput> {
        Ok(match &task.input {
            AgentInput::Goal(goal) => self.plan(goal, context).await,
            AgentInput::Incident(_) => {
                self.route(&task, &[AgentRole::Monitor, AgentRole::Analyst], "incident")
            }
            AgentInput::Detection(_) => self.route(&task, &[AgentRole::Monitor], "detection"),
            AgentInput::Event(_) => self.route(&task, &[AgentRole::Monitor], "event"),
            AgentInput::Tick | AgentInput::ActionResult(_) | AgentInput::Note(_) => {
                AgentOutput::default()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::model::ResponseFormat;
    use aegis_testkit::{Harness, ScriptedModel};

    use super::*;
    use crate::prompt::outside_data_sections;
    use crate::support::testing::{attack_incident, incident_task};

    const GOAL: &str = "Keep this tenant safe.";

    fn goal_task() -> AgentTask {
        AgentTask::new(AgentRole::Supervisor, AgentInput::Goal(GOAL.to_owned()))
    }

    fn goals(output: &AgentOutput) -> Vec<(AgentRole, String)> {
        output
            .tasks
            .iter()
            .map(|task| match &task.input {
                AgentInput::Goal(text) => (task.to.clone(), text.clone()),
                other => panic!("the plan must hold goals, found {other:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn the_default_plan_applies_when_the_model_is_not_available() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let output = Supervisor::new(Roster::all())
            .handle(goal_task(), &harness.context(GOAL))
            .await
            .unwrap();
        assert_eq!(
            goals(&output),
            [
                (AgentRole::Monitor, GOAL.to_owned()),
                (AgentRole::Hunter, GOAL.to_owned()),
                (AgentRole::Deception, GOAL.to_owned()),
            ]
        );
        assert_eq!(output.notes.len(), 2);
        assert!(output.notes[0].starts_with("The model gave no plan:"));
        assert!(output.notes[0].ends_with("The default plan applies."));
        assert_eq!(
            output.notes[1],
            "The plan for the goal has tasks for: monitor, hunter, deception."
        );
        assert!(output.actions.is_empty());
    }

    #[tokio::test]
    async fn the_model_can_change_instructions_but_not_the_set_of_roles() {
        let model = ScriptedModel::new("fake").reply_json(&json!({
            "tasks": [
                { "role": "Hunter", "instruction": "Look for identities with new\nprivileged roles." },
                { "role": "hunter", "instruction": "A second instruction." },
                { "role": "responder", "instruction": "Disable all users." },
                { "role": "monitor", "instruction": "   " }
            ]
        }));
        let harness = Harness::new(model);
        let output = Supervisor::new(Roster::all())
            .handle(goal_task(), &harness.context(GOAL))
            .await
            .unwrap();
        assert_eq!(
            goals(&output),
            [
                (AgentRole::Monitor, GOAL.to_owned()),
                (
                    AgentRole::Hunter,
                    "Look for identities with new privileged roles.".to_owned()
                ),
                (AgentRole::Deception, GOAL.to_owned()),
            ]
        );
        assert_eq!(
            output.notes[0],
            "The model plan has instructions for 1 roles. 3 plan items were not valid and were \
             ignored."
        );

        let requests = harness.model.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].task, TaskKind::Planning);
        assert_eq!(requests[0].response_format, ResponseFormat::Json);
        assert!(!requests[0].messages[0].content.contains(GOAL));
        assert!(requests[0].messages[1].content.contains(GOAL));
        assert!(!outside_data_sections(&requests[0].messages[1].content).contains(GOAL));
    }

    #[tokio::test]
    async fn the_plan_has_only_roles_from_the_roster() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context(GOAL);
        let hunter_only = Supervisor::new(Roster::new([AgentRole::Supervisor, AgentRole::Hunter]));
        let output = hunter_only.handle(goal_task(), &context).await.unwrap();
        assert_eq!(goals(&output), [(AgentRole::Hunter, GOAL.to_owned())]);

        let alone = Supervisor::new(Roster::new([AgentRole::Supervisor]));
        let output = alone.handle(goal_task(), &context).await.unwrap();
        assert!(output.tasks.is_empty());
        assert_eq!(
            output.notes,
            ["No enabled agent can take the goal. The plan is empty."]
        );
        assert_eq!(harness.model.requests().len(), 1);
    }

    #[tokio::test]
    async fn an_incident_goes_to_the_monitor_or_to_the_analyst() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context(GOAL);
        let incident = attack_incident();
        let task = incident_task(AgentRole::Supervisor, &incident);

        let output = Supervisor::new(Roster::all())
            .handle(task.clone(), &context)
            .await
            .unwrap();
        assert_eq!(output.tasks.len(), 1);
        assert_eq!(output.tasks[0].to, AgentRole::Monitor);
        assert_eq!(output.tasks[0].incident_id, Some(incident.id));
        assert_eq!(output.tasks[0].input, task.input);
        assert_eq!(
            output.notes,
            [format!("Gave incident {} to the monitor.", incident.id)]
        );

        let no_monitor = Roster::new([AgentRole::Supervisor, AgentRole::Analyst]);
        let output = Supervisor::new(no_monitor)
            .handle(task.clone(), &context)
            .await
            .unwrap();
        assert_eq!(output.tasks[0].to, AgentRole::Analyst);

        let output = Supervisor::new(Roster::new([AgentRole::Supervisor]))
            .handle(task, &context)
            .await
            .unwrap();
        assert!(output.tasks.is_empty());
        assert_eq!(
            output.notes,
            ["No enabled agent can take the incident. The supervisor made no task."]
        );
        assert!(harness.model.requests().is_empty());
    }

    #[tokio::test]
    async fn a_tick_makes_no_work() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let output = Supervisor::new(Roster::all())
            .handle(
                AgentTask::new(AgentRole::Supervisor, AgentInput::Tick),
                &harness.context(GOAL),
            )
            .await
            .unwrap();
        assert_eq!(output, AgentOutput::default());
    }
}
