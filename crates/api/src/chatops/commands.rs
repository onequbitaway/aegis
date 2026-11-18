//! The chat commands. Slack and Teams use the same commands and the same access rules.

use aegis_contracts::common::ApprovalId;
use aegis_contracts::incident::Incident;
use aegis_contracts::policy::{ApprovalRequest, Principal};

use crate::error::ApiError;
use crate::ops;
use crate::state::{ApiState, ApprovalDecision};

/// The maximum number of incidents and of approval requests in one chat answer.
pub(crate) const MAX_CHAT_ITEMS: usize = 10;

/// The lines of the help text. Each line is one command.
pub(crate) const HELP_LINES: [&str; 4] = [
    "incidents - show the newest incidents",
    "approvals - show the actions that wait for approval",
    "approve <id> [note] - approve one action",
    "reject <id> [note] - reject one action",
];

/// One chat command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    /// Show the commands.
    Help,
    /// Show the newest incidents.
    Incidents,
    /// Show the pending approval requests.
    Approvals,
    /// Approve or reject one approval request.
    Decide {
        /// The approval request.
        id: ApprovalId,
        /// `true` for an approval.
        approve: bool,
        /// The note of the person.
        note: Option<String>,
    },
}

/// Parses the text of a command. The error is a message for the person.
pub(crate) fn parse(text: &str) -> Result<Command, String> {
    let mut words = text.split_whitespace();
    let Some(verb) = words.next() else {
        return Ok(Command::Help);
    };
    let verb = verb.to_ascii_lowercase();
    let no_more = |command: Command, mut words: std::str::SplitWhitespace<'_>| {
        if words.next().is_some() {
            Err(format!("The command {verb} takes no parameters."))
        } else {
            Ok(command)
        }
    };
    match verb.as_str() {
        "help" => no_more(Command::Help, words),
        "incidents" => no_more(Command::Incidents, words),
        "approvals" => no_more(Command::Approvals, words),
        "approve" | "reject" => {
            let id = words
                .next()
                .ok_or_else(|| {
                    format!("Give the identifier of the approval request: {verb} <id> [note].")
                })?
                .parse::<ApprovalId>()
                .map_err(|_| {
                    "The identifier of the approval request is not a valid UUID.".to_owned()
                })?;
            let note = words.collect::<Vec<_>>().join(" ");
            Ok(Command::Decide {
                id,
                approve: verb == "approve",
                note: (!note.is_empty()).then_some(note),
            })
        }
        _ => Err("The command is not known. Send help to see the commands.".to_owned()),
    }
}

/// The answer to a chat command, before a chat format renders it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Reply {
    /// The list of commands.
    Help,
    /// The newest incidents.
    Incidents(Vec<Incident>),
    /// The pending approval requests. `total` counts all pending requests.
    Approvals {
        /// The oldest pending requests.
        items: Vec<ApprovalRequest>,
        /// The number of all pending requests.
        total: usize,
    },
    /// The result of a decision.
    Decided(Box<ApprovalDecision>),
    /// The command did not run. The text tells the person why.
    Refused(String),
}

impl Reply {
    fn refused(error: &ApiError) -> Self {
        Self::Refused(error.view().message)
    }
}

/// Runs one command for `principal`. Each command checks the permission of the principal.
pub(crate) async fn execute(state: &ApiState, principal: &Principal, command: Command) -> Reply {
    let result = match command {
        Command::Help => Ok(Reply::Help),
        Command::Incidents => ops::list_incidents(state, principal, None, MAX_CHAT_ITEMS)
            .await
            .map(|mut incidents| {
                incidents.truncate(MAX_CHAT_ITEMS);
                Reply::Incidents(incidents)
            }),
        Command::Approvals => ops::pending_approvals(state, principal)
            .await
            .map(|mut items| {
                let total = items.len();
                items.truncate(MAX_CHAT_ITEMS);
                Reply::Approvals { items, total }
            }),
        Command::Decide { id, approve, note } => {
            ops::decide_approval(state, principal, id, approve, note)
                .await
                .map(|decision| Reply::Decided(Box::new(decision)))
        }
    };
    result.unwrap_or_else(|error| {
        if error.view().status.is_server_error() {
            tracing::error!(?error, "a chat command failed");
        }
        Reply::refused(&error)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_command_parses() {
        let id = ApprovalId::new();
        assert_eq!(parse(""), Ok(Command::Help));
        assert_eq!(parse("  help "), Ok(Command::Help));
        assert_eq!(parse("Incidents"), Ok(Command::Incidents));
        assert_eq!(parse("approvals"), Ok(Command::Approvals));
        assert_eq!(
            parse(&format!("approve {id}")),
            Ok(Command::Decide {
                id,
                approve: true,
                note: None
            })
        );
        assert_eq!(
            parse(&format!(" REJECT  {id}   not   now,\tplease ")),
            Ok(Command::Decide {
                id,
                approve: false,
                note: Some("not now, please".to_owned())
            })
        );
    }

    #[test]
    fn a_command_that_is_not_valid_gives_a_message() {
        assert_eq!(
            parse("approve"),
            Err("Give the identifier of the approval request: approve <id> [note].".to_owned())
        );
        assert_eq!(
            parse("reject 42 because"),
            Err("The identifier of the approval request is not a valid UUID.".to_owned())
        );
        assert_eq!(
            parse("incidents all"),
            Err("The command incidents takes no parameters.".to_owned())
        );
        assert_eq!(
            parse("shutdown now"),
            Err("The command is not known. Send help to see the commands.".to_owned())
        );
    }

    #[test]
    fn the_help_text_names_each_command() {
        for line in HELP_LINES {
            let verb = line.split_whitespace().next().unwrap();
            let sample = match verb {
                "approve" | "reject" => format!("{verb} {}", ApprovalId::new()),
                other => other.to_owned(),
            };
            assert!(parse(&sample).is_ok(), "{line}");
        }
    }
}
