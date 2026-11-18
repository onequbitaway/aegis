//! Checks and conversions that the provider adapters share.

use aegis_contracts::model::{ChatRequest, ToolChoice, ToolSpec};
use aegis_contracts::{Error, Result};
use serde_json::{Map, Value};

use crate::http::label;

/// The instruction that asks a model for one JSON object.
///
/// The Anthropic adapter sends it because the API has no JSON mode. The OpenAI-compatible
/// adapter sends it when no message of the request has the word "JSON".
pub(crate) const JSON_INSTRUCTION: &str =
    "Answer with one JSON object only. Do not write text before or after the JSON object.";

/// Checks the parts of a chat request that each provider needs.
pub(crate) fn check_request(request: &ChatRequest) -> Result<()> {
    if request.messages.is_empty() {
        return Err(Error::InvalidInput(
            "the chat request has no messages".to_owned(),
        ));
    }
    if request.tools.iter().any(|tool| tool.name.is_empty()) {
        return Err(Error::InvalidInput(
            "the chat request has a tool with no name".to_owned(),
        ));
    }
    match &request.tool_choice {
        ToolChoice::Auto | ToolChoice::None => Ok(()),
        ToolChoice::Required if request.tools.is_empty() => Err(Error::InvalidInput(
            "tool_choice requires a tool call, but the chat request has no tools".to_owned(),
        )),
        ToolChoice::Required => Ok(()),
        ToolChoice::Tool(name) if request.tools.iter().any(|tool| &tool.name == name) => Ok(()),
        ToolChoice::Tool(name) => Err(Error::InvalidInput(format!(
            "tool_choice names the tool {}, but the chat request does not have this tool",
            label(name)
        ))),
    }
}

/// Returns the JSON Schema of the arguments of a tool. A tool with no schema takes no arguments.
pub(crate) fn tool_schema(tool: &ToolSpec) -> Result<Value> {
    match &tool.parameters {
        Value::Null => Ok(serde_json::json!({ "type": "object", "properties": {} })),
        Value::Object(_) => Ok(tool.parameters.clone()),
        _ => Err(Error::InvalidInput(format!(
            "the parameters of tool {} are not a JSON Schema object",
            label(&tool.name)
        ))),
    }
}

/// Returns the arguments of a tool call that the caller sends back to the model.
pub(crate) fn outgoing_arguments(tool: &str, arguments: &Value) -> Result<Value> {
    match arguments {
        Value::Null => Ok(Value::Object(Map::new())),
        Value::Object(_) => Ok(arguments.clone()),
        _ => Err(Error::InvalidInput(format!(
            "the arguments of the call to tool {} are not a JSON object",
            label(tool)
        ))),
    }
}

fn not_an_object(provider: &str, tool: &str) -> Error {
    Error::Serialization(format!(
        "provider {provider} sent arguments for tool {} that are not a JSON object",
        label(tool)
    ))
}

/// Parses the arguments that a model wrote for a tool call. Empty text means no arguments.
pub(crate) fn parse_arguments(provider: &str, tool: &str, text: &str) -> Result<Value> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    match serde_json::from_str::<Value>(text) {
        Ok(value @ Value::Object(_)) => Ok(value),
        _ => Err(not_an_object(provider, tool)),
    }
}

/// Checks the arguments that a provider sent as a JSON value or as JSON text.
pub(crate) fn incoming_arguments(provider: &str, tool: &str, arguments: Value) -> Result<Value> {
    match arguments {
        Value::Null => Ok(Value::Object(Map::new())),
        Value::String(text) => parse_arguments(provider, tool, &text),
        value @ Value::Object(_) => Ok(value),
        _ => Err(not_an_object(provider, tool)),
    }
}

/// Returns the identifier of a tool call. A call with no identifier gets one from its position.
pub(crate) fn call_id(id: Option<String>, position: usize) -> String {
    id.filter(|id| !id.is_empty())
        .unwrap_or_else(|| format!("call_{position}"))
}

/// Removes a Markdown code fence that encloses the full text.
///
/// A model without a JSON mode can enclose its JSON answer in a fence.
pub(crate) fn strip_code_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(inner) = trimmed
        .strip_prefix("```")
        .and_then(|rest| rest.strip_suffix("```"))
    else {
        return text;
    };
    // The first line of a fence can name the language.
    match inner.split_once('\n') {
        Some((language, body))
            if language
                .trim()
                .chars()
                .all(|character| character.is_ascii_alphanumeric()) =>
        {
            body.trim()
        }
        _ => inner.trim(),
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::model::{Message, TaskKind};
    use serde_json::json;

    use super::*;

    fn tool(name: &str) -> ToolSpec {
        ToolSpec {
            name: name.to_owned(),
            description: "Looks up an address.".to_owned(),
            parameters: json!({ "type": "object" }),
        }
    }

    fn request(tools: Vec<ToolSpec>, tool_choice: ToolChoice) -> ChatRequest {
        ChatRequest {
            tools,
            tool_choice,
            ..ChatRequest::new(TaskKind::Triage, vec![Message::user("hello")])
        }
    }

    #[test]
    fn request_check_accepts_valid_tool_choices() {
        assert!(check_request(&request(Vec::new(), ToolChoice::Auto)).is_ok());
        assert!(check_request(&request(Vec::new(), ToolChoice::None)).is_ok());
        assert!(check_request(&request(vec![tool("lookup")], ToolChoice::Required)).is_ok());
        assert!(
            check_request(&request(
                vec![tool("lookup")],
                ToolChoice::Tool("lookup".to_owned())
            ))
            .is_ok()
        );
    }

    #[test]
    fn request_check_rejects_a_tool_choice_that_no_tool_can_satisfy() {
        let required = check_request(&request(Vec::new(), ToolChoice::Required)).unwrap_err();
        assert!(
            matches!(&required, Error::InvalidInput(text) if text.contains("has no tools")),
            "{required}"
        );
        let unknown = check_request(&request(
            vec![tool("lookup")],
            ToolChoice::Tool("isolate".to_owned()),
        ))
        .unwrap_err();
        assert!(
            matches!(&unknown, Error::InvalidInput(text) if text.contains("names the tool isolate")),
            "{unknown}"
        );
    }

    #[test]
    fn request_check_rejects_no_messages_and_a_tool_with_no_name() {
        let empty = check_request(&ChatRequest::new(TaskKind::Triage, Vec::new())).unwrap_err();
        assert!(
            matches!(&empty, Error::InvalidInput(text) if text == "the chat request has no messages"),
            "{empty}"
        );
        let unnamed = check_request(&request(vec![tool("")], ToolChoice::Auto)).unwrap_err();
        assert!(
            matches!(&unnamed, Error::InvalidInput(text) if text == "the chat request has a tool with no name"),
            "{unnamed}"
        );
    }

    #[test]
    fn tool_schema_defaults_to_an_empty_object_schema() {
        let mut spec = tool("lookup");
        assert_eq!(tool_schema(&spec).unwrap(), json!({ "type": "object" }));
        spec.parameters = Value::Null;
        assert_eq!(
            tool_schema(&spec).unwrap(),
            json!({ "type": "object", "properties": {} })
        );
        spec.parameters = json!("string");
        let invalid = tool_schema(&spec).unwrap_err();
        assert!(matches!(&invalid, Error::InvalidInput(_)), "{invalid}");
    }

    #[test]
    fn model_arguments_must_parse_to_an_object() {
        assert_eq!(
            parse_arguments("p", "lookup", r#" {"ip":"203.0.113.7"} "#).unwrap(),
            json!({ "ip": "203.0.113.7" })
        );
        assert_eq!(parse_arguments("p", "lookup", "  ").unwrap(), json!({}));
        for text in ["[1,2]", "\"text\"", "{\"ip\":", "42"] {
            let error = parse_arguments("p", "lookup", text).unwrap_err();
            assert!(
                matches!(&error, Error::Serialization(message)
                    if message == "provider p sent arguments for tool lookup that are not a JSON object"),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn incoming_arguments_accept_text_or_an_object() {
        assert_eq!(
            incoming_arguments("p", "t", json!("{\"a\":1}")).unwrap(),
            json!({ "a": 1 })
        );
        assert_eq!(
            incoming_arguments("p", "t", json!({ "a": 1 })).unwrap(),
            json!({ "a": 1 })
        );
        assert_eq!(
            incoming_arguments("p", "t", Value::Null).unwrap(),
            json!({})
        );
        let error = incoming_arguments("p", "t", json!([1])).unwrap_err();
        assert!(matches!(&error, Error::Serialization(_)), "{error}");
    }

    #[test]
    fn outgoing_arguments_must_be_an_object() {
        assert_eq!(outgoing_arguments("t", &Value::Null).unwrap(), json!({}));
        assert_eq!(
            outgoing_arguments("t", &json!({ "a": 1 })).unwrap(),
            json!({ "a": 1 })
        );
        let error = outgoing_arguments("t", &json!("text")).unwrap_err();
        assert!(matches!(&error, Error::InvalidInput(_)), "{error}");
    }

    #[test]
    fn call_id_keeps_a_real_identifier_and_makes_one_when_it_is_missing() {
        assert_eq!(call_id(Some("call_abc".to_owned()), 3), "call_abc");
        assert_eq!(call_id(Some(String::new()), 3), "call_3");
        assert_eq!(call_id(None, 0), "call_0");
    }

    #[test]
    fn code_fence_is_removed_only_when_it_encloses_the_full_text() {
        assert_eq!(strip_code_fence("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_code_fence("  ```\n{\"a\":1}\n```  "), "{\"a\":1}");
        assert_eq!(strip_code_fence("```{\"a\":1}```"), "{\"a\":1}");
        assert_eq!(strip_code_fence("{\"a\":1}"), "{\"a\":1}");
        assert_eq!(
            strip_code_fence("See ```json\n{}\n``` here"),
            "See ```json\n{}\n``` here"
        );
    }
}
