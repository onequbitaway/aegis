//! Text from an attacker, from a model, or from an analyst in the documents.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use aegis_contracts::common::{EvidenceKind, EvidenceRef};
use aegis_contracts::event::{Event, attr};
use aegis_contracts::incident::TimelineEntry;
use aegis_contracts::{AttackTechnique, DetectionTier, Verdict};
use aegis_share::{
    AbuseReport, AddressPolicy, IndicatorOptions, IndicatorSet, SkipReason, StixOptions, Tlp,
};
use serde_json::Value;

const HOSTILE_USER_AGENT: &str = "<script>alert(1)</script>\u{1b}[31m`x` [link](http://evil.example) \n# Heading | cell \u{202e} é漢😀";

/// The user agent as a document shows it: each unsafe character is visible text.
const SHOWN_USER_AGENT: &str = "<script>alert(1)</script>{U+001B}[31m`x` [link](http://evil.example) {U+000A}# Heading | cell {U+202E} é漢😀";

fn hostile_event() -> Event {
    let mut event = support::sign_in_from(1, 600, "203.0.113.50", HOSTILE_USER_AGENT)
        .with_attribute(
            attr::HTTP_PATH,
            "/a/<img src=x onerror=alert(1)>/```\n\n## Injected",
        )
        .with_attribute(
            attr::FAILURE_REASON,
            "</pre><h1>Injected</h1> ![image](http://evil.example/x.png) \u{0}\u{7f}\u{2028}",
        )
        .with_attribute(attr::CLIENT_FINGERPRINT, "fp`|\r\n<b>");
    event.action = "sign_in\n\n# Injected action".to_owned();
    event
}

fn hostile_report() -> AbuseReport {
    let event = hostile_event();
    let detection = support::detection(1, Verdict::Malicious, 600, &[&event], Vec::new());
    let incident = support::incident(vec![detection]);
    let mut package = AbuseReport::build(&incident, &[event], &[], &support::options()).unwrap();
    assert_eq!(package.reports.len(), 1);
    package.reports.remove(0)
}

#[test]
fn markup_and_control_characters_from_an_event_have_no_effect_in_markdown() {
    let markdown = hostile_report().to_markdown();

    // No control character and no invisible character, only the line feeds of the writer.
    for character in markdown.chars() {
        assert!(
            character == '\n' || !character.is_control(),
            "control character {:?}",
            character
        );
        assert!(
            !matches!(character, '\u{202e}' | '\u{2028}' | '\u{200b}'),
            "invisible character {:?}",
            character
        );
    }
    assert!(!markdown.contains(HOSTILE_USER_AGENT));

    // The untrusted text is only in code spans and in code blocks.
    let outside = support::outside_code(&markdown);
    for markup in [
        "<script>",
        "</script>",
        "[link]",
        "(http://evil.example)",
        "evil.example",
        "<img",
        "onerror",
        "<h1>",
        "</pre>",
        "![image]",
        "Injected",
        "Heading",
        "<b>",
    ] {
        assert!(
            !outside.contains(markup),
            "{markup:?} is outside code in:\n{outside}"
        );
    }
    // The headings of the document are the headings of the writer.
    let headings: Vec<&str> = markdown
        .lines()
        .filter(|line| line.starts_with('#'))
        .collect();
    assert_eq!(
        headings,
        [
            "# Abuse report: activity from 203.0.113.50",
            "## Summary",
            "## What occurred",
            "### Address 203.0.113.50",
            "#### C1. Log record with an action that has no plain name that failed",
            "#### C2. Detection: activity classified as malicious",
            "## Addresses and ports",
            "## User agents and client fingerprints",
            "## ATT&CK techniques",
            "## Evidence and integrity",
        ]
    );

    // The values are shown as they are, in code spans with a fence that they cannot close.
    assert!(
        markdown.contains(&format!(
            "- 203.0.113.50, User agent: ``{SHOWN_USER_AGENT}`` (1 record)\n"
        )),
        "{markdown}"
    );
    assert!(
        markdown.contains(
            "- 203.0.113.50, Client fingerprint: ``fp`|{U+000D}{U+000A}<b>`` (1 record)\n"
        ),
        "{markdown}"
    );
    assert!(
        markdown.contains("- Action name: `sign_in{U+000A}{U+000A}# Injected action`\n"),
        "{markdown}"
    );
    // In a code block, the markup characters are JSON escapes.
    assert!(markdown.contains("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"));
    assert!(markdown.contains("\\u003cimg src=x onerror=alert(1)\\u003e/\\u0060\\u0060\\u0060"));
}

#[test]
fn markup_and_control_characters_from_an_event_are_escaped_in_json() {
    let report = hostile_report();
    let text = report.to_json_string().unwrap();

    // The text is printable ASCII, with no character that starts markup.
    for byte in text.bytes() {
        assert!(
            byte == b'\n' || (0x20..0x7f).contains(&byte),
            "byte {byte:#x} in the JSON text"
        );
        assert!(!matches!(byte, b'<' | b'>' | b'&' | b'`'), "byte {byte:#x}");
    }
    assert!(text.contains("\\u003cscript\\u003e"));
    // A character that is not ASCII is an escape. An emoji is a surrogate pair.
    assert!(text.contains("{U+202E} \\u00e9\\u6f22\\ud83d\\ude00"));

    // A parser returns the values, with each unsafe character as visible text.
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value, report.to_json().unwrap());
    assert_eq!(
        value["addresses"][0]["user_agents"][0]["value"],
        SHOWN_USER_AGENT
    );
    let item: Value =
        serde_json::from_str(value["evidence"][0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(item["user_agent"], SHOWN_USER_AGENT);
    assert_eq!(item["action"], "sign_in{U+000A}{U+000A}# Injected action");
    assert_eq!(
        item["attributes"]["http_path"],
        "/a/<img src=x onerror=alert(1)>/```{U+000A}{U+000A}#[fragment removed]"
    );
    assert_eq!(
        item["attributes"]["failure_reason"],
        "</pre><h1>Injected</h1> ![image](http://evil.example/x.png) {U+0000}{U+007F}{U+2028}"
    );
    assert_eq!(
        item["attributes"]["client_fingerprint"],
        "fp`|{U+000D}{U+000A}<b>"
    );

    // Each evidence item is one line of printable ASCII.
    let file = report.evidence_jsonl();
    assert_eq!(file.lines().count(), report.evidence.len());
    assert_eq!(report.evidence.len(), 1);
    assert!(
        file.bytes()
            .all(|byte| byte == b'\n' || (0x20..0x7f).contains(&byte))
    );
    report.manifest.verify_file(&file).unwrap();
}

#[test]
fn a_long_value_from_an_event_is_cut() {
    let event = support::sign_in_from(1, 600, "203.0.113.50", &"A".repeat(5000))
        .with_attribute(attr::FAILURE_REASON, "b ".repeat(4000));
    let detection = support::detection(1, Verdict::Malicious, 600, &[&event], Vec::new());
    let incident = support::incident(vec![detection]);
    let package = AbuseReport::build(&incident, &[event], &[], &support::options()).unwrap();
    let item: Value = serde_json::from_str(&package.reports[0].evidence[0].content).unwrap();
    assert_eq!(
        item["user_agent"].as_str().unwrap(),
        format!("{}...[cut]", "A".repeat(256))
    );
    let reason = item["attributes"]["failure_reason"].as_str().unwrap();
    assert_eq!(reason.chars().count(), 512 + "...[cut]".len());
    assert!(reason.ends_with("b ...[cut]"));
}

#[test]
fn a_report_copies_no_text_that_can_name_a_person_or_a_group() {
    let event = support::sign_in_from(1, 600, "203.0.113.50", "curl/8.4.0");
    let mut rule = support::detection(1, Verdict::Malicious, 600, &[&event], Vec::new());
    rule.title = "APT29 password spray".to_owned();
    rule.description = "The group Fancy Bear did this. The operator is John Smith.".to_owned();
    rule.rule_id = "threat-actor.apt29.spray".to_owned();
    rule.attributes
        .insert("actor".to_owned(), Value::String("APT29".to_owned()));
    // A model wrote this detection. Its technique name states an attribution.
    let mut model = support::detection(2, Verdict::Malicious, 601, &[&event], Vec::new());
    model.tier = DetectionTier::Llm;
    model.title = "Activity of Lazarus Group".to_owned();
    model.attack = vec![
        AttackTechnique::new("initial-access", "T1078", "Valid Accounts used by APT29"),
        AttackTechnique::new("the tactic of John Smith", "T9999 by APT29", "Text"),
    ];
    let mut incident = support::incident(vec![rule, model]);
    incident.title = "APT29 campaign by John Smith".to_owned();
    incident.summary = "We attribute this attack to Fancy Bear with high confidence.".to_owned();
    incident.timeline = vec![TimelineEntry {
        time: support::at(700),
        author: "analyst John Smith".to_owned(),
        description: "The attacker is Lazarus Group.".to_owned(),
        evidence: vec![EvidenceRef::new(EvidenceKind::Event, event.id).with_note("by APT29")],
    }];
    // The texts are in the input.
    assert!(incident.title.contains("APT29"));
    assert!(incident.detections[1].attack[0].name.contains("APT29"));

    let package = AbuseReport::build(&incident, &[event], &[], &support::options()).unwrap();
    assert_eq!(package.reports.len(), 1);
    let report = &package.reports[0];
    for file in report.files().unwrap() {
        let lower = file.content.to_lowercase();
        for name in [
            "apt29",
            "fancy bear",
            "john smith",
            "lazarus",
            "attribute",
            "threat-actor",
            "campaign",
            "confidence",
            "analyst",
        ] {
            assert!(!lower.contains(name), "{name:?} is in {}", file.name);
        }
    }

    // The techniques stay, as checked identifiers. The name of the model does not.
    assert_eq!(report.techniques.len(), 2);
    assert_eq!(report.techniques[0].id, "T1078");
    assert_eq!(report.techniques[0].name, None);
    assert_eq!(report.techniques[0].tactics, ["initial-access"]);
    assert_eq!(report.techniques[1].id, "T1110.003");
    assert_eq!(
        report.techniques[1].name.as_deref(),
        Some("Password Spraying")
    );
    // Each report says that it does not identify a person or a group.
    assert_eq!(
        report.notice,
        "This report gives log data of the reporter. It does not identify a person or a group."
    );
    assert!(report.to_markdown().contains(&report.notice));
    assert_eq!(report.to_json().unwrap()["notice"], report.notice.as_str());
}

#[test]
fn an_internal_name_in_text_that_stays_is_masked() {
    // The failure reason and the operation stay by default. Here they name the user, the
    // tenant, and an application of the operator.
    let event = support::sign_in_from(
        1,
        600,
        "203.0.113.50",
        "curl/8.4.0 (for ERIN@contoso.example)",
    )
    .with_attribute(
        attr::FAILURE_REASON,
        "The account erin@contoso.example in tenant-contoso is locked. User-Erin must wait.",
    )
    .with_attribute(
        attr::OPERATION,
        "GET /tenants/tenant-contoso/apps/app-payroll",
    )
    .with_attribute(attr::APP_ID, "app-payroll")
    .with_attribute(attr::HTTP_PATH, "/u/user-erin/login");
    let detection = support::detection(1, Verdict::Malicious, 600, &[&event], Vec::new());
    let incident = support::incident(vec![detection]);
    let package = AbuseReport::build(&incident, &[event], &[], &support::options()).unwrap();
    let report = &package.reports[0];
    let item: Value = serde_json::from_str(&report.evidence[0].content).unwrap();
    assert_eq!(item["user_agent"], "curl/8.4.0 (for [masked])");
    assert_eq!(
        item["attributes"],
        serde_json::json!({
            "failure_reason": "The account [masked] in [masked] is locked. [masked] must wait.",
            "http_path": "/u/[masked]/login",
            "operation": "GET /tenants/[masked]/apps/[masked]",
        })
    );
    assert_eq!(
        report.addresses[0].user_agents[0].value,
        "curl/8.4.0 (for [masked])"
    );
    for file in report.files().unwrap() {
        let lower = file.content.to_lowercase();
        for name in ["erin", "contoso", "payroll", "idp-prod"] {
            assert!(!lower.contains(name), "{name:?} is in {}", file.name);
        }
    }
}

#[test]
fn secrets_in_event_text_are_in_no_output() {
    let key = "sk-proj-0123456789abcdefghijklmnopqrstuv";
    let event = support::sign_in_from(1, 600, "203.0.113.50", &format!("agent/1.0 key={key}"))
        .with_attribute(
            attr::HTTP_PATH,
            "/v1/chat/completions?api_key=hunter2hunter2",
        )
        .with_attribute(
            attr::FAILURE_REASON,
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl refused",
        )
        .with_attribute(attr::OPERATION, "POST password=Tr0ub4dor&3 for 10.9.8.7")
        // The original record and an attribute that is not on the allow list.
        .with_attribute("request_body", "the prompt with secret-prompt-text")
        .with_raw(serde_json::json!({"authorization": "Bearer raw-secret-value-123456"}));
    let detection = support::detection(1, Verdict::Malicious, 600, &[&event], Vec::new());
    let incident = support::incident(vec![detection.clone()]);
    let events = [event];
    let package = AbuseReport::build(&incident, &events, &[], &support::options()).unwrap();
    let report = &package.reports[0];
    let item: Value = serde_json::from_str(&report.evidence[0].content).unwrap();
    assert_eq!(item["user_agent"], "agent/1.0 key=[secret removed]");
    assert_eq!(
        item["attributes"],
        serde_json::json!({
            "failure_reason": "Authorization: Bearer [secret removed] refused",
            "http_path": "/v1/chat/completions?[query removed]",
            "operation": "POST password=[secret removed]&3 for [address removed]",
        })
    );
    for file in report.files().unwrap() {
        for secret in [
            key,
            "hunter2",
            "eyJhbGciOiJIUzI1NiJ9",
            "Tr0ub4dor",
            "secret-prompt-text",
            "raw-secret-value",
            "request_body",
            "10.9.8.7",
        ] {
            assert!(
                !file.content.contains(secret),
                "{secret:?} is in {}",
                file.name
            );
        }
    }

    // The user agent holds a key, so it does not become an indicator. The note for the
    // operator does not hold the key.
    let options =
        IndicatorOptions::new().with_addresses(AddressPolicy::new().with_documentation_ranges());
    let set = IndicatorSet::collect(&[detection], &events, &options).unwrap();
    let values: Vec<&str> = set
        .indicators
        .iter()
        .map(|indicator| indicator.value.as_str())
        .collect();
    assert_eq!(values, ["203.0.113.50"]);
    assert_eq!(set.skipped.len(), 1);
    assert_eq!(set.skipped[0].reason, SkipReason::HoldsSecret);
    assert_eq!(set.skipped[0].value, "agent/1.0 key=[secret removed]");
    let stix = set
        .to_stix_string(&StixOptions::new(Tlp::Amber, support::report_time()))
        .unwrap();
    assert!(!stix.contains(key));
    assert!(!set.to_csv(Tlp::Amber).contains(key));
}

#[test]
fn a_user_agent_with_markup_is_escaped_in_the_stix_text_and_one_with_control_characters_is_left_out()
 {
    let markup = "Mozilla/5.0 <script>alert('x')</script> & \\o/ `tick`";
    let with_markup = support::sign_in_from(1, 600, "93.184.216.34", markup);
    let with_control = support::sign_in_from(2, 601, "93.184.216.35", "bad\r\nX-Injected: 1");
    let with_hidden = support::sign_in_from(3, 602, "93.184.216.36", "hidden\u{202e}text");
    let events = [with_markup, with_control, with_hidden];
    let detection = support::detection(
        1,
        Verdict::Malicious,
        602,
        &events.iter().collect::<Vec<_>>(),
        Vec::new(),
    );
    let set = IndicatorSet::collect(&[detection], &events, &IndicatorOptions::new()).unwrap();
    let user_agents: Vec<&str> = set
        .of_kind(aegis_share::IndicatorKind::UserAgent)
        .map(|indicator| indicator.value.as_str())
        .collect();
    assert_eq!(user_agents, [markup]);
    let reasons: Vec<(&str, SkipReason)> = set
        .skipped
        .iter()
        .map(|skipped| (skipped.value.as_str(), skipped.reason))
        .collect();
    assert_eq!(
        reasons,
        [
            (
                "bad{U+000D}{U+000A}X-Injected: 1",
                SkipReason::UnsafeCharacters
            ),
            ("hidden{U+202E}text", SkipReason::UnsafeCharacters),
        ]
    );

    let text = set
        .to_stix_string(&StixOptions::new(Tlp::Green, support::report_time()))
        .unwrap();
    for byte in text.bytes() {
        assert!(byte == b'\n' || (0x20..0x7f).contains(&byte), "{byte:#x}");
        assert!(!matches!(byte, b'<' | b'>' | b'&' | b'`'), "{byte:#x}");
    }
    let bundle: Value = serde_json::from_str(&text).unwrap();
    let indicator = bundle["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| {
            object["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("User agent"))
        })
        .unwrap();
    assert_eq!(indicator["name"], format!("User agent {markup}"));
    assert_eq!(
        indicator["pattern"],
        "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = \
         'Mozilla/5.0 <script>alert(\\'x\\')</script> & \\\\o/ `tick`']"
    );
}
