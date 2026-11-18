//! Tests of the hot load of rule packs: the engine changes its rules with no restart.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;
use std::sync::Arc;

use aegis_contracts::common::{EntityKind, EventId};
use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action};
use aegis_detect::DetectError;
use aegis_detect::engine::{DetectionEngine, EngineConfig, EngineOutput};
use aegis_detect::pack::RulePack;
use chrono::DateTime;
use tempfile::TempDir;
use uuid::Uuid;

fn rule_text(id: &str, action: &str) -> String {
    format!(
        "title: Rule {id}\nid: {id}\nlevel: high\ntags:\n  - attack.t1136.003\ndetection:\n  \
         selection:\n    action: {action}\n  condition: selection\n"
    )
}

/// Writes a pack directory with the given version and rule files.
fn write_pack(version: &str, rules: &[(&str, String)]) -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("pack.yml"),
        format!(
            "name: hot-load\nversion: \"{version}\"\ndescription: A pack for the hot load tests.\n"
        ),
    )
    .unwrap();
    fs::create_dir(directory.path().join("rules")).unwrap();
    for (file, text) in rules {
        fs::write(directory.path().join("rules").join(file), text).unwrap();
    }
    directory
}

fn load(directory: &Path) -> RulePack {
    RulePack::load(directory).unwrap()
}

fn user_create(sequence: u32) -> Event {
    Event::new(
        DateTime::from_timestamp(1_793_696_400 + i64::from(sequence), 0).unwrap(),
        EventSource::new("test", "vendor", "product").with_tenant("tenant-1"),
        EventClass::AccountChange,
        action::USER_CREATE,
        Actor::new(EntityKind::User, format!("user-admin-{sequence}")),
    )
    .with_id(EventId(Uuid::from_u128(u128::from(sequence))))
    .with_outcome(Outcome::Success)
}

fn rule_ids(output: &EngineOutput) -> Vec<&str> {
    output
        .detections
        .iter()
        .map(|detection| detection.rule_id.as_str())
        .collect()
}

#[tokio::test]
async fn a_reload_with_a_new_rule_makes_the_same_event_match() {
    let first = write_pack("1", &[("role.yml", rule_text("role-rule", "role.assign"))]);
    let engine = DetectionEngine::new(EngineConfig::default(), load(first.path())).unwrap();
    assert_eq!(engine.pack().manifest().version, "1");

    // The first pack has no rule for this event.
    let event = user_create(1);
    let before = engine.process(&event).await.unwrap();
    assert_eq!(before, EngineOutput::default());

    // The second pack adds a rule for the event. The engine is the same engine.
    let second = write_pack(
        "2",
        &[
            ("role.yml", rule_text("role-rule", "role.assign")),
            ("user.yml", rule_text("user-rule", "user.create")),
        ],
    );
    let previous = engine.reload(load(second.path()));
    assert_eq!(previous.manifest().version, "1");
    assert_eq!(engine.pack().manifest().version, "2");

    let after = engine.process(&event).await.unwrap();
    assert_eq!(rule_ids(&after), ["user-rule"]);
    assert_eq!(after.detections[0].event_ids, [event.id]);
    assert_eq!(after.incidents.len(), 1);
}

#[tokio::test]
async fn a_broken_pack_is_rejected_and_the_old_rules_stay_active() {
    let good = write_pack("1", &[("user.yml", rule_text("user-rule", "user.create"))]);
    let engine = DetectionEngine::new(EngineConfig::default(), load(good.path())).unwrap();
    assert_eq!(
        rule_ids(&engine.process(&user_create(1)).await.unwrap()),
        ["user-rule"]
    );

    // One rule of the new pack is valid, and one rule has a modifier that does not exist.
    let broken = write_pack(
        "2",
        &[
            ("a_valid.yml", rule_text("other-rule", "user.create")),
            (
                "b_broken.yml",
                "title: Broken\ndetection:\n  selection:\n    action|fuzzy: user.create\n  \
                 condition: selection\n"
                    .to_owned(),
            ),
        ],
    );
    let error = engine.reload_from_dir(broken.path()).err().unwrap();
    let broken_file = broken.path().join("rules").join("b_broken.yml");
    assert!(
        matches!(
            &error,
            DetectError::Rule { file, reason }
                if *file == broken_file.display().to_string()
                    && reason.contains("the modifier \"fuzzy\", which is not supported")
        ),
        "{error}"
    );
    let contract: aegis_contracts::Error = error.into();
    assert!(
        matches!(contract, aegis_contracts::Error::Config(_)),
        "{contract}"
    );

    // No rule of the broken pack is active, and the old rule is.
    assert_eq!(engine.pack().manifest().version, "1");
    assert_eq!(
        rule_ids(&engine.process(&user_create(2)).await.unwrap()),
        ["user-rule"]
    );

    // A directory that is not a pack is also rejected.
    let empty = tempfile::tempdir().unwrap();
    let error = engine.reload_from_dir(empty.path()).err().unwrap();
    assert!(matches!(error, DetectError::Io { .. }), "{error}");
    assert_eq!(engine.pack().manifest().version, "1");
    assert_eq!(
        rule_ids(&engine.process(&user_create(3)).await.unwrap()),
        ["user-rule"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_event_sees_one_full_pack_while_reloads_occur_and_no_event_is_lost() {
    let single = write_pack("1", &[("a.yml", rule_text("single", "user.create"))]);
    let double = write_pack(
        "2",
        &[
            ("a.yml", rule_text("double-a", "user.create")),
            ("b.yml", rule_text("double-b", "user.create")),
        ],
    );
    let engine =
        Arc::new(DetectionEngine::new(EngineConfig::default(), load(single.path())).unwrap());

    // A thread changes the pack 400 times while the test examines events.
    let reloader = {
        let engine = engine.clone();
        let (single, double) = (single.path().to_owned(), double.path().to_owned());
        std::thread::spawn(move || {
            for _ in 0..200 {
                engine.reload_from_dir(&double).unwrap();
                engine.reload_from_dir(&single).unwrap();
            }
        })
    };

    let mut outputs = Vec::new();
    let mut sequence = 0_u32;
    while sequence < 2_000 || !reloader.is_finished() {
        outputs.push(engine.process(&user_create(sequence)).await.unwrap());
        sequence += 1;
    }
    reloader.join().unwrap();

    // Each event gave the detections of exactly one of the two packs.
    assert!(outputs.len() >= 2_000, "{}", outputs.len());
    for output in &outputs {
        let ids = rule_ids(output);
        assert!(
            ids == ["single"] || ids == ["double-a", "double-b"],
            "{ids:?}"
        );
    }
    // The last reload made the pack with one rule the active pack.
    let last = engine.process(&user_create(sequence)).await.unwrap();
    assert_eq!(rule_ids(&last), ["single"]);
}
