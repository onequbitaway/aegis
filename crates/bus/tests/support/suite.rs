//! The test cases that describe the rules of `MessageBus`.
//!
//! Each case is generic over the bus. The test binaries run the cases for the in-process
//! bus and for the NATS bus.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_contracts::Event;
use aegis_contracts::bus::{BusMessage, publish_json};
use aegis_testkit::fixtures;
use futures::{StreamExt, stream};

use super::{Case, WAIT, invalid_input, next, next_text, take_texts, text};

pub async fn a_durable_subscription_gets_a_stored_message(case: &Case) {
    case.publish("events.file", "hello").await;
    let mut stream = case.subscribe("events.>", Some("reader")).await;
    let message = next(&mut stream).await;
    assert_eq!(
        message,
        BusMessage {
            subject: case.subject("events.file"),
            payload: b"hello".to_vec(),
        }
    );
}

pub async fn an_ephemeral_subscription_gets_only_new_messages(case: &Case) {
    case.publish("events.file", "old").await;
    let mut stream = case.subscribe("events.*", None).await;
    case.publish("detections.deterministic", "other subject")
        .await;
    case.publish("events.entra", "new").await;
    case.publish("events.file", "end").await;

    let first = next(&mut stream).await;
    assert_eq!(first.subject, case.subject("events.entra"));
    assert_eq!(first.payload, b"new");
    // The end marker comes directly after it. Thus, the bus sent no other message.
    let second = next(&mut stream).await;
    assert_eq!(second.subject, case.subject("events.file"));
    assert_eq!(second.payload, b"end");
}

pub async fn each_ephemeral_subscription_gets_each_new_message(case: &Case) {
    let mut left = case.subscribe("events.>", None).await;
    let mut right = case.subscribe("events.>", None).await;
    for payload in ["1", "2", "3"] {
        case.publish("events.file", payload).await;
    }
    assert_eq!(take_texts(&mut left, 3).await, ["1", "2", "3"]);
    assert_eq!(take_texts(&mut right, 3).await, ["1", "2", "3"]);
}

pub async fn a_new_durable_name_starts_at_the_first_stored_message(case: &Case) {
    for payload in ["1", "2", "3"] {
        case.publish("events.file", payload).await;
    }
    let mut detect = case.subscribe("events.>", Some("detect")).await;
    assert_eq!(take_texts(&mut detect, 3).await, ["1", "2", "3"]);

    // A second name has its own position. It also starts at the first message.
    let mut archive = case.subscribe("events.>", Some("archive")).await;
    assert_eq!(take_texts(&mut archive, 3).await, ["1", "2", "3"]);
}

pub async fn a_durable_consumer_continues_after_a_restart(case: &Case) {
    for payload in ["1", "2", "3"] {
        case.publish("events.file", payload).await;
    }
    let mut first = case.subscribe("events.>", Some("detect")).await;
    assert_eq!(next_text(&mut first).await, "1");
    // This poll acknowledges message 1.
    assert_eq!(next_text(&mut first).await, "2");
    // The consumer goes away before it polls again. Message 2 has no acknowledgement.
    drop(first);

    let mut resumed = case.subscribe("events.>", Some("detect")).await;
    let expected: &[&str] = if case.redelivers_unacknowledged {
        &["2", "3"]
    } else {
        &["3"]
    };
    let mut received = take_texts(&mut resumed, expected.len()).await;
    received.sort();
    assert_eq!(received, expected);

    // The end marker comes directly after them. Thus, the bus did not send message 1 again.
    case.publish("events.file", "end").await;
    assert_eq!(next_text(&mut resumed).await, "end");
}

pub async fn consumers_with_one_durable_name_share_the_messages(case: &Case) {
    const COUNT: usize = 20;
    let left = case.subscribe("events.>", Some("workers")).await;
    let right = case.subscribe("events.>", Some("workers")).await;
    let mut merged = stream::select(
        left.map(|item| ("left", item)),
        right.map(|item| ("right", item)),
    );

    let publish = async {
        for number in 0..COUNT {
            case.publish("events.file", &format!("{number:02}")).await;
        }
    };
    let collect = async {
        let mut received = Vec::new();
        while received.len() < COUNT {
            let (side, item) = tokio::time::timeout(WAIT, merged.next())
                .await
                .expect("the bus must deliver a message in time")
                .expect("the streams must stay open");
            received.push((side, text(&item.expect("the item must be a message"))));
        }
        received
    };
    let ((), received) = tokio::join!(publish, collect);

    // Each message arrived one time. No message went to the two consumers.
    let mut payloads: Vec<&str> = received.iter().map(|(_, text)| text.as_str()).collect();
    payloads.sort_unstable();
    let expected: Vec<String> = (0..COUNT).map(|number| format!("{number:02}")).collect();
    assert_eq!(payloads, expected);

    let left_count = received.iter().filter(|(side, _)| *side == "left").count();
    assert!(
        left_count > 0 && left_count < COUNT,
        "the two consumers must each get messages, but the left consumer got {left_count} of {COUNT}"
    );

    // The end marker comes directly after them. Thus, the bus sent no late duplicate.
    case.publish("events.file", "end").await;
    let (_, item) = tokio::time::timeout(WAIT, merged.next())
        .await
        .expect("the bus must deliver the end marker in time")
        .expect("the streams must stay open");
    assert_eq!(text(&item.expect("the item must be a message")), "end");
}

pub async fn wildcards_select_the_correct_subjects(case: &Case) {
    let mut one_token = case.subscribe("events.*", None).await;
    let mut all_tokens = case.subscribe("events.>", None).await;
    let mut middle = case.subscribe("*.entra", None).await;
    let mut exact = case.subscribe("audit", None).await;
    let mut first_token = case
        .bus
        .subscribe("*.audit", None)
        .await
        .expect("the subscription must start");
    let mut everything = case.subscribe(">", None).await;

    case.publish("events.file", "a").await;
    case.publish("events.entra.signin", "b").await;
    case.publish("detections.deterministic", "c").await;
    case.publish("audit", "d").await;
    case.publish("events.entra", "e").await;
    case.publish("detections.entra", "f").await;

    // After each check, one more message that matches the pattern must come next. Thus,
    // the bus sent no message that is not in the expected list.
    assert_eq!(take_texts(&mut exact, 1).await, ["d"]);
    case.publish("audit", "g").await;
    assert_eq!(next_text(&mut exact).await, "g");

    assert_eq!(take_texts(&mut first_token, 2).await, ["d", "g"]);
    case.publish("audit", "h").await;
    assert_eq!(next_text(&mut first_token).await, "h");

    // `*` matches one token. It does not match `events.entra.signin`.
    assert_eq!(take_texts(&mut one_token, 2).await, ["a", "e"]);
    case.publish("events.last", "i").await;
    assert_eq!(next_text(&mut one_token).await, "i");

    // `>` matches one token or more.
    assert_eq!(take_texts(&mut all_tokens, 4).await, ["a", "b", "e", "i"]);
    case.publish("events.last.deep", "j").await;
    assert_eq!(next_text(&mut all_tokens).await, "j");

    assert_eq!(take_texts(&mut middle, 2).await, ["e", "f"]);
    case.publish("other.entra", "k").await;
    assert_eq!(next_text(&mut middle).await, "k");

    assert_eq!(
        take_texts(&mut everything, 11).await,
        ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]
    );
}

pub async fn publish_rejects_a_subject_that_is_not_concrete(case: &Case) {
    let subjects = [
        String::new(),
        case.subject("*"),
        case.subject(">"),
        case.subject("events.*"),
        case.subject(".events"),
        case.subject("events."),
        format!(".{}", case.root),
    ];
    for subject in subjects {
        let result = case.bus.publish(&subject, b"rejected".to_vec()).await;
        let message = invalid_input(result);
        assert!(!message.is_empty(), "{subject:?}");
    }
    let message = invalid_input(case.bus.subscribe("", None).await.map(|_| ()));
    assert!(!message.is_empty());

    // A new durable name starts at the first stored message. Thus, the bus stored none of
    // the rejected messages.
    case.publish("events.file", "accepted").await;
    let mut stream = case.subscribe(">", Some("reader")).await;
    assert_eq!(next_text(&mut stream).await, "accepted");
}

pub async fn a_typed_event_makes_a_round_trip(case: &Case) {
    let events = fixtures::artex_style_attack();
    let event = events
        .iter()
        .find(|event| event.target.is_some() && !event.attributes.is_empty())
        .expect("the attack log must have an event with a target and attributes");
    // `aegis.events.{connector}` when the root is `aegis`.
    let subject = format!("{}.{}", case.subject("events"), event.source.connector);
    publish_json(case.bus.as_ref(), &subject, event)
        .await
        .expect("the publish must succeed");

    let mut stream = case.subscribe("events.*", Some("detect")).await;
    let message = next(&mut stream).await;
    assert_eq!(message.subject, subject);
    let decoded: Event = message.decode().expect("the payload must be an event");
    assert_eq!(&decoded, event);
}

pub async fn the_attack_log_arrives_complete_and_in_sequence(case: &Case) {
    let events = fixtures::artex_style_attack();
    assert_eq!(events.len(), fixtures::ATTACK_LOG_EVENTS);
    let mut live = case.subscribe("events.>", None).await;
    for event in &events {
        let subject = format!("{}.{}", case.subject("events"), event.source.connector);
        publish_json(case.bus.as_ref(), &subject, event)
            .await
            .expect("the publish must succeed");
    }
    let mut stored = case.subscribe("events.>", Some("detect")).await;
    for stream in [&mut live, &mut stored] {
        let mut received = Vec::with_capacity(events.len());
        for _ in 0..events.len() {
            let event: Event = next(stream).await.decode().expect("an event");
            received.push(event.id);
        }
        let expected: Vec<_> = events.iter().map(|event| event.id).collect();
        assert_eq!(received, expected);
    }
}

pub async fn concurrent_publishers_lose_no_message(case: &Case) {
    const PUBLISHERS: usize = 8;
    const MESSAGES: usize = 25;
    let publishers = (0..PUBLISHERS).map(|publisher| async move {
        for number in 0..MESSAGES {
            case.publish("events.file", &format!("{publisher}-{number:02}"))
                .await;
        }
    });
    futures::future::join_all(publishers).await;

    let mut stream = case.subscribe("events.>", Some("reader")).await;
    let received = take_texts(&mut stream, PUBLISHERS * MESSAGES).await;
    // The messages of one publisher keep their sequence.
    for publisher in 0..PUBLISHERS {
        let prefix = format!("{publisher}-");
        let of_publisher: Vec<&String> = received
            .iter()
            .filter(|text| text.starts_with(&prefix))
            .collect();
        let expected: Vec<String> = (0..MESSAGES)
            .map(|number| format!("{publisher}-{number:02}"))
            .collect();
        assert_eq!(of_publisher, expected.iter().collect::<Vec<_>>());
    }
}

pub async fn a_waiting_subscriber_wakes_when_a_message_arrives(case: &Case) {
    let mut ephemeral = case.subscribe("audit", None).await;
    let mut durable = case.subscribe("audit", Some("archive")).await;
    let waiting = async {
        let from_ephemeral = next_text(&mut ephemeral).await;
        let from_durable = next_text(&mut durable).await;
        (from_ephemeral, from_durable)
    };
    let publish = async {
        // Let the subscribers start to wait before the message arrives.
        tokio::task::yield_now().await;
        case.publish("audit", "record").await;
    };
    let ((from_ephemeral, from_durable), ()) = tokio::join!(waiting, publish);
    assert_eq!(from_ephemeral, "record");
    assert_eq!(from_durable, "record");
}

pub async fn a_message_with_no_acknowledgement_goes_to_a_different_consumer(case: &Case) {
    case.publish("events.file", "1").await;
    let mut holder = case.subscribe("events.>", Some("workers")).await;
    assert_eq!(next_text(&mut holder).await, "1");

    // A second consumer waits. The bus has no other message for it.
    let mut waiter = case.subscribe("events.>", Some("workers")).await;
    let waiting = async { next_text(&mut waiter).await };
    let release = async {
        tokio::task::yield_now().await;
        drop(holder);
    };
    let (redelivered, ()) = tokio::join!(waiting, release);
    assert_eq!(redelivered, "1");

    // The waiter polls again, which acknowledges message 1. A third consumer does not get it.
    case.publish("events.file", "2").await;
    assert_eq!(next_text(&mut waiter).await, "2");
    case.publish("events.file", "3").await;
    assert_eq!(next_text(&mut waiter).await, "3");
    drop(waiter);
    let mut third = case.subscribe("events.>", Some("workers")).await;
    assert_eq!(next_text(&mut third).await, "3");
    case.publish("events.file", "end").await;
    assert_eq!(next_text(&mut third).await, "end");
}

pub async fn a_durable_name_reads_one_pattern_only(case: &Case) {
    let _events = case.subscribe("events.>", Some("detect")).await;
    let result = case
        .bus
        .subscribe(&case.subject("detections.>"), Some("detect"))
        .await
        .map(|_| ());
    let message = invalid_input(result);
    assert_eq!(
        message,
        format!(
            "durable name \"detect\" already reads the pattern {:?}; use one pattern for each \
             durable name",
            case.subject("events.>")
        )
    );
    // The same pattern is accepted again, and a different name can read a different pattern.
    let _same = case.subscribe("events.>", Some("detect")).await;
    let _other = case.subscribe("detections.>", Some("triage")).await;
}

pub async fn a_subject_outside_the_stream_is_not_valid(case: &Case) {
    let result = case.bus.publish("elsewhere.events", b"x".to_vec()).await;
    let message = invalid_input(result);
    assert!(
        message
            .starts_with("subject \"elsewhere.events\" is not in the subjects that the bus stores"),
        "{message}"
    );
    // The root token alone does not match `{root}.>`.
    let message = invalid_input(case.bus.publish(&case.root, b"x".to_vec()).await);
    assert!(
        message.contains("is not in the subjects that the bus stores"),
        "{message}"
    );

    let result = case.bus.subscribe("elsewhere.>", None).await.map(|_| ());
    let message = invalid_input(result);
    assert!(
        message.starts_with("pattern \"elsewhere.>\" cannot match a subject that the bus stores"),
        "{message}"
    );
    let result = case
        .bus
        .subscribe("elsewhere.>", Some("reader"))
        .await
        .map(|_| ());
    assert!(invalid_input(result).contains("cannot match"));
}

pub async fn a_durable_name_has_a_limited_character_set(case: &Case) {
    let too_long = "n".repeat(65);
    for name in [
        "",
        "detect.tier1",
        "detect tier1",
        "detect*",
        "detect>",
        "detect/1",
        &too_long,
    ] {
        let result = case
            .bus
            .subscribe(&case.subject("events.>"), Some(name))
            .await
            .map(|_| ());
        let message = invalid_input(result);
        assert!(message.starts_with("durable name "), "{name:?}: {message}");
    }
    let longest = "n".repeat(64);
    let _valid = case.subscribe("events.>", Some("Tier-1_detect")).await;
    let _longest = case.subscribe("events.>", Some(&longest)).await;
}

pub async fn a_pattern_with_a_misplaced_wildcard_is_not_valid(case: &Case) {
    let patterns = [
        case.subject(">.events"),
        case.subject("events..file"),
        case.subject("events. file"),
        format!("{}.{}", case.root, "a".repeat(256)),
    ];
    for pattern in patterns {
        for durable in [None, Some("reader")] {
            let result = case.bus.subscribe(&pattern, durable).await.map(|_| ());
            let message = invalid_input(result);
            assert!(message.starts_with("pattern "), "{pattern:?}: {message}");
        }
    }
    let message = invalid_input(
        case.bus
            .publish(&case.subject("events\tfile"), b"x".to_vec())
            .await,
    );
    assert!(message.contains("whitespace or control"), "{message}");
}
