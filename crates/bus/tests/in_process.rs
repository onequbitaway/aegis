//! The shared test cases for the in-process bus, and for the reference bus of the test kit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use aegis_bus::{BusConfig, BusKind};
use aegis_contracts::bus::subject;

use support::Case;

struct Fixture {
    case: Case,
}

impl Fixture {
    fn case(&self) -> &Case {
        &self.case
    }

    async fn finish(self) {}
}

/// The in-process bus from the public constructor, with the default stream settings.
async fn in_process() -> Fixture {
    let config = BusConfig {
        kind: BusKind::Memory,
        ..BusConfig::default()
    };
    let bus = aegis_bus::connect(&config)
        .await
        .expect("the in-process bus needs no server");
    Fixture {
        case: Case {
            bus,
            root: "aegis".to_owned(),
            redelivers_unacknowledged: true,
        },
    }
}

/// The in-memory bus of the test kit. Other crates test against it. It acknowledges a
/// message when it delivers it, so it never delivers a message again.
async fn reference() -> Fixture {
    Fixture {
        case: Case {
            bus: Arc::new(aegis_testkit::MemoryBus::default()),
            root: "aegis".to_owned(),
            redelivers_unacknowledged: false,
        },
    }
}

mod in_process_bus {
    use super::in_process;
    use crate::support;

    support::core_semantic_tests!(in_process);
    support::strict_semantic_tests!(in_process);
}

/// The shared cases must describe the contract, not this crate. The reference bus proves it.
mod reference_bus {
    use super::reference;
    use crate::support;

    support::core_semantic_tests!(reference);
}

#[tokio::test]
async fn the_test_subjects_are_the_contract_subjects() {
    let fixture = in_process().await;
    assert_eq!(fixture.case.subject("events"), subject::EVENTS);
    assert_eq!(fixture.case.subject("detections"), subject::DETECTIONS);
    assert_eq!(fixture.case.subject("audit"), subject::AUDIT);
}
