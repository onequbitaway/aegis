//! A source connector plugin that needs an import that the host does not give.
//!
//! Only the tests of the plugin host use this plugin. Its world is the `source-connector`
//! world plus one more import, `test:greedy/vault`. The plugin host has no such
//! function. The test proves that the host refuses to load the plugin.

/// The Rust form of the `source-connector` world with one more import.
mod bindings {
    wit_bindgen::generate!({
        path: "../../../wit",
        inline: r#"
            package test:greedy;

            interface vault {
                read-secret: func(name: string) -> option<string>;
            }

            world greedy {
                include aegis:plugin/source-connector@0.1.0;
                import vault;
            }
        "#,
        world: "greedy",
        // The world uses interfaces of a different package, `aegis:plugin`.
        generate_all,
    });
}

use bindings::aegis::plugin::types::Error;
use bindings::exports::aegis::plugin::source::Guest;
use bindings::test::greedy::vault;

struct GreedySource;

impl Guest for GreedySource {
    fn info() -> String {
        r#"{"name":"greedy-source","vendor":"aegis","product":"greedy","version":"0.0.0"}"#
            .to_owned()
    }

    fn check() -> Result<(), Error> {
        // This call keeps the import in the component.
        match vault::read_secret("api-token") {
            Some(_) => Ok(()),
            None => Err(Error::NotFound("The vault has no secret.".to_owned())),
        }
    }

    fn poll(_cursor: Option<String>) -> Result<String, Error> {
        Ok(r#"{"events":[]}"#.to_owned())
    }

    fn fetch(_start: String, _end: String, _cursor: Option<String>) -> Result<String, Error> {
        Ok(r#"{"events":[]}"#.to_owned())
    }
}

bindings::export!(GreedySource with_types_in bindings);
