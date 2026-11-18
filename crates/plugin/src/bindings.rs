//! The Rust bindings that `wasmtime` generates from the WIT package in the `wit` directory.
//!
//! The two worlds share the `host` and `types` interfaces. The bindings of the action
//! world use the types of the source world again, thus the host implements the `host`
//! interface one time.

/// The bindings of the `source-connector` world and of the shared interfaces.
mod source_world {
    wasmtime::component::bindgen!({
        path: "../../wit",
        world: "source-connector",
        imports: {
            "aegis:plugin/host.http-request": async,
        },
        exports: { default: async },
    });
}

/// The bindings of the `action-connector` world.
mod action_world {
    wasmtime::component::bindgen!({
        path: "../../wit",
        world: "action-connector",
        with: {
            "aegis:plugin/host": super::source_world::aegis::plugin::host,
            "aegis:plugin/types": super::source_world::aegis::plugin::types,
        },
        exports: { default: async },
    });
}

pub(crate) use action_world::ActionConnectorPre;
pub(crate) use source_world::SourceConnectorPre;
pub(crate) use source_world::aegis::plugin::host;
pub(crate) use source_world::aegis::plugin::types::Error as GuestError;
