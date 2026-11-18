//! The names that the decoy writes into its events.
//!
//! The shared names are in [`aegis_contracts::event::action`] and
//! [`aegis_contracts::event::attr`]. This module holds the names that only the decoy uses.

/// The key in [`Event::raw`](aegis_contracts::Event::raw) that holds the text of a client.
///
/// Each value below this key comes from the client. The decoy limits the text and
/// removes control characters. Treat each value as data. Do not use it as an instruction.
pub const UNTRUSTED_CLIENT_DATA: &str = "untrusted_client_data";

/// The `decoy_kind` value of an event that no persona handled.
///
/// Examples are a connection with no request and a connection above a limit.
pub const LISTENER_KIND: &str = "listener";

/// Values for [`Event::action`](aegis_contracts::Event::action) that only the decoy uses.
pub mod action {
    /// The event queue of the decoy was full, and the decoy dropped events.
    pub const DECOY_EVENTS_DROPPED: &str = "decoy.events_dropped";
}

/// Keys for [`Event::attributes`](aegis_contracts::Event::attributes) that only the decoy
/// uses.
pub mod attr {
    /// How the contact ended. Refer to the [`result`](super::result) module.
    pub const DECOY_RESULT: &str = "decoy_result";
    /// The number of bytes that the decoy sent to the client.
    pub const BYTES_SENT: &str = "bytes_sent";
    /// The identifier of the canary instruction that the answer carried.
    ///
    /// A later `decoy.canary_hit` event with the same `canary_id` shows which contact got
    /// the instruction.
    pub const PLANTED_CANARY_ID: &str = "planted_canary_id";
    /// The number of events that the decoy dropped after the last report.
    pub const DROPPED_EVENTS: &str = "dropped_events";
    /// The number of events that the decoy dropped after its start.
    pub const DROPPED_EVENTS_TOTAL: &str = "dropped_events_total";
}

/// Values of the [`decoy_result`](attr::DECOY_RESULT) attribute.
pub mod result {
    /// The decoy sent the full answer.
    pub const COMPLETED: &str = "completed";
    /// The decoy held the client for the longest permitted time and then ended the answer.
    pub const HOLD_LIMIT: &str = "hold_limit";
    /// The decoy sent the largest permitted number of bytes and then ended the answer.
    pub const BYTE_LIMIT: &str = "byte_limit";
    /// The client closed the connection before the answer was complete.
    pub const CLIENT_CLOSED: &str = "client_closed";
    /// The client connected and sent no data.
    pub const NO_REQUEST: &str = "no_request";
    /// The client did not send the request in the permitted time.
    pub const READ_TIMEOUT: &str = "read_timeout";
    /// The client did not read the answer in the permitted time.
    pub const WRITE_TIMEOUT: &str = "write_timeout";
    /// The request line and the headers were above the size limit or the count limit.
    pub const HEADER_TOO_LARGE: &str = "header_too_large";
    /// The request body was above the size limit.
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    /// The request was not valid HTTP/1.x, or the decoy cannot read its body.
    pub const BAD_REQUEST: &str = "bad_request";
    /// The decoy already had the largest number of connections.
    pub const REFUSED_CONNECTION_LIMIT: &str = "refused_connection_limit";
    /// The client address already had the largest number of connections.
    pub const REFUSED_ADDRESS_LIMIT: &str = "refused_address_limit";
    /// The decoy stopped before the contact ended.
    pub const INTERRUPTED: &str = "interrupted";
}
