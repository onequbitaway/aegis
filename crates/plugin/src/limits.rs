//! The resource limits of the plugin sandbox.

use std::time::Duration;

use aegis_contracts::{Error, Result};

/// The resource limits that a [`PluginHost`](crate::PluginHost) applies to each plugin.
///
/// The default values are safe for a connector that calls a web API. Change one value
/// and keep the others:
///
/// ```
/// use std::time::Duration;
///
/// use aegis_plugin::HostLimits;
///
/// let limits = HostLimits {
///     call_timeout: Duration::from_secs(5),
///     ..HostLimits::default()
/// };
/// assert_eq!(limits.max_memory_bytes, 64 * 1024 * 1024);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLimits {
    /// The largest total size of the linear memories of one plugin instance, in bytes.
    ///
    /// The default value is 64 MiB.
    pub max_memory_bytes: usize,
    /// The largest size of the data that a plugin gives to the host in one transfer, in
    /// bytes.
    ///
    /// A transfer is the result of one plugin function, or the parameters of one host
    /// function. The host stops a call that transfers more. The default value is 8 MiB.
    pub max_transfer_bytes: usize,
    /// The longest time that one call into a plugin can take.
    ///
    /// The time includes the HTTP requests that the host sends for the plugin. The default
    /// value is 30 seconds.
    pub call_timeout: Duration,
    /// The largest number of calls that run in one plugin at the same time.
    ///
    /// More calls wait for a free position. The default value is 4.
    pub max_concurrent_calls: usize,
    /// The largest size of a component file, in bytes.
    ///
    /// The default value is 32 MiB.
    pub max_component_bytes: u64,
    /// The longest time that one outbound HTTP request can take.
    ///
    /// The default value is 10 seconds.
    pub http_timeout: Duration,
    /// The largest size of the body of one HTTP response, in bytes.
    ///
    /// The default value is 4 MiB.
    pub max_http_response_bytes: usize,
    /// The largest number of HTTP requests that a plugin can make in one call.
    ///
    /// A request that the host refuses also counts. The default value is 32.
    pub max_http_requests_per_call: u32,
    /// The largest number of log messages that the host writes for one call.
    ///
    /// The host drops the messages after this number, and writes one warning that it
    /// does so. The default value is 100.
    pub max_log_messages_per_call: u32,
    /// With `true`, the host refuses a manifest that has no `sha256` value.
    ///
    /// The default value is `false`.
    pub require_sha256: bool,
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,
            max_transfer_bytes: 8 * 1024 * 1024,
            call_timeout: Duration::from_secs(30),
            max_concurrent_calls: 4,
            max_component_bytes: 32 * 1024 * 1024,
            http_timeout: Duration::from_secs(10),
            max_http_response_bytes: 4 * 1024 * 1024,
            max_http_requests_per_call: 32,
            max_log_messages_per_call: 100,
            require_sha256: false,
        }
    }
}

impl HostLimits {
    /// Checks that each limit permits a plugin to run.
    ///
    /// A limit of zero for memory, transfer size, time, calls, or component size makes
    /// each call fail. Such a value is [`Error::Config`].
    pub(crate) fn validate(&self) -> Result<()> {
        let zero = [
            ("max_memory_bytes", self.max_memory_bytes == 0),
            ("max_transfer_bytes", self.max_transfer_bytes == 0),
            ("call_timeout", self.call_timeout.is_zero()),
            ("max_concurrent_calls", self.max_concurrent_calls == 0),
            ("max_component_bytes", self.max_component_bytes == 0),
            ("http_timeout", self.http_timeout.is_zero()),
        ];
        match zero.iter().find(|(_, is_zero)| *is_zero) {
            Some((name, _)) => Err(Error::Config(format!(
                "the plugin host limit {name} must be larger than zero"
            ))),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_limits_are_valid() {
        HostLimits::default().validate().unwrap();
    }

    #[test]
    fn a_zero_limit_is_a_configuration_error_that_names_the_limit() {
        let cases = [
            (
                HostLimits {
                    max_memory_bytes: 0,
                    ..HostLimits::default()
                },
                "max_memory_bytes",
            ),
            (
                HostLimits {
                    max_transfer_bytes: 0,
                    ..HostLimits::default()
                },
                "max_transfer_bytes",
            ),
            (
                HostLimits {
                    call_timeout: Duration::ZERO,
                    ..HostLimits::default()
                },
                "call_timeout",
            ),
            (
                HostLimits {
                    max_concurrent_calls: 0,
                    ..HostLimits::default()
                },
                "max_concurrent_calls",
            ),
            (
                HostLimits {
                    max_component_bytes: 0,
                    ..HostLimits::default()
                },
                "max_component_bytes",
            ),
            (
                HostLimits {
                    http_timeout: Duration::ZERO,
                    ..HostLimits::default()
                },
                "http_timeout",
            ),
        ];
        for (limits, name) in cases {
            let error = limits.validate().unwrap_err();
            assert!(
                matches!(&error, Error::Config(message)
                    if *message == format!("the plugin host limit {name} must be larger than zero")),
                "{error:?}"
            );
        }
    }

    #[test]
    fn zero_http_requests_and_zero_log_messages_are_valid() {
        let limits = HostLimits {
            max_http_requests_per_call: 0,
            max_log_messages_per_call: 0,
            max_http_response_bytes: 0,
            ..HostLimits::default()
        };
        limits.validate().unwrap();
    }
}
