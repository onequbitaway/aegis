//! The rules for which addresses a document can name.
//!
//! A document for other defenders must not name an address of the operator. It also
//! must not name an address that has no meaning outside one network, for example a
//! private address. [`AddressPolicy`] holds the rules. The report builder and the
//! indicator export use the same policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

/// The class of an address, as [`AddressPolicy::classify`] gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClass {
    /// A public address that is not in a network of the operator.
    Global,
    /// An address in a network of the operator.
    Operator,
    /// A private address, a unique local address, or an address in the shared address
    /// space of a carrier.
    Private,
    /// An address in a range that the IETF keeps for documentation.
    Documentation,
    /// A loopback, link-local, multicast, unspecified, translation, or other
    /// special-purpose address.
    Reserved,
}

const fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(a, b, c, d), prefix)
}

const fn v6(segments: [u16; 8], prefix: u8) -> Ipv6Net {
    Ipv6Net::new_assert(
        Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        ),
        prefix,
    )
}

/// The IPv4 special-purpose ranges, from the IANA registry.
const SPECIAL_V4: &[(Ipv4Net, AddressClass)] = &[
    (v4(0, 0, 0, 0, 8), AddressClass::Reserved),
    (v4(10, 0, 0, 0, 8), AddressClass::Private),
    (v4(100, 64, 0, 0, 10), AddressClass::Private),
    (v4(127, 0, 0, 0, 8), AddressClass::Reserved),
    (v4(169, 254, 0, 0, 16), AddressClass::Reserved),
    (v4(172, 16, 0, 0, 12), AddressClass::Private),
    (v4(192, 0, 0, 0, 24), AddressClass::Reserved),
    (v4(192, 0, 2, 0, 24), AddressClass::Documentation),
    (v4(192, 88, 99, 0, 24), AddressClass::Reserved),
    (v4(192, 168, 0, 0, 16), AddressClass::Private),
    (v4(198, 18, 0, 0, 15), AddressClass::Reserved),
    (v4(198, 51, 100, 0, 24), AddressClass::Documentation),
    (v4(203, 0, 113, 0, 24), AddressClass::Documentation),
    (v4(224, 0, 0, 0, 4), AddressClass::Reserved),
    (v4(240, 0, 0, 0, 4), AddressClass::Reserved),
];

/// The IPv6 special-purpose ranges, from the IANA registry. The first match applies.
const SPECIAL_V6: &[(Ipv6Net, AddressClass)] = &[
    (
        v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
        AddressClass::Documentation,
    ),
    (
        v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
        AddressClass::Documentation,
    ),
    (v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7), AddressClass::Private),
    (
        v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
        AddressClass::Reserved,
    ),
    (
        v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
        AddressClass::Reserved,
    ),
];

/// The range of the IPv6 global unicast addresses. All other IPv6 addresses are special.
const GLOBAL_UNICAST_V6: Ipv6Net = v6([0x2000, 0, 0, 0, 0, 0, 0, 0], 3);

/// Returns the canonical form of an address.
///
/// An IPv4 address in the IPv6-mapped form becomes an IPv4 address. The two forms of one
/// address are thus equal, and a mapped form cannot go around the policy.
#[must_use]
pub fn canonical_address(address: IpAddr) -> IpAddr {
    address.to_canonical()
}

/// The rules for which addresses a document can name.
///
/// The default policy has no operator networks and does not permit the documentation
/// ranges.
///
/// ```
/// use aegis_share::{AddressClass, AddressPolicy};
///
/// let policy = AddressPolicy::new().with_operator_network("198.51.100.0/24".parse()?);
/// assert_eq!(policy.classify("198.51.100.7".parse()?), AddressClass::Operator);
/// assert_eq!(policy.classify("10.1.2.3".parse()?), AddressClass::Private);
/// assert_eq!(policy.classify("203.0.113.50".parse()?), AddressClass::Documentation);
/// assert!(!policy.permits("203.0.113.50".parse()?));
/// assert!(policy.permits("93.184.216.34".parse()?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressPolicy {
    /// The networks of the operator. A document never names an address in them.
    #[serde(default)]
    pub operator_networks: Vec<IpNet>,
    /// With `true`, a document can name an address in a documentation range.
    ///
    /// The recorded attack log of AEGIS uses the documentation ranges, so tests and
    /// demonstrations set this option. Do not set it for a document that you send.
    #[serde(default)]
    pub permit_documentation_ranges: bool,
}

impl AddressPolicy {
    /// Makes the default policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a network of the operator.
    #[must_use]
    pub fn with_operator_network(mut self, network: IpNet) -> Self {
        self.operator_networks.push(network);
        self
    }

    /// Permits the documentation ranges. Use this only for tests and demonstrations.
    #[must_use]
    pub fn with_documentation_ranges(mut self) -> Self {
        self.permit_documentation_ranges = true;
        self
    }

    /// Returns the class of `address`.
    ///
    /// The check of the operator networks comes first. An operator network can thus
    /// contain private addresses.
    #[must_use]
    pub fn classify(&self, address: IpAddr) -> AddressClass {
        let address = canonical_address(address);
        if self
            .operator_networks
            .iter()
            .any(|network| network.contains(&address))
        {
            return AddressClass::Operator;
        }
        match address {
            IpAddr::V4(address) => SPECIAL_V4
                .iter()
                .find(|(network, _)| network.contains(&address))
                .map_or(AddressClass::Global, |(_, class)| *class),
            IpAddr::V6(address) => SPECIAL_V6
                .iter()
                .find(|(network, _)| network.contains(&address))
                .map_or_else(
                    || {
                        if GLOBAL_UNICAST_V6.contains(&address) {
                            AddressClass::Global
                        } else {
                            AddressClass::Reserved
                        }
                    },
                    |(_, class)| *class,
                ),
        }
    }

    /// Returns `true` if a document can name `address`.
    ///
    /// This is so for a [`AddressClass::Global`] address. With
    /// [`permit_documentation_ranges`](Self::permit_documentation_ranges), it is also so
    /// for a [`AddressClass::Documentation`] address.
    #[must_use]
    pub fn permits(&self, address: IpAddr) -> bool {
        match self.classify(address) {
            AddressClass::Global => true,
            AddressClass::Documentation => self.permit_documentation_ranges,
            AddressClass::Operator | AddressClass::Private | AddressClass::Reserved => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(text: &str) -> AddressClass {
        AddressPolicy::new().classify(text.parse().unwrap())
    }

    #[test]
    fn ipv4_ranges_get_the_class_of_the_registry() {
        let cases = [
            ("8.8.8.8", AddressClass::Global),
            ("93.184.216.34", AddressClass::Global),
            ("100.63.255.255", AddressClass::Global),
            ("100.128.0.0", AddressClass::Global),
            ("172.32.0.1", AddressClass::Global),
            ("192.0.1.1", AddressClass::Global),
            ("198.20.0.1", AddressClass::Global),
            ("223.255.255.255", AddressClass::Global),
            ("0.1.2.3", AddressClass::Reserved),
            ("10.0.0.1", AddressClass::Private),
            ("100.64.0.1", AddressClass::Private),
            ("100.127.255.255", AddressClass::Private),
            ("127.0.0.1", AddressClass::Reserved),
            ("169.254.169.254", AddressClass::Reserved),
            ("172.16.0.1", AddressClass::Private),
            ("172.31.255.255", AddressClass::Private),
            ("192.0.0.8", AddressClass::Reserved),
            ("192.0.2.77", AddressClass::Documentation),
            ("192.88.99.1", AddressClass::Reserved),
            ("192.168.1.1", AddressClass::Private),
            ("198.18.0.1", AddressClass::Reserved),
            ("198.19.255.255", AddressClass::Reserved),
            ("198.51.100.10", AddressClass::Documentation),
            ("203.0.113.50", AddressClass::Documentation),
            ("224.0.0.1", AddressClass::Reserved),
            ("239.255.255.255", AddressClass::Reserved),
            ("240.0.0.1", AddressClass::Reserved),
            ("255.255.255.255", AddressClass::Reserved),
        ];
        assert_eq!(cases.len(), 28);
        for (address, expected) in cases {
            assert_eq!(class(address), expected, "{address}");
        }
    }

    #[test]
    fn ipv6_ranges_get_the_class_of_the_registry() {
        let cases = [
            ("2606:4700:4700::1111", AddressClass::Global),
            ("2a00:1450:4001:81b::200e", AddressClass::Global),
            ("2001:4860:4860::8888", AddressClass::Global),
            ("3ffe::1", AddressClass::Global),
            ("::", AddressClass::Reserved),
            ("::1", AddressClass::Reserved),
            ("64:ff9b::808:808", AddressClass::Reserved),
            ("100::1", AddressClass::Reserved),
            ("2001::1", AddressClass::Reserved),
            ("2001:1ff:ffff::1", AddressClass::Reserved),
            ("2001:db8::1", AddressClass::Documentation),
            ("2001:db8:ffff:ffff::1", AddressClass::Documentation),
            ("2002:c000:204::1", AddressClass::Reserved),
            ("3fff::1", AddressClass::Documentation),
            ("3fff:fff:ffff::1", AddressClass::Documentation),
            ("5f00::1", AddressClass::Reserved),
            ("fc00::1", AddressClass::Private),
            ("fd12:3456:789a::1", AddressClass::Private),
            ("fe80::1", AddressClass::Reserved),
            ("fec0::1", AddressClass::Reserved),
            ("ff02::1", AddressClass::Reserved),
        ];
        assert_eq!(cases.len(), 21);
        for (address, expected) in cases {
            assert_eq!(class(address), expected, "{address}");
        }
    }

    #[test]
    fn a_mapped_address_has_the_class_of_its_ipv4_address() {
        assert_eq!(class("::ffff:10.0.0.1"), AddressClass::Private);
        assert_eq!(class("::ffff:203.0.113.50"), AddressClass::Documentation);
        assert_eq!(class("::ffff:8.8.8.8"), AddressClass::Global);
        assert_eq!(
            canonical_address("::ffff:8.8.8.8".parse().unwrap()),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );

        // A mapped form does not go around an operator network.
        let policy = AddressPolicy::new().with_operator_network("8.8.8.0/24".parse().unwrap());
        assert_eq!(
            policy.classify("::ffff:8.8.8.8".parse().unwrap()),
            AddressClass::Operator
        );
    }

    #[test]
    fn an_operator_network_wins_over_each_other_class() {
        let policy = AddressPolicy::new()
            .with_operator_network("10.0.0.0/8".parse().unwrap())
            .with_operator_network("203.0.113.0/25".parse().unwrap())
            .with_operator_network("2606:4700::/32".parse().unwrap());
        let class = |text: &str| policy.classify(text.parse().unwrap());
        assert_eq!(class("10.9.8.7"), AddressClass::Operator);
        assert_eq!(class("203.0.113.50"), AddressClass::Operator);
        assert_eq!(class("203.0.113.200"), AddressClass::Documentation);
        assert_eq!(class("2606:4700:4700::1111"), AddressClass::Operator);
        assert_eq!(class("2607::1"), AddressClass::Global);
    }

    #[test]
    fn only_global_addresses_are_permitted_by_default() {
        let policy = AddressPolicy::new().with_operator_network("93.184.216.0/24".parse().unwrap());
        let permits = |text: &str| policy.permits(text.parse().unwrap());
        assert!(permits("8.8.8.8"));
        assert!(permits("2606:4700:4700::1111"));
        assert!(!permits("93.184.216.34"));
        assert!(!permits("10.0.0.1"));
        assert!(!permits("127.0.0.1"));
        assert!(!permits("203.0.113.50"));
        assert!(!permits("2001:db8::1"));
        assert!(!permits("fe80::1"));
    }

    #[test]
    fn the_documentation_option_permits_only_the_documentation_ranges() {
        let policy = AddressPolicy::new()
            .with_documentation_ranges()
            .with_operator_network("198.51.100.0/24".parse().unwrap());
        let permits = |text: &str| policy.permits(text.parse().unwrap());
        assert!(permits("203.0.113.50"));
        assert!(permits("192.0.2.77"));
        assert!(permits("2001:db8::1"));
        // An operator network in a documentation range stays out.
        assert!(!permits("198.51.100.10"));
        assert!(!permits("10.0.0.1"));
        assert!(!permits("169.254.1.1"));
    }

    #[test]
    fn the_policy_decodes_from_json_and_rejects_unknown_keys() {
        let policy: AddressPolicy = serde_json::from_str(
            r#"{"operator_networks":["198.51.100.0/24","2001:db8:1::/48"],"permit_documentation_ranges":true}"#,
        )
        .unwrap();
        assert_eq!(policy.operator_networks.len(), 2);
        assert!(policy.permit_documentation_ranges);
        assert_eq!(
            serde_json::from_str::<AddressPolicy>("{}").unwrap(),
            AddressPolicy::default()
        );
        let error =
            serde_json::from_str::<AddressPolicy>(r#"{"operator_network":[]}"#).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}
