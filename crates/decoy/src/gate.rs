//! The connection limits and the memory count of a decoy.
//!
//! The [`Gate`] admits a connection only below the limit for all clients and the limit
//! for one client address. The [`MemoryGauge`] counts the bytes that the decoy keeps for
//! connections and for recorded data.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Why the gate refused a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The decoy already has the largest number of connections.
    Total,
    /// The client address already has the largest number of connections.
    Address,
}

#[derive(Default)]
struct GateState {
    total: usize,
    per_address: HashMap<IpAddr, usize>,
}

/// Admits connections up to the limits.
///
/// The gate keeps one counter for each address that has an open connection. Thus the
/// table never has more entries than the connection limit.
pub(crate) struct Gate {
    max_total: usize,
    max_per_address: usize,
    state: Mutex<GateState>,
    peak: AtomicUsize,
}

impl Gate {
    pub(crate) fn new(max_total: usize, max_per_address: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total,
            max_per_address,
            state: Mutex::default(),
            peak: AtomicUsize::new(0),
        })
    }

    /// Admits one connection of `address`, or refuses it.
    ///
    /// The connection counts until the caller drops the [`Permit`].
    pub(crate) fn enter(self: &Arc<Self>, address: IpAddr) -> Result<Permit, Refusal> {
        let key = address_key(address);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let of_address = state.per_address.get(&key).copied().unwrap_or(0);
        if of_address >= self.max_per_address {
            return Err(Refusal::Address);
        }
        if state.total >= self.max_total {
            return Err(Refusal::Total);
        }
        state.total += 1;
        state.per_address.insert(key, of_address + 1);
        self.peak.fetch_max(state.total, Ordering::Relaxed);
        Ok(Permit {
            gate: Arc::clone(self),
            key,
        })
    }

    /// Returns the number of open connections.
    pub(crate) fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }

    /// Returns the largest number of connections that were open at the same time.
    pub(crate) fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Returns the number of addresses in the table.
    #[cfg(test)]
    pub(crate) fn tracked_addresses(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .per_address
            .len()
    }
}

/// One admitted connection. The drop of the permit frees its place.
pub(crate) struct Permit {
    gate: Arc<Gate>,
    key: IpAddr,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.total = state.total.saturating_sub(1);
        let remaining = state
            .per_address
            .get(&self.key)
            .copied()
            .unwrap_or(0)
            .saturating_sub(1);
        if remaining == 0 {
            state.per_address.remove(&self.key);
        } else {
            state.per_address.insert(self.key, remaining);
        }
    }
}

/// Returns `address` in its usual form: an IPv4 address in IPv6 form becomes IPv4.
pub(crate) fn canonical(address: IpAddr) -> IpAddr {
    address.to_canonical()
}

/// Returns the key that counts the connections of `address`.
///
/// An IPv4 address is its own key. For IPv6, the key is the `/64` network, because one
/// client usually controls all addresses of its `/64` network.
pub(crate) fn address_key(address: IpAddr) -> IpAddr {
    match canonical(address) {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => {
            let network = u128::from(address) & !u128::from(u64::MAX);
            IpAddr::V6(Ipv6Addr::from(network))
        }
    }
}

/// Counts the bytes that the decoy keeps, and the largest count that occurred.
#[derive(Default)]
pub(crate) struct MemoryGauge {
    current: AtomicUsize,
    peak: AtomicUsize,
}

impl MemoryGauge {
    pub(crate) fn add(&self, bytes: usize) {
        let before = self.current.fetch_add(bytes, Ordering::Relaxed);
        self.peak
            .fetch_max(before.saturating_add(bytes), Ordering::Relaxed);
    }

    pub(crate) fn sub(&self, bytes: usize) {
        // Each caller subtracts only what it added. The count still stops at zero.
        let mut current = self.current.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(bytes);
            match self.current.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(found) => current = found,
            }
        }
    }

    /// Returns the number of bytes that the decoy keeps now.
    pub(crate) fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    /// Returns the largest number of bytes that the decoy kept at one time.
    pub(crate) fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }
}

/// The bytes that one connection keeps. The drop of the reservation frees the bytes.
pub(crate) struct Reservation {
    gauge: Arc<MemoryGauge>,
    bytes: usize,
}

impl Reservation {
    pub(crate) fn new(gauge: Arc<MemoryGauge>) -> Self {
        Self { gauge, bytes: 0 }
    }

    /// Adds `bytes` to the reservation.
    pub(crate) fn grow(&mut self, bytes: usize) {
        self.gauge.add(bytes);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    /// Removes `bytes` from the reservation. It removes no more than the reservation has.
    pub(crate) fn shrink(&mut self, bytes: usize) {
        let bytes = bytes.min(self.bytes);
        self.gauge.sub(bytes);
        self.bytes -= bytes;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.gauge.sub(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    #[test]
    fn the_gate_refuses_above_the_limit_for_one_address() {
        let gate = Gate::new(10, 2);
        let first = gate.enter(v4(1)).unwrap();
        let _second = gate.enter(v4(1)).unwrap();
        assert_eq!(gate.enter(v4(1)).err(), Some(Refusal::Address));
        // A different address still gets in.
        let _other = gate.enter(v4(2)).unwrap();
        assert_eq!(gate.active(), 3);
        // A free place lets the address in again.
        drop(first);
        assert_eq!(gate.active(), 2);
        assert!(gate.enter(v4(1)).is_ok());
    }

    #[test]
    fn the_gate_refuses_above_the_limit_for_all_addresses() {
        let gate = Gate::new(3, 2);
        let permits: Vec<Permit> = (1..=3).map(|last| gate.enter(v4(last)).unwrap()).collect();
        assert_eq!(gate.enter(v4(4)).err(), Some(Refusal::Total));
        assert_eq!(gate.active(), 3);
        assert_eq!(gate.peak(), 3);
        drop(permits);
        assert_eq!(gate.active(), 0);
        assert_eq!(gate.peak(), 3);
        assert!(gate.enter(v4(4)).is_ok());
    }

    #[test]
    fn the_address_table_holds_only_addresses_with_open_connections() {
        let gate = Gate::new(100, 4);
        let permits: Vec<Permit> = (0..50).map(|last| gate.enter(v4(last)).unwrap()).collect();
        assert_eq!(gate.tracked_addresses(), 50);
        drop(permits);
        assert_eq!(gate.tracked_addresses(), 0);
        let first = gate.enter(v4(1)).unwrap();
        let second = gate.enter(v4(1)).unwrap();
        assert_eq!(gate.tracked_addresses(), 1);
        drop(first);
        assert_eq!(gate.tracked_addresses(), 1);
        drop(second);
        assert_eq!(gate.tracked_addresses(), 0);
    }

    #[test]
    fn an_ipv4_address_in_ipv6_form_counts_as_the_ipv4_address() {
        let gate = Gate::new(10, 1);
        let mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 1).to_ipv6_mapped());
        assert_eq!(canonical(mapped), v4(1));
        let _permit = gate.enter(mapped).unwrap();
        assert_eq!(gate.enter(v4(1)).err(), Some(Refusal::Address));
    }

    #[test]
    fn the_addresses_of_one_ipv6_network_share_one_limit() {
        let gate = Gate::new(10, 1);
        let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let same_network: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let other_network: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(
            address_key(first),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
        let _permit = gate.enter(first).unwrap();
        assert_eq!(gate.enter(same_network).err(), Some(Refusal::Address));
        assert!(gate.enter(other_network).is_ok());
    }

    #[test]
    fn the_gauge_counts_the_bytes_and_keeps_the_peak() {
        let gauge = Arc::new(MemoryGauge::default());
        let mut first = Reservation::new(gauge.clone());
        first.grow(100);
        let mut second = Reservation::new(gauge.clone());
        second.grow(50);
        assert_eq!(gauge.current(), 150);
        first.shrink(30);
        assert_eq!(gauge.current(), 120);
        // A shrink removes no more than the reservation has.
        first.shrink(1000);
        assert_eq!(gauge.current(), 50);
        drop(first);
        assert_eq!(gauge.current(), 50);
        drop(second);
        assert_eq!(gauge.current(), 0);
        assert_eq!(gauge.peak(), 150);
        gauge.sub(10);
        assert_eq!(gauge.current(), 0);
    }
}
