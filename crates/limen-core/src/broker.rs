//! What a Kafka session request says about the CLI's local listeners
//! (ADR-0037, "The multi-broker design"). A Kafka client connects to every
//! broker at the address the cluster advertises, so the CLI opens one
//! loopback listener for bootstrap and one per broker slot, and every
//! session carries the port table so the worker can rewrite advertised
//! addresses to those ports.

use std::fmt;

/// The most local listeners (the bootstrap one plus one per broker).
pub const MAX_LISTENERS: usize = 65;

/// Which local listener a session came in on, and where all of them are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaSlot {
    /// Index into `ports`: 0 is the bootstrap listener, `n` serves the
    /// broker of rank `n - 1` (node IDs sorted ascending).
    pub slot: usize,
    /// Loopback ports of the CLI's listeners, bootstrap first.
    pub ports: Vec<u16>,
}

/// The text is not a slot description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadSlot(pub &'static str);

impl fmt::Display for BadSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad Kafka slot: {}", self.0)
    }
}

impl std::error::Error for BadSlot {}

impl KafkaSlot {
    #[must_use]
    pub fn new(slot: usize, ports: Vec<u16>) -> Self {
        Self { slot, ports }
    }

    /// `slot=2;ports=41001,41002,41003`
    #[must_use]
    pub fn encode(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(u16::to_string).collect();
        format!("slot={};ports={}", self.slot, ports.join(","))
    }

    /// The loopback port that stands for the broker of rank `rank`, if the
    /// CLI opened a listener for it.
    #[must_use]
    pub fn port_for_rank(&self, rank: usize) -> Option<u16> {
        self.ports.get(rank + 1).copied()
    }

    /// The rank of the broker this session is for, or `None` for bootstrap.
    #[must_use]
    pub fn rank(&self) -> Option<usize> {
        self.slot.checked_sub(1)
    }

    /// # Errors
    /// If the text is not in the form [`KafkaSlot::encode`] writes, or the
    /// slot is outside the table, or a port is zero.
    pub fn parse(text: &str) -> Result<Self, BadSlot> {
        let (slot, ports) = text
            .strip_prefix("slot=")
            .and_then(|rest| rest.split_once(";ports="))
            .ok_or(BadSlot("expected slot=N;ports=P,P,…"))?;
        let slot: usize = slot.parse().map_err(|_| BadSlot("the slot is not a number"))?;
        let ports = ports
            .split(',')
            .map(|p| match p.parse::<u16>() {
                Ok(0) | Err(_) => Err(BadSlot("a port is not 1 to 65535")),
                Ok(p) => Ok(p),
            })
            .collect::<Result<Vec<u16>, _>>()?;
        if ports.len() < 2 || ports.len() > MAX_LISTENERS {
            return Err(BadSlot("expected between 2 and 65 listeners"));
        }
        if slot >= ports.len() {
            return Err(BadSlot("the slot is not in the port table"));
        }
        Ok(Self { slot, ports })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_names_brokers_by_rank() {
        let s = KafkaSlot::new(2, vec![40000, 40001, 40002, 40003]);
        assert_eq!(s.encode(), "slot=2;ports=40000,40001,40002,40003");
        assert_eq!(KafkaSlot::parse(&s.encode()).expect("parses"), s);
        assert_eq!(s.rank(), Some(1));
        assert_eq!(KafkaSlot::new(0, vec![1, 2]).rank(), None);
        assert_eq!(s.port_for_rank(0), Some(40001));
        assert_eq!(s.port_for_rank(2), Some(40003));
        assert_eq!(s.port_for_rank(3), None);
    }

    #[test]
    fn refuses_anything_else() {
        for bad in [
            "",
            "slot=0",
            "slot=x;ports=1,2",
            "slot=0;ports=1",
            "slot=2;ports=1,2",
            "slot=0;ports=0,2",
            "slot=0;ports=1,70000",
            "slot=0;ports=1,,2",
            "ports=1,2;slot=0",
        ] {
            assert!(KafkaSlot::parse(bad).is_err(), "{bad:?}");
        }
        let many = format!(
            "slot=0;ports={}",
            (1..=66).map(|p| p.to_string()).collect::<Vec<_>>().join(",")
        );
        assert!(KafkaSlot::parse(&many).is_err());
    }
}
