//! User-space side of the Aegis-eBPF probe: turns the records of the eBPF
//! programs into the events that `aegis-agent` ingests.

pub mod container;
pub mod event;
