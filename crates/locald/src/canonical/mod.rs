//! Canonical event and fact models
//!
//! This module provides the canonical data models used throughout the detection pipeline:
//! - `event`: Canonical events normalized from various telemetry sources
//! - `fact`: Derived facts from events, used for playbook matching
//! - `scope`: Scope keys for correlation (process, user, host)

pub mod event;
pub mod fact;
pub mod scope;

pub use event::{CanonicalEvent, CanonicalEventType, OrderedF32};
pub use fact::{Fact, FactBuilder, FactDomain, FactType, FieldValue, PersistType};
pub use scope::{ExeScopeKey, FileScopeKey, ProcScopeKey, SockScopeKey, UserScopeKey};
