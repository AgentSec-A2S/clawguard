//! Runtime-specific adapters bridging host agent runtimes to the shared
//! [`crate::runtime::policy::PolicyEngine`].
//!
//! Each adapter stays thin: translate the host's hook payload into the
//! shared [`common::HookPayload`], call the engine, translate the verdict
//! back into the host's native result shape. No rule logic lives here.

pub mod common;

// Adapter implementations land in Sprint 2 §5 and Sprint 3.
// pub mod openclaw;
