//! Runtime policy enforcement for ClawGuard V1.3 Sprint 2.
//!
//! This module hosts the in-the-loop deterministic policy layer that
//! evaluates tool calls before and after they hit the agent runtime.
//!
//! # Structure
//! - [`policy`] — `PolicyEngine` trait, verdict types, rule implementations,
//!   and the TOML manifest loader.
//! - [`adapter`] — runtime-specific entry points (OpenClaw, Claude Code in
//!   Sprint 3+) that translate hook payloads into `PolicyEngine` calls and
//!   back.
//!
//! # Trust boundary
//! Adapters run inside the host agent runtime. Every entry point that the
//! host invokes wraps `PolicyEngine` calls in `catch_unwind` and fails-open
//! on panic so a ClawGuard bug cannot crash the host. This fail-open stance
//! is explicit and documented; Sprint 3 introduces a circuit breaker that
//! surfaces repeated failures to operators.

pub mod adapter;
pub mod policy;
