//! Host-plugin installation and introspection.
//!
//! §6 of the V1.3 Sprint 2 plan replaces the manual
//! `cp -R openclaw-plugin-runtime ~/.openclaw/extensions/clawguard-runtime`
//! step that the runbook still carries as a stopgap.

pub mod openclaw;

pub use openclaw::{
    detect_broker_resolvable, install_runtime_plugin, plugin_status, InstallAction,
    InstallError, InstallReport, PluginStatus,
};
