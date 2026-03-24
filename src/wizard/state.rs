use std::fmt::{Display, Formatter};

use crate::config::presets::preset_by_id;
use crate::config::schema::{AlertStrategy, AppConfig, Strictness};
use crate::discovery::DiscoveryReport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardAnswers {
    pub selected_preset: Option<String>,
    pub alert_strategy: AlertStrategy,
    pub webhook_url: Option<String>,
    pub strictness: Strictness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardError {
    NoDetectedRuntime,
    UnknownPreset(String),
    PromptFailed(String),
    PersistConfig(String),
}

impl Display for WizardError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDetectedRuntime => write!(f, "no supported runtime was detected"),
            Self::UnknownPreset(preset) => write!(f, "unknown preset: {preset}"),
            Self::PromptFailed(error) => write!(f, "wizard prompt failed: {error}"),
            Self::PersistConfig(error) => write!(f, "failed to persist config: {error}"),
        }
    }
}

impl std::error::Error for WizardError {}

pub fn build_app_config(
    discovery: &DiscoveryReport,
    answers: &WizardAnswers,
) -> Result<AppConfig, WizardError> {
    let preset_id = answers
        .selected_preset
        .clone()
        .or_else(|| {
            discovery
                .runtimes
                .iter()
                .find(|runtime| runtime.recommended)
                .map(|runtime| runtime.preset_id.clone())
        })
        .or_else(|| {
            discovery
                .runtimes
                .first()
                .map(|runtime| runtime.preset_id.clone())
        })
        .ok_or(WizardError::NoDetectedRuntime)?;

    let preset = preset_by_id(&preset_id).ok_or_else(|| WizardError::UnknownPreset(preset_id))?;

    Ok(AppConfig {
        preset: preset.id,
        strictness: answers.strictness,
        alert_strategy: answers.alert_strategy,
        webhook_url: answers.webhook_url.clone(),
        max_file_size_bytes: preset.max_file_size_bytes,
    })
}
