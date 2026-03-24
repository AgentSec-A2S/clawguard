pub mod state;

use std::io::{self, BufRead, Write};
use std::path::Path;

use crate::config::presets::preset_by_id;
use crate::config::schema::AlertStrategy;
use crate::config::schema::AppConfig;
use crate::config::schema::Strictness;
use crate::config::store::{config_path_for_home, resolve_home_dir, save_config_for_home};
use crate::discovery::DiscoveryReport;

pub use state::{build_app_config, WizardAnswers, WizardError};

pub fn run_non_interactive(
    discovery: &DiscoveryReport,
    answers: WizardAnswers,
    home_dir: &Path,
) -> Result<AppConfig, WizardError> {
    let config = build_app_config(discovery, &answers)?;
    save_config_for_home(&config, home_dir)
        .map_err(|error| WizardError::PersistConfig(error.to_string()))?;

    Ok(config)
}

pub fn run_interactive(discovery: &DiscoveryReport) -> Result<AppConfig, WizardError> {
    let home_dir = resolve_home_dir();
    let stdin = io::stdin();
    let stdout = io::stdout();

    run_interactive_with_io(discovery, &home_dir, stdin.lock(), stdout.lock())
}

fn run_interactive_with_io<R: BufRead, W: Write>(
    discovery: &DiscoveryReport,
    home_dir: &Path,
    mut input: R,
    mut output: W,
) -> Result<AppConfig, WizardError> {
    writeln!(
        output,
        "ClawGuard is not configured yet. Starting first-run setup."
    )
    .map_err(|error| WizardError::PromptFailed(error.to_string()))?;

    let selected_preset = explain_selected_runtime(discovery, &mut output)?;
    let alert_strategy = prompt_alert_strategy(&mut input, &mut output)?;
    let webhook_url = prompt_webhook_url(&alert_strategy, &mut input, &mut output)?;
    let strictness = prompt_strictness(&mut input, &mut output)?;

    let config = run_non_interactive(
        discovery,
        WizardAnswers {
            selected_preset,
            alert_strategy,
            webhook_url,
            strictness,
        },
        home_dir,
    )?;

    writeln!(
        output,
        "ClawGuard setup saved to {}.",
        config_path_for_home(home_dir).display()
    )
    .map_err(|error| WizardError::PromptFailed(error.to_string()))?;

    Ok(config)
}

fn explain_selected_runtime<W: Write>(
    discovery: &DiscoveryReport,
    output: &mut W,
) -> Result<Option<String>, WizardError> {
    let recommended = discovery
        .runtimes
        .iter()
        .find(|runtime| runtime.recommended)
        .or_else(|| discovery.runtimes.first())
        .ok_or(WizardError::NoDetectedRuntime)?;

    let label = preset_by_id(&recommended.preset_id)
        .map(|preset| preset.label)
        .unwrap_or_else(|| recommended.preset_id.clone());

    writeln!(output, "Detected runtime: {label}")
        .map_err(|error| WizardError::PromptFailed(error.to_string()))?;
    writeln!(output, "ClawGuard will protect it by default.")
        .map_err(|error| WizardError::PromptFailed(error.to_string()))?;

    Ok(Some(recommended.preset_id.clone()))
}

fn prompt_alert_strategy<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
) -> Result<AlertStrategy, WizardError> {
    writeln!(
        output,
        "Alert channel [Desktop/Webhook/LogOnly] (default: Desktop)"
    )
    .map_err(|error| WizardError::PromptFailed(error.to_string()))?;
    let choice = read_optional_line(input)?;

    Ok(match choice.as_deref() {
        Some("2") | Some("Webhook") | Some("webhook") => AlertStrategy::Webhook,
        Some("3") | Some("LogOnly") | Some("logonly") | Some("log-only") => AlertStrategy::LogOnly,
        _ => AlertStrategy::Desktop,
    })
}

fn prompt_strictness<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
) -> Result<Strictness, WizardError> {
    writeln!(
        output,
        "Strictness [Recommended/Relaxed/Strict] (default: Recommended)"
    )
    .map_err(|error| WizardError::PromptFailed(error.to_string()))?;
    let choice = read_optional_line(input)?;

    Ok(match choice.as_deref() {
        Some("2") | Some("Relaxed") | Some("relaxed") => Strictness::Relaxed,
        Some("3") | Some("Strict") | Some("strict") => Strictness::Strict,
        _ => Strictness::Recommended,
    })
}

fn prompt_webhook_url<R: BufRead, W: Write>(
    alert_strategy: &AlertStrategy,
    input: &mut R,
    output: &mut W,
) -> Result<Option<String>, WizardError> {
    if *alert_strategy != AlertStrategy::Webhook {
        return Ok(None);
    }

    writeln!(
        output,
        "Webhook URL (required for Webhook alerts; must start with http:// or https://)"
    )
    .map_err(|error| WizardError::PromptFailed(error.to_string()))?;
    let Some(url) = read_optional_line(input)? else {
        return Err(WizardError::PromptFailed(
            "webhook alert strategy requires a non-empty webhook URL".to_string(),
        ));
    };

    Ok(Some(url))
}

fn read_optional_line<R: BufRead>(input: &mut R) -> Result<Option<String>, WizardError> {
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|error| WizardError::PromptFailed(error.to_string()))?;

    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}
