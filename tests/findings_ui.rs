use clawguard::scan::{
    Finding, FindingCategory, FindingFix, Fixability, RecommendedAction, RuntimeConfidence,
    ScanResult, Severity,
};
use clawguard::ui::findings::FindingsUiState;

#[test]
fn finding_detail_view_includes_title_explanation_evidence_and_action() {
    let state = FindingsUiState::new(ScanResult::from_batches(vec![vec![sample_finding(
        "config-high",
        "openclaw-config",
        Severity::High,
        FindingCategory::Config,
        "/tmp/openclaw/exec-approvals.json",
        Some("\"ask\": \"off\""),
        "OpenClaw may execute commands without asking for confirmation.",
        "Turn command approvals back on",
    )]]));

    let rendered = state.render();

    assert!(rendered.contains("OpenClaw Configuration Risk"));
    assert!(rendered.contains("Severity: High"));
    assert!(rendered.contains("OpenClaw may execute commands without asking for confirmation."));
    assert!(rendered.contains("\"ask\": \"off\""));
    assert!(rendered.contains("Recommended action"));
    assert!(rendered.contains("Turn command approvals back on"));
}

#[test]
fn summary_view_marks_the_selected_finding() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
        ),
        sample_finding(
            "skill-low",
            "skills",
            Severity::Low,
            FindingCategory::Skills,
            "/tmp/openclaw/skills/risky/SKILL.md",
            Some("curl ... | sh"),
            "This skill downloads and executes remote shell content.",
            "Disable or remove the risky skill",
        ),
    ]]));

    state.show_summary();
    let rendered = state.render();

    assert!(rendered.contains("> [CRITICAL] OpenClaw Advisory"));
    assert!(rendered.contains("  [LOW] Risky Skill Behavior"));
}

#[test]
fn summary_view_lists_findings_in_severity_order() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding(
            "skill-low",
            "skills",
            Severity::Low,
            FindingCategory::Skills,
            "/tmp/openclaw/skills/risky/SKILL.md",
            Some("curl ... | sh"),
            "This skill downloads and executes remote shell content.",
            "Disable or remove the risky skill",
        ),
        sample_finding(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
        ),
        sample_finding(
            "mcp-medium",
            "mcp",
            Severity::Medium,
            FindingCategory::Mcp,
            "/tmp/openclaw/openclaw.json",
            Some("npx @modelcontextprotocol/server-filesystem"),
            "This MCP server launcher may auto-install code at runtime.",
            "Pin the MCP package version",
        ),
    ]]));

    state.show_summary();
    let rendered = state.render();

    assert_before(
        &rendered,
        "[CRITICAL] OpenClaw Advisory",
        "[MEDIUM] MCP Configuration Risk",
    );
    assert_before(
        &rendered,
        "[MEDIUM] MCP Configuration Risk",
        "[LOW] Risky Skill Behavior",
    );
}

#[test]
fn empty_result_renders_reassuring_state() {
    let state = FindingsUiState::new(ScanResult::from_batches(vec![]));

    let rendered = state.render();

    assert!(rendered.contains("No active findings to review right now."));
    assert!(rendered.contains("Your latest ClawGuard scan did not surface any risks."));
}

#[test]
fn advisory_action_renders_command_hint() {
    let state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding_with_hint(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
            "bun update openclaw",
        ),
    ]]));

    let rendered = state.render();

    assert!(rendered.contains("Command hint"));
    assert!(rendered.contains("bun update openclaw"));
}

#[test]
fn fixable_finding_renders_fix_summary() {
    let state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_fixable_finding(),
    ]]));

    let rendered = state.render();

    assert!(rendered.contains("Fix summary"));
    assert!(rendered.contains("Restore the safer command approval mode"));
    assert!(rendered.contains("Reversible: yes"));
}

#[test]
fn derived_titles_are_stable_for_the_same_finding() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![sample_finding(
        "secret-high",
        "secrets",
        Severity::High,
        FindingCategory::Secrets,
        "/tmp/openclaw/.env",
        Some("OPENAI_API_KEY=sk-***"),
        "A literal API key is stored in local runtime state.",
        "Rotate and remove the exposed secret",
    )]]));

    state.show_summary();
    let summary = state.render();
    state.show_details();
    let detail = state.render();

    assert!(summary.contains("Exposed Secret In Local State"));
    assert!(detail.contains("Exposed Secret In Local State"));
}

#[test]
fn selection_can_move_between_visible_findings() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
        ),
        sample_finding(
            "mcp-medium",
            "mcp",
            Severity::Medium,
            FindingCategory::Mcp,
            "/tmp/openclaw/openclaw.json",
            Some("npx @modelcontextprotocol/server-filesystem"),
            "This MCP server launcher may auto-install code at runtime.",
            "Pin the MCP package version",
        ),
        sample_finding(
            "skill-low",
            "skills",
            Severity::Low,
            FindingCategory::Skills,
            "/tmp/openclaw/skills/risky/SKILL.md",
            Some("curl ... | sh"),
            "This skill downloads and executes remote shell content.",
            "Disable or remove the risky skill",
        ),
    ]]));

    state.show_summary();
    state.select_next();
    let after_next = state.render();
    state.select_previous();
    let after_previous = state.render();

    assert!(after_next.contains("> [MEDIUM] MCP Configuration Risk"));
    assert!(after_previous.contains("> [CRITICAL] OpenClaw Advisory"));
}

#[test]
fn ignore_once_hides_the_selected_finding_for_the_session() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
        ),
        sample_finding(
            "skill-low",
            "skills",
            Severity::Low,
            FindingCategory::Skills,
            "/tmp/openclaw/skills/risky/SKILL.md",
            Some("curl ... | sh"),
            "This skill downloads and executes remote shell content.",
            "Disable or remove the risky skill",
        ),
    ]]));

    state.show_summary();
    state.ignore_selected_once();
    let rendered = state.render();

    assert!(!rendered.contains("OpenClaw Advisory"));
    assert!(rendered.contains("Risky Skill Behavior"));
}

#[test]
fn summary_highest_severity_excludes_ignored_findings() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
        ),
        sample_finding(
            "mcp-medium",
            "mcp",
            Severity::Medium,
            FindingCategory::Mcp,
            "/tmp/openclaw/openclaw.json",
            Some("npx @modelcontextprotocol/server-filesystem"),
            "This MCP server launcher may auto-install code at runtime.",
            "Pin the MCP package version",
        ),
    ]]));

    state.show_summary();
    state.ignore_selected_once();
    let rendered = state.render();

    assert!(rendered.contains("Highest severity: Medium"));
    assert!(!rendered.contains("Highest severity: Critical"));
}

#[test]
fn ignoring_a_middle_finding_keeps_selection_on_the_next_visible_finding() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
        ),
        sample_finding(
            "mcp-medium",
            "mcp",
            Severity::Medium,
            FindingCategory::Mcp,
            "/tmp/openclaw/openclaw.json",
            Some("npx @modelcontextprotocol/server-filesystem"),
            "This MCP server launcher may auto-install code at runtime.",
            "Pin the MCP package version",
        ),
        sample_finding(
            "skill-low",
            "skills",
            Severity::Low,
            FindingCategory::Skills,
            "/tmp/openclaw/skills/risky/SKILL.md",
            Some("curl ... | sh"),
            "This skill downloads and executes remote shell content.",
            "Disable or remove the risky skill",
        ),
    ]]));

    state.show_summary();
    state.select_next();
    state.ignore_selected_once();
    let rendered = state.render();

    assert!(rendered.contains("> [LOW] Risky Skill Behavior"));
    assert!(!rendered.contains("MCP Configuration Risk"));
}

#[test]
fn selection_clamps_at_boundaries() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
        ),
        sample_finding(
            "secret-high",
            "secrets",
            Severity::High,
            FindingCategory::Secrets,
            "/tmp/openclaw/.env",
            Some("OPENAI_API_KEY=sk-***"),
            "A literal API key is stored in local runtime state.",
            "Rotate and remove the exposed secret",
        ),
    ]]));

    state.show_summary();
    state.select_previous();
    let first = state.render();
    state.select_next();
    state.select_next();
    let last = state.render();

    assert!(first.contains("> [CRITICAL] OpenClaw Advisory"));
    assert!(last.contains("> [HIGH] Exposed Secret In Local State"));
}

#[test]
fn ignoring_the_last_finding_renders_the_empty_state() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![sample_finding(
        "secret-high",
        "secrets",
        Severity::High,
        FindingCategory::Secrets,
        "/tmp/openclaw/.env",
        Some("OPENAI_API_KEY=sk-***"),
        "A literal API key is stored in local runtime state.",
        "Rotate and remove the exposed secret",
    )]]));

    state.ignore_selected_once();
    let rendered = state.render();

    assert!(rendered.contains("No active findings to review right now."));
}

#[test]
fn detail_view_without_evidence_omits_evidence_section_and_path_line_suffix() {
    let state = FindingsUiState::new(ScanResult::from_batches(vec![vec![Finding {
        line: None,
        evidence: None,
        ..sample_finding(
            "drift-low",
            "drift",
            Severity::Low,
            FindingCategory::Drift,
            "/tmp/openclaw/state-snapshot.json",
            Some("unused"),
            "A local backup artifact does not match the active runtime state.",
            "Review the drift before trusting the state",
        )
    }]]));

    let rendered = state.render();

    assert!(!rendered.contains("\nEvidence\n"));
    assert!(rendered.contains("Path: /tmp/openclaw/state-snapshot.json"));
    assert!(!rendered.contains("Path: /tmp/openclaw/state-snapshot.json:"));
}

#[test]
fn switching_between_summary_and_detail_preserves_valid_selection() {
    let mut state = FindingsUiState::new(ScanResult::from_batches(vec![vec![
        sample_finding(
            "advisory-critical",
            "advisory",
            Severity::Critical,
            FindingCategory::Advisory,
            "/tmp/openclaw/package.json",
            Some("openclaw@1.0.0"),
            "Installed OpenClaw version matches a known vulnerable advisory.",
            "Upgrade OpenClaw immediately",
        ),
        sample_finding(
            "secret-high",
            "secrets",
            Severity::High,
            FindingCategory::Secrets,
            "/tmp/openclaw/.env",
            Some("OPENAI_API_KEY=sk-***"),
            "A literal API key is stored in local runtime state.",
            "Rotate and remove the exposed secret",
        ),
    ]]));

    state.show_summary();
    state.select_next();
    let summary = state.render();
    state.show_details();
    let detail = state.render();
    state.show_summary();
    let summary_again = state.render();

    assert!(summary.contains("> [HIGH] Exposed Secret In Local State"));
    assert!(detail.contains("Exposed Secret In Local State"));
    assert!(summary_again.contains("> [HIGH] Exposed Secret In Local State"));
}

fn sample_finding(
    id: &str,
    detector_id: &str,
    severity: Severity,
    category: FindingCategory,
    path: &str,
    evidence: Option<&str>,
    explanation: &str,
    action_label: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        detector_id: detector_id.to_string(),
        severity,
        category,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: path.to_string(),
        line: Some(1),
        evidence: evidence.map(str::to_string),
        plain_english_explanation: explanation.to_string(),
        recommended_action: RecommendedAction {
            label: action_label.to_string(),
            command_hint: None,
        },
        fixability: Fixability::Manual,
        fix: None,
    }
}

fn sample_finding_with_hint(
    id: &str,
    detector_id: &str,
    severity: Severity,
    category: FindingCategory,
    path: &str,
    evidence: Option<&str>,
    explanation: &str,
    action_label: &str,
    command_hint: &str,
) -> Finding {
    Finding {
        recommended_action: RecommendedAction {
            label: action_label.to_string(),
            command_hint: Some(command_hint.to_string()),
        },
        ..sample_finding(
            id,
            detector_id,
            severity,
            category,
            path,
            evidence,
            explanation,
            action_label,
        )
    }
}

fn sample_fixable_finding() -> Finding {
    Finding {
        fix: Some(FindingFix {
            summary: "Restore the safer command approval mode".to_string(),
            reversible: true,
        }),
        ..sample_finding(
            "config-high",
            "openclaw-config",
            Severity::High,
            FindingCategory::Config,
            "/tmp/openclaw/exec-approvals.json",
            Some("\"ask\": \"off\""),
            "OpenClaw may execute commands without asking for confirmation.",
            "Turn command approvals back on",
        )
    }
}

fn assert_before(haystack: &str, first: &str, second: &str) {
    let first_index = haystack
        .find(first)
        .unwrap_or_else(|| panic!("missing expected fragment: {first}"));
    let second_index = haystack
        .find(second)
        .unwrap_or_else(|| panic!("missing expected fragment: {second}"));

    assert!(
        first_index < second_index,
        "{first:?} should appear before {second:?}"
    );
}
