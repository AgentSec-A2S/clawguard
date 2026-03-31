use std::collections::BTreeSet;

use crate::scan::{
    Finding, FindingCategory, Fixability, RuntimeConfidence, ScanMeta, ScanResult, Severity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Summary,
    Detail,
}

#[derive(Debug, Clone)]
pub struct FindingsUiState {
    result: ScanResult,
    selected_index: usize,
    view_mode: ViewMode,
    ignored_ids: BTreeSet<String>,
}

impl FindingsUiState {
    pub fn new(result: ScanResult) -> Self {
        Self {
            result,
            selected_index: 0,
            view_mode: ViewMode::Detail,
            ignored_ids: BTreeSet::new(),
        }
    }

    pub fn render(&self) -> String {
        let visible_findings = self.visible_findings();

        if visible_findings.is_empty() {
            return render_empty_state(&self.result.meta);
        }

        match self.view_mode {
            ViewMode::Summary => self.render_summary(&visible_findings),
            ViewMode::Detail => self.render_detail(&visible_findings),
        }
    }

    pub fn select_next(&mut self) {
        let visible_count = self.visible_findings().len();
        if visible_count == 0 {
            self.selected_index = 0;
            return;
        }

        if self.selected_index + 1 < visible_count {
            self.selected_index += 1;
        }
    }

    pub fn select_previous(&mut self) {
        if self.visible_findings().is_empty() {
            self.selected_index = 0;
            return;
        }

        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn show_details(&mut self) {
        self.view_mode = ViewMode::Detail;
    }

    pub fn show_summary(&mut self) {
        self.view_mode = ViewMode::Summary;
    }

    pub fn ignore_selected_once(&mut self) {
        let Some(selected) = self.selected_finding().map(|finding| finding.id.clone()) else {
            self.selected_index = 0;
            return;
        };

        self.ignored_ids.insert(selected);
        self.normalize_selection();
    }

    fn render_summary(&self, visible_findings: &[&Finding]) -> String {
        let highest = visible_findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .map(severity_title_case)
            .unwrap_or("None");

        let mut lines = vec![
            format!("Findings to review: {}", visible_findings.len()),
            format!("Highest severity: {highest}"),
            String::new(),
        ];

        for (index, finding) in visible_findings.iter().enumerate() {
            let view = FindingView::from_finding(finding);
            let marker = if index == self.selected_index {
                ">"
            } else {
                " "
            };
            lines.push(format!(
                "{marker} [{}] {}",
                severity_badge(finding.severity),
                view.title
            ));

            if !view.summary_context.is_empty() {
                lines.push(format!("    {}", view.summary_context));
            }
        }

        lines.join("\n")
    }

    fn render_detail(&self, visible_findings: &[&Finding]) -> String {
        let selected = visible_findings
            .get(self.selected_index)
            .copied()
            .or_else(|| visible_findings.first().copied())
            .expect("visible findings should never be empty here");
        let view = FindingView::from_finding(selected);

        let mut lines = vec![
            view.title,
            format!("Severity: {}", severity_title_case(selected.severity)),
            format!("Category: {}", category_label(selected.category)),
            format!(
                "Confidence: {}",
                confidence_label(selected.runtime_confidence)
            ),
            format!("Path: {}", view.path_display),
            String::new(),
            "Explanation".to_string(),
            view.explanation,
        ];

        if let Some(evidence) = view.evidence {
            lines.push(String::new());
            lines.push("Evidence".to_string());
            lines.push(evidence.to_string());
        }

        lines.push(String::new());
        lines.push("Recommended action".to_string());
        lines.push(view.action_label);

        if let Some(command_hint) = view.command_hint {
            lines.push(String::new());
            lines.push("Command hint".to_string());
            lines.push(command_hint.to_string());
        }

        lines.push(String::new());
        lines.push(format!(
            "Fixability: {}",
            fixability_label(selected.fixability)
        ));

        if let Some(fix_summary) = view.fix_summary {
            lines.push(String::new());
            lines.push("Fix summary".to_string());
            lines.push(fix_summary.to_string());
            lines.push(format!(
                "Reversible: {}",
                if view.fix_reversible { "yes" } else { "no" }
            ));
        }

        lines.join("\n")
    }

    fn visible_findings(&self) -> Vec<&Finding> {
        self.result
            .findings()
            .iter()
            .filter(|finding| !self.ignored_ids.contains(&finding.id))
            .collect()
    }

    fn selected_finding(&self) -> Option<&Finding> {
        let visible_findings = self.visible_findings();
        visible_findings
            .get(self.selected_index)
            .copied()
            .or_else(|| visible_findings.first().copied())
    }

    fn normalize_selection(&mut self) {
        let visible_count = self.visible_findings().len();
        if visible_count == 0 {
            self.selected_index = 0;
            return;
        }

        if self.selected_index >= visible_count {
            self.selected_index = visible_count - 1;
        }
    }
}

#[derive(Debug, Clone)]
struct FindingView {
    title: String,
    summary_context: String,
    path_display: String,
    explanation: String,
    evidence: Option<String>,
    action_label: String,
    command_hint: Option<String>,
    fix_summary: Option<String>,
    fix_reversible: bool,
}

impl FindingView {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            title: title_for_finding(finding).to_string(),
            summary_context: summary_context(finding),
            path_display: format_path(finding),
            explanation: finding.plain_english_explanation.clone(),
            evidence: finding.evidence.clone(),
            action_label: finding.recommended_action.label.clone(),
            command_hint: finding.recommended_action.command_hint.clone(),
            fix_summary: finding.fix.as_ref().map(|fix| fix.summary.clone()),
            fix_reversible: finding.fix.as_ref().is_some_and(|fix| fix.reversible),
        }
    }
}

fn render_empty_state(meta: &ScanMeta) -> String {
    let mut lines = Vec::new();

    if !meta.runtime_label.is_empty() {
        let root_display = meta
            .runtime_root
            .as_deref()
            .and_then(|r| r.strip_prefix(&dirs::home_dir_string()))
            .map(|suffix| format!("~{suffix}"))
            .or_else(|| meta.runtime_root.clone())
            .unwrap_or_default();

        lines.push(format!(
            "ClawGuard scanned {} at {}",
            meta.runtime_label, root_display
        ));
        lines.push(String::new());

        let mut checked_parts = Vec::new();
        if meta.config_file_count > 0 {
            checked_parts.push(format!(
                "{} config {}",
                meta.config_file_count,
                plural("file", meta.config_file_count)
            ));
        }
        if meta.skill_dir_count > 0 {
            checked_parts.push(format!(
                "{} skill {}",
                meta.skill_dir_count,
                plural("dir", meta.skill_dir_count)
            ));
        }
        if meta.mcp_file_count > 0 {
            checked_parts.push(format!(
                "{} MCP {}",
                meta.mcp_file_count,
                plural("config", meta.mcp_file_count)
            ));
        }
        if meta.env_file_count > 0 {
            checked_parts.push(format!(
                "{} env {}",
                meta.env_file_count,
                plural("file", meta.env_file_count)
            ));
        }

        if !checked_parts.is_empty() {
            lines.push(format!("  Checked: {}", checked_parts.join(", ")));
        }

        if !meta.strictness.is_empty() {
            lines.push(format!("  Strictness: {}", meta.strictness));
        }

        lines.push(String::new());
    }

    lines.push("No findings. Your configuration looks clean.".to_string());

    lines.join("\n")
}

fn plural(word: &str, count: usize) -> String {
    if count == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

mod dirs {
    pub fn home_dir_string() -> String {
        std::env::var("HOME").unwrap_or_default()
    }
}

fn title_for_finding(finding: &Finding) -> &'static str {
    // V0-only discovery special case. Do not add more ID-prefix title rules here;
    // widen the finding model if later tasks need richer detector-owned titles.
    if finding.detector_id == "discovery"
        && finding.id.starts_with("discovery:runtime-not-detected:")
    {
        return "Supported Runtime Not Detected";
    }

    match finding.category {
        FindingCategory::Config => "OpenClaw Configuration Risk",
        FindingCategory::Skills => "Risky Skill Behavior",
        FindingCategory::Mcp => "MCP Configuration Risk",
        FindingCategory::Secrets => "Exposed Secret In Local State",
        FindingCategory::Advisory => "OpenClaw Advisory",
        FindingCategory::Drift => "Unexpected State Drift",
    }
}

fn summary_context(finding: &Finding) -> String {
    let raw_context = finding
        .evidence
        .as_deref()
        .or_else(|| Some(finding.path.as_str()))
        .unwrap_or_default();

    truncate_single_line(raw_context, 72)
}

fn format_path(finding: &Finding) -> String {
    match finding.line {
        Some(line) => format!("{}:{line}", finding.path),
        None => finding.path.clone(),
    }
}

fn truncate_single_line(value: &str, max_len: usize) -> String {
    let single_line = value.replace('\n', " ");

    if single_line.chars().count() <= max_len {
        return single_line;
    }

    let truncated: String = single_line
        .chars()
        .take(max_len.saturating_sub(3))
        .collect();
    format!("{truncated}...")
}

fn category_label(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::Config => "Configuration",
        FindingCategory::Skills => "Skills",
        FindingCategory::Mcp => "MCP",
        FindingCategory::Secrets => "Secrets",
        FindingCategory::Advisory => "Advisory",
        FindingCategory::Drift => "Drift",
    }
}

fn confidence_label(confidence: RuntimeConfidence) -> &'static str {
    match confidence {
        RuntimeConfidence::ActiveRuntime => "Active runtime",
        RuntimeConfidence::OverridePath => "Override path",
        RuntimeConfidence::OptionalLocalState => "Optional local state",
        RuntimeConfidence::TemplateExample => "Template example",
        RuntimeConfidence::BackupArtifact => "Backup artifact",
    }
}

fn fixability_label(fixability: Fixability) -> &'static str {
    match fixability {
        Fixability::AdvisoryOnly => "Advisory only",
        Fixability::Manual => "Manual",
        Fixability::AutoSafe => "Auto-safe",
    }
}

fn severity_badge(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn severity_title_case(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

#[cfg(test)]
mod tests {
    use super::FindingsUiState;
    use crate::scan::{
        Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, ScanResult,
        Severity,
    };

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
            ),
            sample_finding(
                "skill-low",
                "skills",
                Severity::Low,
                FindingCategory::Skills,
                "/tmp/openclaw/skills/risky/SKILL.md",
                Some("curl ... | sh"),
            ),
        ]]));

        state.show_summary();
        state.ignore_selected_once();

        let rendered = state.render();

        assert!(rendered.contains("Highest severity: Low"));
        assert!(!rendered.contains("Highest severity: Critical"));
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
            ),
            sample_finding(
                "skill-low",
                "skills",
                Severity::Low,
                FindingCategory::Skills,
                "/tmp/openclaw/skills/risky/SKILL.md",
                Some("curl ... | sh"),
            ),
        ]]));

        state.show_summary();
        state.select_previous();
        let first = state.render();

        state.select_next();
        state.select_next();
        let last = state.render();

        assert!(first.contains("> [CRITICAL] OpenClaw Advisory"));
        assert!(last.contains("> [LOW] Risky Skill Behavior"));
    }

    #[test]
    fn detail_view_skips_missing_evidence_and_line_suffix() {
        let state = FindingsUiState::new(ScanResult::from_batches(vec![vec![Finding {
            id: "secret-high".to_string(),
            detector_id: "secrets".to_string(),
            severity: Severity::High,
            category: FindingCategory::Secrets,
            runtime_confidence: RuntimeConfidence::ActiveRuntime,
            path: "/tmp/openclaw/.env".to_string(),
            line: None,
            evidence: None,
            plain_english_explanation: "A literal API key is stored in local runtime state."
                .to_string(),
            recommended_action: RecommendedAction {
                label: "Rotate and remove the exposed secret".to_string(),
                command_hint: None,
            },
            fixability: Fixability::Manual,
            fix: None,
            owasp_asi: None,
        }]]));

        let rendered = state.render();

        assert!(rendered.contains("Path: /tmp/openclaw/.env"));
        assert!(!rendered.contains("Path: /tmp/openclaw/.env:"));
        assert!(!rendered.contains("\nEvidence\n"));
    }

    fn sample_finding(
        id: &str,
        detector_id: &str,
        severity: Severity,
        category: FindingCategory,
        path: &str,
        evidence: Option<&str>,
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
            plain_english_explanation: "example explanation".to_string(),
            recommended_action: RecommendedAction {
                label: "example action".to_string(),
                command_hint: None,
            },
            fixability: Fixability::Manual,
            fix: None,
            owasp_asi: None,
        }
    }
}
