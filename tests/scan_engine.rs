use clawguard::scan::{
    Finding, FindingCategory, FindingFix, Fixability, RecommendedAction, RuntimeConfidence,
    ScanResult, Severity,
};

#[test]
fn aggregated_scan_result_reports_highest_severity_and_total_findings() {
    let result = ScanResult::from_batches(vec![
        vec![sample_finding(
            "finding-config-1",
            "openclaw-config",
            Severity::High,
            FindingCategory::Config,
            RuntimeConfidence::ActiveRuntime,
            "Review command approval settings",
        )],
        vec![
            sample_finding(
                "finding-skills-1",
                "skills",
                Severity::Medium,
                FindingCategory::Skills,
                RuntimeConfidence::ActiveRuntime,
                "Disable the risky skill",
            ),
            sample_finding(
                "finding-advisory-1",
                "advisory",
                Severity::Critical,
                FindingCategory::Advisory,
                RuntimeConfidence::ActiveRuntime,
                "Upgrade OpenClaw immediately",
            ),
        ],
    ]);

    assert_eq!(result.finding_count(), 3);
    assert_eq!(result.highest_severity(), Some(Severity::Critical));
    assert_eq!(result.findings()[0].severity, Severity::Critical);
}

#[test]
fn machine_readable_scan_output_preserves_confidence_and_recommended_action() {
    let result = ScanResult::from_batches(vec![vec![Finding {
        id: "finding-config-1".to_string(),
        detector_id: "openclaw-config".to_string(),
        severity: Severity::High,
        category: FindingCategory::Config,
        runtime_confidence: RuntimeConfidence::ActiveRuntime,
        path: "/tmp/openclaw/exec-approvals.json".to_string(),
        line: Some(1),
        evidence: Some("\"ask\": \"off\"".to_string()),
        plain_english_explanation: "OpenClaw may execute commands without asking for confirmation."
            .to_string(),
        recommended_action: RecommendedAction {
            label: "Turn command approvals back on".to_string(),
            command_hint: Some("Review and re-enable exec approvals".to_string()),
        },
        fixability: Fixability::Manual,
        fix: Some(FindingFix {
            summary: "Restore the safer command approval mode".to_string(),
            reversible: true,
        }),
    }]]);

    let report = result
        .to_json()
        .expect("scan results should serialize to JSON");
    let json: serde_json::Value =
        serde_json::from_str(&report).expect("serialized JSON should parse");

    assert_eq!(json["summary"]["total_findings"], 1);
    assert_eq!(json["summary"]["highest_severity"], "high");
    assert_eq!(json["findings"][0]["id"], "finding-config-1");
    assert_eq!(json["findings"][0]["runtime_confidence"], "active_runtime");
    assert_eq!(
        json["findings"][0]["recommended_action"]["label"],
        "Turn command approvals back on"
    );
    assert_eq!(json["findings"][0]["fixability"], "manual");
}

#[test]
fn empty_scan_result_reports_no_findings_and_serializes_cleanly() {
    let result = ScanResult::from_batches(vec![]);

    assert_eq!(result.finding_count(), 0);
    assert_eq!(result.highest_severity(), None);

    let json = result
        .to_json()
        .expect("empty scan results should serialize to JSON");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("json should parse");

    assert_eq!(parsed["summary"]["total_findings"], 0);
    assert_eq!(
        parsed["summary"]["highest_severity"],
        serde_json::Value::Null
    );
    assert_eq!(
        parsed["findings"]
            .as_array()
            .expect("findings should serialize as an array")
            .len(),
        0
    );
}

fn sample_finding(
    id: &str,
    detector_id: &str,
    severity: Severity,
    category: FindingCategory,
    runtime_confidence: RuntimeConfidence,
    action_label: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        detector_id: detector_id.to_string(),
        severity,
        category,
        runtime_confidence,
        path: format!("/tmp/fixtures/{detector_id}.txt"),
        line: Some(1),
        evidence: Some("example evidence".to_string()),
        plain_english_explanation: "example explanation".to_string(),
        recommended_action: RecommendedAction {
            label: action_label.to_string(),
            command_hint: None,
        },
        fixability: Fixability::AdvisoryOnly,
        fix: None,
    }
}
