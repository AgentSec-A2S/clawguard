use assert_cmd::Command;

fn stdout_text(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn help_mentions_product_name() {
    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    let assert = cmd.arg("--help").assert().success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("clawguard"));
    assert!(stdout.contains("scan"));
}

#[test]
fn version_exits_successfully() {
    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    cmd.arg("--version").assert().success();
}

#[test]
fn scan_exits_successfully() {
    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    let assert = cmd.arg("scan").assert().success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("scan not implemented yet"));
}

#[test]
fn no_args_exits_successfully() {
    let mut cmd = Command::cargo_bin("clawguard").unwrap();
    let assert = cmd.assert().success();
    let stdout = stdout_text(&assert);

    assert!(stdout.contains("ClawGuard is not configured yet"));
}
