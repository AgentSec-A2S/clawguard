use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use clawguard::notify::sse::{SseAlertEvent, SseDigestEvent, SseEvent, SseServer};
use clawguard::scan::{
    Finding, FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity,
};
use clawguard::state::model::{AlertRecord, AlertStatus};

/// Find an available TCP port by binding to port 0 and reading the assigned port.
fn available_port() -> u16 {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("should bind to an ephemeral port");
    listener
        .local_addr()
        .expect("should have a local address")
        .port()
}

/// Connect to the SSE /stream endpoint and return the stream positioned after the HTTP
/// headers so callers can read SSE event lines directly.
fn connect_sse_stream(port: u16) -> TcpStream {
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{port}")).expect("should connect to SSE server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("should set read timeout");
    stream
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("should send request");
    stream.flush().expect("should flush");

    // Consume the HTTP response headers up to the blank line.
    let mut reader = BufReader::new(&stream);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("should read header");
        if line == "\r\n" {
            break;
        }
    }

    stream
}

/// Send a GET request to the given path and return the full response body.
fn get_json(port: u16, path: &str) -> String {
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{port}")).expect("should connect to SSE server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("should set read timeout");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("should send request");
    stream.flush().expect("should flush");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("should read response");
    response
}

/// Extract the body from a raw HTTP response string (everything after the blank line).
fn extract_body(raw: &str) -> &str {
    if let Some(idx) = raw.find("\r\n\r\n") {
        &raw[idx + 4..]
    } else {
        raw
    }
}

fn sample_alert(
    alert_id: &str,
    status: AlertStatus,
    created_at_unix_ms: u64,
    path: &str,
) -> AlertRecord {
    AlertRecord {
        alert_id: alert_id.to_string(),
        finding_id: format!("finding:{alert_id}"),
        status,
        created_at_unix_ms,
        finding: Finding {
            id: format!("baseline:modified:{path}"),
            detector_id: "baseline".to_string(),
            severity: Severity::High,
            category: FindingCategory::Drift,
            runtime_confidence: RuntimeConfidence::ActiveRuntime,
            path: path.to_string(),
            line: None,
            evidence: None,
            plain_english_explanation: "Config drift detected".to_string(),
            recommended_action: RecommendedAction {
                label: "Review the config".to_string(),
                command_hint: None,
            },
            fixability: Fixability::Manual,
            fix: None,
            owasp_asi: None,
        },
    }
}

#[test]
fn health_endpoint_returns_ok() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");

    // Give the server thread a moment to begin listening.
    thread::sleep(Duration::from_millis(50));

    let response = get_json(port, "/health");
    let body = extract_body(&response);
    assert!(
        response.contains("200 OK"),
        "health endpoint should return HTTP 200"
    );
    assert!(
        body.contains(r#""ok":true"#),
        "health response body should contain ok:true, got: {body}"
    );

    server.shutdown();
}

#[test]
fn status_endpoint_returns_client_count() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let response = get_json(port, "/status");
    let body = extract_body(&response);
    assert!(
        body.contains(r#""mode":"sse""#),
        "status response should include mode:sse, got: {body}"
    );
    assert!(
        body.contains(r#""clients":"#),
        "status response should include client count, got: {body}"
    );

    server.shutdown();
}

#[test]
fn alerts_endpoint_defaults_to_recent_open_alerts() {
    let port = available_port();
    let server = SseServer::start_with_recent_alerts(
        "127.0.0.1",
        port,
        vec![
            sample_alert(
                "alert-open-newest",
                AlertStatus::Open,
                1_764_000_003_000,
                "/tmp/openclaw.json",
            ),
            sample_alert(
                "alert-ack",
                AlertStatus::Acknowledged,
                1_764_000_002_000,
                "/tmp/exec-approvals.json",
            ),
            sample_alert(
                "alert-resolved",
                AlertStatus::Resolved,
                1_764_000_001_000,
                "/tmp/old-skill/SKILL.md",
            ),
            sample_alert(
                "alert-open-older",
                AlertStatus::Open,
                1_764_000_000_000,
                "/tmp/.env",
            ),
        ],
    )
    .expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let response = get_json(port, "/alerts");
    let body = extract_body(&response);
    let parsed: serde_json::Value =
        serde_json::from_str(body).expect("alerts endpoint should return valid json");
    let alerts = parsed
        .as_array()
        .expect("alerts endpoint should return a JSON array");

    assert!(
        response.contains("200 OK"),
        "alerts endpoint should return HTTP 200, got: {response}"
    );
    assert_eq!(
        alerts.len(),
        2,
        "default alerts view should include only recent open alerts, got: {body}"
    );
    assert_eq!(alerts[0]["alert_id"].as_str(), Some("alert-open-newest"));
    assert_eq!(alerts[1]["alert_id"].as_str(), Some("alert-open-older"));
    assert!(
        alerts
            .iter()
            .all(|alert| alert["status"].as_str() == Some("open")),
        "default alerts view should exclude acknowledged and resolved history, got: {body}"
    );

    server.shutdown();
}

#[test]
fn alerts_endpoint_honors_status_and_limit_queries() {
    let port = available_port();
    let server = SseServer::start_with_recent_alerts(
        "127.0.0.1",
        port,
        vec![
            sample_alert(
                "alert-open-newest",
                AlertStatus::Open,
                1_764_000_003_000,
                "/tmp/openclaw.json",
            ),
            sample_alert(
                "alert-ack",
                AlertStatus::Acknowledged,
                1_764_000_002_000,
                "/tmp/exec-approvals.json",
            ),
            sample_alert(
                "alert-resolved",
                AlertStatus::Resolved,
                1_764_000_001_000,
                "/tmp/old-skill/SKILL.md",
            ),
        ],
    )
    .expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let response = get_json(port, "/alerts?status=all&limit=2");
    let body = extract_body(&response);
    let alerts: serde_json::Value =
        serde_json::from_str(body).expect("alerts endpoint should return valid json");
    let alerts = alerts
        .as_array()
        .expect("alerts endpoint should return a JSON array");

    assert!(
        response.contains("200 OK"),
        "alerts endpoint should still resolve with query params, got: {response}"
    );
    assert_eq!(
        alerts.len(),
        2,
        "limit query should cap the result length, got: {body}"
    );
    assert_eq!(alerts[0]["alert_id"].as_str(), Some("alert-open-newest"));
    assert_eq!(alerts[1]["alert_id"].as_str(), Some("alert-ack"));

    server.shutdown();
}

#[test]
fn alerts_endpoint_invalid_queries_fall_back_to_default_open_view() {
    let port = available_port();
    let server = SseServer::start_with_recent_alerts(
        "127.0.0.1",
        port,
        vec![
            sample_alert(
                "alert-open-newest",
                AlertStatus::Open,
                1_764_000_003_000,
                "/tmp/openclaw.json",
            ),
            sample_alert(
                "alert-ack",
                AlertStatus::Acknowledged,
                1_764_000_002_000,
                "/tmp/exec-approvals.json",
            ),
        ],
    )
    .expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let response = get_json(port, "/alerts?status=unknown&limit=not-a-number");
    let body = extract_body(&response);
    let alerts: serde_json::Value =
        serde_json::from_str(body).expect("alerts endpoint should return valid json");
    let alerts = alerts
        .as_array()
        .expect("alerts endpoint should return a JSON array");

    assert_eq!(
        alerts.len(),
        1,
        "invalid query params should fall back to the default open-alert view, got: {body}"
    );
    assert_eq!(alerts[0]["alert_id"].as_str(), Some("alert-open-newest"));

    server.shutdown();
}

#[test]
fn alerts_endpoint_includes_newly_broadcast_open_alerts() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    server.broadcast(SseEvent::Alert(SseAlertEvent {
        alert_id: "alert-live".to_string(),
        severity: "high".to_string(),
        path: "/tmp/openclaw.json".to_string(),
        explanation: "Live drift detected".to_string(),
        recommended_action: "Review the config".to_string(),
        created_at_unix_ms: 1_764_000_004_000,
    }));
    thread::sleep(Duration::from_millis(300));

    let response = get_json(port, "/alerts?limit=10");
    let body = extract_body(&response);
    let alerts: serde_json::Value =
        serde_json::from_str(body).expect("alerts endpoint should return valid json");
    let alerts = alerts
        .as_array()
        .expect("alerts endpoint should return a JSON array");

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["alert_id"].as_str(), Some("alert-live"));
    assert_eq!(alerts[0]["status"].as_str(), Some("open"));

    server.shutdown();
}

#[test]
fn known_routes_ignore_query_strings() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let response = get_json(port, "/health?probe=1");
    let body = extract_body(&response);

    assert!(
        response.contains("200 OK"),
        "health endpoint should still return HTTP 200 when a query string is present"
    );
    assert!(
        body.contains(r#""ok":true"#),
        "health endpoint should still return the health payload, got: {body}"
    );

    server.shutdown();
}

#[test]
fn unknown_path_returns_404() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let response = get_json(port, "/nonexistent?limit=10");
    assert!(
        response.contains("404"),
        "unknown paths should still return HTTP 404 when a query string is present, got: {response}"
    );

    server.shutdown();
}

#[test]
fn sse_stream_receives_alert_event() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let stream = connect_sse_stream(port);
    // Give the server loop time to register the client.
    thread::sleep(Duration::from_millis(200));

    server.broadcast(SseEvent::Alert(SseAlertEvent {
        alert_id: "alert:sse:1".to_string(),
        severity: "high".to_string(),
        path: "/tmp/.openclaw/config.json".to_string(),
        explanation: "Config drift detected".to_string(),
        recommended_action: "Review the config".to_string(),
        created_at_unix_ms: 1_700_000_000_000,
    }));

    // Give the server loop time to broadcast.
    thread::sleep(Duration::from_millis(300));

    // Read what was sent.
    let mut reader = BufReader::new(&stream);
    let mut collected = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                collected.push_str(&line);
                // SSE events are terminated by a double newline. Once we see
                // the data line, the next blank line terminates the event.
                if collected.contains("alert:sse:1") && line.trim().is_empty() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    assert!(
        collected.contains("event: alert"),
        "SSE stream should contain the alert event type, got: {collected}"
    );
    assert!(
        collected.contains("alert:sse:1"),
        "SSE stream should contain the alert ID, got: {collected}"
    );
    assert!(
        collected.contains("Config drift detected"),
        "SSE stream should contain the explanation, got: {collected}"
    );

    server.shutdown();
}

#[test]
fn sse_stream_receives_digest_event() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let stream = connect_sse_stream(port);
    thread::sleep(Duration::from_millis(200));

    server.broadcast(SseEvent::Digest(SseDigestEvent {
        alert_count: 3,
        summary: "3 new alerts since last digest".to_string(),
    }));

    thread::sleep(Duration::from_millis(300));

    let mut reader = BufReader::new(&stream);
    let mut collected = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                collected.push_str(&line);
                if collected.contains("3 new alerts") && line.trim().is_empty() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    assert!(
        collected.contains("event: digest"),
        "SSE stream should contain the digest event type, got: {collected}"
    );
    assert!(
        collected.contains("3 new alerts"),
        "SSE stream should contain the digest summary, got: {collected}"
    );

    server.shutdown();
}

#[test]
fn broadcast_is_non_blocking_when_channel_is_full() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");

    // Flood the channel with 300 events (capacity is 256). This must not block.
    for i in 0..300 {
        server.broadcast(SseEvent::Alert(SseAlertEvent {
            alert_id: format!("alert:flood:{i}"),
            severity: "info".to_string(),
            path: "/tmp/test".to_string(),
            explanation: "test".to_string(),
            recommended_action: "none".to_string(),
            created_at_unix_ms: 0,
        }));
    }

    // If we get here without blocking, the non-blocking guarantee holds.
    // shutdown() drops the sender so the server loop exits on Disconnected even when
    // the channel is too full for the Shutdown sentinel.
    server.shutdown();
}

#[test]
fn status_endpoint_reflects_connected_sse_clients() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    // Before any SSE clients connect
    let response = get_json(port, "/status");
    let body = extract_body(&response);
    assert!(
        body.contains(r#""clients":0"#),
        "status should show 0 clients before any connect, got: {body}"
    );

    // Connect an SSE client
    let _stream = connect_sse_stream(port);
    // Give the server loop time to register the client.
    thread::sleep(Duration::from_millis(300));

    let response = get_json(port, "/status");
    let body = extract_body(&response);
    assert!(
        body.contains(r#""clients":1"#),
        "status should show 1 client after connecting, got: {body}"
    );

    server.shutdown();
}

#[test]
fn server_survives_client_disconnect() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    // Connect and immediately disconnect.
    {
        let _stream = connect_sse_stream(port);
    }
    // Give the server time to detect the disconnect during the next broadcast.
    thread::sleep(Duration::from_millis(200));

    // Broadcast an event -- this should not panic even though the client disconnected.
    server.broadcast(SseEvent::Alert(SseAlertEvent {
        alert_id: "alert:after-disconnect".to_string(),
        severity: "low".to_string(),
        path: "/tmp/test".to_string(),
        explanation: "test".to_string(),
        recommended_action: "none".to_string(),
        created_at_unix_ms: 0,
    }));

    // Give the broadcast time to execute.
    thread::sleep(Duration::from_millis(200));

    // The health endpoint should still work.
    let response = get_json(port, "/health");
    assert!(
        response.contains("200 OK"),
        "server should remain healthy after client disconnect"
    );

    server.shutdown();
}

#[test]
fn shutdown_terminates_the_server_thread() {
    let port = available_port();
    let server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    server.shutdown();

    // After shutdown, connecting should fail.
    thread::sleep(Duration::from_millis(200));
    let result = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    );
    assert!(
        result.is_err(),
        "connections should be refused after server shutdown"
    );
}

#[test]
fn sse_stream_does_not_include_wildcard_cors_header() {
    let port = available_port();
    let _server = SseServer::start("127.0.0.1", port).expect("server should start");
    thread::sleep(Duration::from_millis(50));

    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{port}")).expect("should connect to SSE server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("should set read timeout");
    stream
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("should send request");
    stream.flush().expect("should flush");

    let mut headers = String::new();
    let mut reader = BufReader::new(&stream);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("should read header");
        if line == "\r\n" {
            break;
        }
        headers.push_str(&line);
    }

    assert!(
        !headers.contains("Access-Control-Allow-Origin"),
        "SSE stream should not include CORS header, got: {headers}"
    );
}
