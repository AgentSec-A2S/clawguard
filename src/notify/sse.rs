use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::state::model::AlertRecord;

const MAX_SSE_CLIENTS: usize = 16;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// An alert event suitable for SSE serialization.
#[derive(Debug, Clone, Serialize)]
pub struct SseAlertEvent {
    pub alert_id: String,
    pub severity: String,
    pub path: String,
    pub explanation: String,
    pub recommended_action: String,
    pub created_at_unix_ms: u64,
}

impl SseAlertEvent {
    pub fn from_alert(alert: &AlertRecord) -> Self {
        Self {
            alert_id: alert.alert_id.clone(),
            severity: severity_slug(&alert.finding.severity),
            path: alert.finding.path.clone(),
            explanation: alert.finding.plain_english_explanation.clone(),
            recommended_action: alert.finding.recommended_action.label.clone(),
            created_at_unix_ms: alert.created_at_unix_ms,
        }
    }
}

/// A digest event suitable for SSE serialization.
#[derive(Debug, Clone, Serialize)]
pub struct SseDigestEvent {
    pub alert_count: usize,
    pub summary: String,
}

/// Events the watch loop sends to the SSE server thread.
#[derive(Debug)]
pub enum SseEvent {
    Alert(SseAlertEvent),
    Digest(SseDigestEvent),
    Shutdown,
}

/// A lightweight SSE HTTP server that runs on a dedicated thread.
///
/// The watch loop thread sends events via a bounded `SyncSender` (non-blocking `try_send`).
/// The server thread owns the `TcpListener`, accepts connections, routes HTTP requests, and
/// manages up to [`MAX_SSE_CLIENTS`] long-lived SSE streams.
pub struct SseServer {
    sender: mpsc::SyncSender<SseEvent>,
    thread: Option<JoinHandle<()>>,
    port: u16,
}

impl SseServer {
    /// Start the SSE server on the given bind address and port.
    ///
    /// Returns an error string if the listener cannot bind.
    pub fn start(bind: &str, port: u16) -> Result<Self, String> {
        let addr = format!("{bind}:{port}");
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("failed to start SSE server on {addr}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to set SSE listener to non-blocking on {addr}: {e}"))?;

        let (sender, receiver) = mpsc::sync_channel::<SseEvent>(256);

        let thread = thread::spawn(move || {
            run_server_loop(listener, receiver);
        });

        Ok(Self {
            sender,
            thread: Some(thread),
            port,
        })
    }

    /// Non-blocking broadcast of an event to all connected SSE clients.
    ///
    /// If the internal channel is full the event is silently dropped so the watch loop
    /// is never blocked by slow consumers.
    pub fn broadcast(&self, event: SseEvent) {
        let _ = self.sender.try_send(event);
    }

    /// The port this server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Gracefully shut down the SSE server and join its thread.
    ///
    /// This first attempts to send a `Shutdown` sentinel. If the channel is full (e.g. after
    /// a burst of events), it drops the sender so the receiver sees `Disconnected` and the
    /// server loop exits on its next drain cycle.
    pub fn shutdown(mut self) {
        let _ = self.sender.try_send(SseEvent::Shutdown);
        // Drop the sender so the server loop sees Disconnected even if the Shutdown
        // sentinel could not be enqueued.
        drop(std::mem::replace(
            &mut self.sender,
            mpsc::sync_channel::<SseEvent>(0).0,
        ));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SseServer {
    fn drop(&mut self) {
        let _ = self.sender.try_send(SseEvent::Shutdown);
        // No join in Drop -- the server thread will exit when the sender is dropped and
        // the receiver sees Disconnected.
    }
}

// ---------------------------------------------------------------------------
// Server loop
// ---------------------------------------------------------------------------

fn run_server_loop(listener: TcpListener, receiver: mpsc::Receiver<SseEvent>) {
    let mut sse_clients: Vec<TcpStream> = Vec::new();
    let mut last_heartbeat = Instant::now();

    loop {
        // 1. Accept new connections (non-blocking).
        accept_connections(&listener, &mut sse_clients);

        // 2. Drain all pending events from the channel.
        loop {
            match receiver.try_recv() {
                Ok(SseEvent::Shutdown) => return,
                Ok(SseEvent::Alert(alert)) => {
                    let data = serde_json::to_string(&alert).unwrap_or_default();
                    let msg = format!("event: alert\ndata: {data}\n\n");
                    broadcast_to_clients(&mut sse_clients, msg.as_bytes());
                }
                Ok(SseEvent::Digest(digest)) => {
                    let data = serde_json::to_string(&digest).unwrap_or_default();
                    let msg = format!("event: digest\ndata: {data}\n\n");
                    broadcast_to_clients(&mut sse_clients, msg.as_bytes());
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }

        // 3. Send periodic heartbeats to keep connections alive and detect dead clients.
        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            broadcast_to_clients(&mut sse_clients, b":heartbeat\n\n");
            last_heartbeat = Instant::now();
        }

        // 4. Sleep briefly to avoid a busy loop.
        thread::sleep(ACCEPT_POLL_INTERVAL);
    }
}

/// Accept pending TCP connections and route each to the appropriate handler.
fn accept_connections(listener: &TcpListener, sse_clients: &mut Vec<TcpStream>) {
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // Set a short read timeout so we can parse the request line without blocking
                // the accept loop indefinitely.
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                handle_connection(stream, sse_clients);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

/// Parse the HTTP request line and route to the right handler.
fn handle_connection(stream: TcpStream, sse_clients: &mut Vec<TcpStream>) {
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    let path = parse_request_path(&request_line);

    match path.as_deref() {
        Some("/stream") => handle_sse_upgrade(stream, sse_clients),
        Some("/health") => handle_json_response(stream, br#"{"ok":true}"#),
        Some("/status") => {
            let body = format!(r#"{{"mode":"sse","clients":{}}}"#, sse_clients.len());
            handle_json_response(stream, body.as_bytes());
        }
        Some("/alerts") => {
            handle_json_response(stream, br#"{"error":"not implemented"}"#);
        }
        _ => handle_not_found(stream),
    }
}

/// Extract the path component from an HTTP request line like `GET /stream HTTP/1.1`.
fn parse_request_path(request_line: &str) -> Option<String> {
    let mut parts = request_line.split_whitespace();
    let _method = parts.next()?;
    let path = parts.next()?;
    Some(path.to_string())
}

/// Promote a connection to a long-lived SSE stream.
fn handle_sse_upgrade(stream: TcpStream, sse_clients: &mut Vec<TcpStream>) {
    if sse_clients.len() >= MAX_SSE_CLIENTS {
        handle_service_unavailable(stream);
        return;
    }

    let mut client = stream;
    let headers = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/event-stream\r\n",
        "Cache-Control: no-cache\r\n",
        "Connection: keep-alive\r\n",
        "Access-Control-Allow-Origin: *\r\n",
        "\r\n",
    );

    if client.write_all(headers.as_bytes()).is_ok() {
        // Switch to non-blocking so broadcast writes detect broken pipes quickly.
        let _ = client.set_nonblocking(true);
        // Clear the read timeout that was set during request parsing.
        let _ = client.set_read_timeout(None);
        sse_clients.push(client);
    }
}

fn handle_json_response(mut stream: TcpStream, body: &[u8]) {
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn handle_not_found(mut stream: TcpStream) {
    let body = br#"{"error":"not found"}"#;
    let response = format!(
        "HTTP/1.1 404 Not Found\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn handle_service_unavailable(mut stream: TcpStream) {
    let body = br#"{"error":"too many SSE clients"}"#;
    let response = format!(
        "HTTP/1.1 503 Service Unavailable\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Write a message to every connected SSE client. Clients that fail to receive the
/// write (broken pipe, connection reset) are removed from the list.
fn broadcast_to_clients(clients: &mut Vec<TcpStream>, message: &[u8]) {
    clients.retain_mut(|client| client.write_all(message).is_ok() && client.flush().is_ok());
}

fn severity_slug(severity: &crate::scan::Severity) -> String {
    match severity {
        crate::scan::Severity::Info => "info".to_string(),
        crate::scan::Severity::Low => "low".to_string(),
        crate::scan::Severity::Medium => "medium".to_string(),
        crate::scan::Severity::High => "high".to_string(),
        crate::scan::Severity::Critical => "critical".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_path_extracts_path_from_http_get() {
        assert_eq!(
            parse_request_path("GET /stream HTTP/1.1\r\n"),
            Some("/stream".to_string())
        );
        assert_eq!(
            parse_request_path("GET /health HTTP/1.1\r\n"),
            Some("/health".to_string())
        );
    }

    #[test]
    fn parse_request_path_returns_none_for_empty_input() {
        assert_eq!(parse_request_path(""), None);
        assert_eq!(parse_request_path("GET"), None);
    }

    #[test]
    fn sse_alert_event_from_alert_maps_all_fields() {
        use crate::scan::{
            FindingCategory, Fixability, RecommendedAction, RuntimeConfidence, Severity,
        };
        use crate::state::model::{AlertRecord, AlertStatus};

        let alert = AlertRecord {
            alert_id: "alert:test:1".to_string(),
            finding_id: "finding:1".to_string(),
            status: AlertStatus::Open,
            created_at_unix_ms: 1_700_000_000_000,
            finding: crate::scan::Finding {
                id: "finding:1".to_string(),
                detector_id: "baseline".to_string(),
                severity: Severity::High,
                category: FindingCategory::Drift,
                runtime_confidence: RuntimeConfidence::ActiveRuntime,
                path: "/tmp/.openclaw/openclaw.json".to_string(),
                line: None,
                evidence: None,
                plain_english_explanation: "Config was modified".to_string(),
                recommended_action: RecommendedAction {
                    label: "Review the change".to_string(),
                    command_hint: None,
                },
                fixability: Fixability::Manual,
                fix: None,
            },
        };

        let event = SseAlertEvent::from_alert(&alert);
        assert_eq!(event.alert_id, "alert:test:1");
        assert_eq!(event.severity, "high");
        assert_eq!(event.path, "/tmp/.openclaw/openclaw.json");
        assert_eq!(event.explanation, "Config was modified");
        assert_eq!(event.recommended_action, "Review the change");
        assert_eq!(event.created_at_unix_ms, 1_700_000_000_000);
    }

    #[test]
    fn sse_alert_event_serializes_to_json() {
        let event = SseAlertEvent {
            alert_id: "a1".to_string(),
            severity: "critical".to_string(),
            path: "/etc/config".to_string(),
            explanation: "Drift detected".to_string(),
            recommended_action: "Review".to_string(),
            created_at_unix_ms: 1_000,
        };
        let json = serde_json::to_string(&event).expect("should serialize");
        assert!(json.contains("\"alert_id\":\"a1\""));
        assert!(json.contains("\"severity\":\"critical\""));
    }

    #[test]
    fn sse_digest_event_serializes_to_json() {
        let event = SseDigestEvent {
            alert_count: 5,
            summary: "5 new alerts".to_string(),
        };
        let json = serde_json::to_string(&event).expect("should serialize");
        assert!(json.contains("\"alert_count\":5"));
        assert!(json.contains("\"summary\":\"5 new alerts\""));
    }
}
