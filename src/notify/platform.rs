use std::env;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopNotifierKind {
    Osascript,
    NotifySend,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopNotification {
    pub kind: DesktopNotifierKind,
    pub title: String,
    pub body: String,
}

pub trait DesktopNotifier {
    fn notify(&self, notification: DesktopNotification) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct CommandDesktopNotifier;

impl DesktopNotifier for CommandDesktopNotifier {
    fn notify(&self, notification: DesktopNotification) -> Result<(), String> {
        match notification.kind {
            DesktopNotifierKind::Osascript => run_osascript_notification(&notification),
            DesktopNotifierKind::NotifySend => run_notify_send_notification(&notification),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlatformSnapshot {
    pub target_os: String,
    pub ssh_session: bool,
    pub container_like: bool,
    pub display_available: bool,
    pub wayland_available: bool,
    pub osascript_on_path: bool,
    pub notify_send_on_path: bool,
}

impl PlatformSnapshot {
    pub fn detect() -> Self {
        Self {
            target_os: env::consts::OS.to_string(),
            ssh_session: env::var_os("SSH_CONNECTION").is_some()
                || env::var_os("SSH_TTY").is_some(),
            container_like: env::var_os("container").is_some()
                || PathBuf::from("/.dockerenv").exists()
                || PathBuf::from("/run/.containerenv").exists(),
            display_available: env::var_os("DISPLAY").is_some(),
            wayland_available: env::var_os("WAYLAND_DISPLAY").is_some(),
            osascript_on_path: command_on_path("osascript"),
            notify_send_on_path: command_on_path("notify-send"),
        }
    }

    pub fn desktop_notifier_kind(&self) -> Option<DesktopNotifierKind> {
        if self.ssh_session || self.container_like {
            return None;
        }

        match self.target_os.as_str() {
            "macos" if self.osascript_on_path => Some(DesktopNotifierKind::Osascript),
            "linux"
                if (self.display_available || self.wayland_available)
                    && self.notify_send_on_path =>
            {
                Some(DesktopNotifierKind::NotifySend)
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum PlatformNotifyError {
    Launch(String),
    Exit(String),
}

impl Display for PlatformNotifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Launch(message) | Self::Exit(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for PlatformNotifyError {}

const OSASCRIPT_NOTIFICATION_SCRIPT: [&str; 3] = [
    "on run argv",
    "display notification (item 1 of argv) with title (item 2 of argv)",
    "end run",
];

fn run_osascript_notification(notification: &DesktopNotification) -> Result<(), String> {
    let output = Command::new("osascript")
        .args(osascript_invocation_args(notification))
        .output()
        .map_err(|error| {
            PlatformNotifyError::Launch(format!("failed to run osascript notifier: {error}"))
                .to_string()
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(PlatformNotifyError::Exit(format!(
            "osascript notifier exited with status {}",
            output.status
        ))
        .to_string())
    }
}

fn osascript_invocation_args(notification: &DesktopNotification) -> Vec<String> {
    vec![
        "-e".to_string(),
        OSASCRIPT_NOTIFICATION_SCRIPT[0].to_string(),
        "-e".to_string(),
        OSASCRIPT_NOTIFICATION_SCRIPT[1].to_string(),
        "-e".to_string(),
        OSASCRIPT_NOTIFICATION_SCRIPT[2].to_string(),
        "--".to_string(),
        notification.body.clone(),
        notification.title.clone(),
    ]
}

fn run_notify_send_notification(notification: &DesktopNotification) -> Result<(), String> {
    let output = Command::new("notify-send")
        .arg(&notification.title)
        .arg(&notification.body)
        .output()
        .map_err(|error| {
            PlatformNotifyError::Launch(format!("failed to run notify-send notifier: {error}"))
                .to_string()
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(PlatformNotifyError::Exit(format!(
            "notify-send notifier exited with status {}",
            output.status
        ))
        .to_string())
    }
}

fn command_on_path(command: &str) -> bool {
    let Some(path_value) = env::var_os("PATH") else {
        return false;
    };

    env::split_paths(&path_value).any(|directory| directory.join(command).is_file())
}

#[cfg(test)]
mod tests {
    use super::{
        osascript_invocation_args, DesktopNotification, DesktopNotifierKind,
        OSASCRIPT_NOTIFICATION_SCRIPT,
    };

    #[test]
    fn osascript_invocation_keeps_notification_text_out_of_script_source() {
        let notification = DesktopNotification {
            kind: DesktopNotifierKind::Osascript,
            title: "\" & do shell script \"id\" & \"".to_string(),
            body: "/tmp/openclaw.json\nline two".to_string(),
        };

        let args = osascript_invocation_args(&notification);

        assert_eq!(
            &args[..6],
            &[
                "-e".to_string(),
                OSASCRIPT_NOTIFICATION_SCRIPT[0].to_string(),
                "-e".to_string(),
                OSASCRIPT_NOTIFICATION_SCRIPT[1].to_string(),
                "-e".to_string(),
                OSASCRIPT_NOTIFICATION_SCRIPT[2].to_string(),
            ],
            "AppleScript source should stay static and should not inline untrusted text"
        );
        assert_eq!(args[6], "--");
        assert_eq!(args[7], notification.body);
        assert_eq!(args[8], notification.title);
    }
}
