//! One Android app, one window.
//!
//! Each open app is a scrcpy process holding a virtual display on the phone.
//! The flags are not decoration — each one fixes something that is wrong by
//! default:
//!
//! * `--new-display` is the whole feature. Without it scrcpy mirrors the
//!   phone's own screen, which is the "desktop in a window" model this service
//!   exists to avoid.
//! * `--no-vd-system-decorations` removes Android's back/home/recents bar.
//!   Android puts it on every display; inside a single-app window it is
//!   navigation to nowhere.
//! * `--display-ime-policy=local` keeps the keyboard in the window. Otherwise
//!   typing here makes the keyboard pop up on the phone.
//! * `--no-vd-destroy-content` means closing the window sends the app back to
//!   the phone instead of killing it mid-task.
//!
//! The daemon owns these processes rather than the panel: it is the one
//! watching udev, so it is the only part that learns about an unplug in time to
//! close the windows properly. Spawned from the panel they would outlive a
//! restart of the shell and leak.

use std::collections::HashMap;
use std::process::Stdio;

use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

use vasak_connect_protocol::Transport;

/// Identifies an open window: one app on one device.
pub type WindowKey = (String, String);

pub struct Window {
    pub label: String,
    pub pid: u32,
    child: Child,
}

#[derive(Debug)]
pub enum SpawnError {
    /// scrcpy is not installed.
    Missing,
    Io(std::io::Error),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::Missing => write!(f, "scrcpy no está instalado"),
            SpawnError::Io(err) => write!(f, "no se pudo iniciar scrcpy: {err}"),
        }
    }
}

/// Every app window currently open, and who they belong to.
#[derive(Default)]
pub struct WindowManager {
    open: HashMap<WindowKey, Window>,
}

impl WindowManager {
    pub fn list(&self) -> impl Iterator<Item = (&WindowKey, &Window)> {
        self.open.iter()
    }

    /// Opens an app in its own window.
    ///
    /// The process is kept here and collected by [`WindowManager::reap`], which
    /// the daemon calls on a timer. Waiting on the child in a task instead
    /// would mean moving it out of the map, and then nothing could close the
    /// window on request.
    pub fn launch(
        &mut self,
        serial: &str,
        package: &str,
        label: &str,
        transport: Transport,
    ) -> Result<u32, SpawnError> {
        let key = (serial.to_string(), package.to_string());
        if let Some(existing) = self.open.get(&key) {
            // Already open: raising it is the compositor's job, not ours, but
            // starting a second copy would create a second virtual display for
            // the same app.
            return Ok(existing.pid);
        }

        let mut command = Command::new("scrcpy");
        command
            .args(["-s", serial])
            .arg("--new-display=1000x700/220")
            .arg("--no-vd-system-decorations")
            .arg("--display-ime-policy=local")
            .arg("--no-vd-destroy-content")
            .arg("--flex-display")
            // `+` force-stops first. An app already running on the phone's own
            // screen otherwise refuses to move to the new display and the
            // window stays black.
            .arg(format!("--start-app=+{package}"))
            .arg(format!("--window-title={label}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        // Over the network the link is both slower and lossier, so the defaults
        // — tuned for USB — produce a stuttering window.
        if transport == Transport::Tcp {
            command
                .arg("--video-codec=h265")
                .arg("--video-bit-rate=4M")
                .arg("--max-fps=30");
        }

        let mut child = command.spawn().map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                SpawnError::Missing
            } else {
                SpawnError::Io(err)
            }
        })?;

        let pid = child.id().unwrap_or(0);
        let stderr = child.stderr.take();
        info!(%serial, %package, pid, "ventana abierta");

        {
            let key = key.clone();
            tokio::spawn(async move {
                if let Some(stderr) = stderr {
                    // scrcpy explains its own failures well; losing that output
                    // is what makes "the window did not open" unanswerable.
                    //
                    // At debug level, though: adb writes its progress here too
                    // ("1 file pushed, 0 skipped"), so treating the stream as
                    // errors turns a normal launch into a warning. A launch
                    // that actually fails is reported by `reap`, which is the
                    // only place that knows the exit status.
                    let mut reader = tokio::io::BufReader::new(stderr);
                    let mut text = String::new();
                    use tokio::io::AsyncReadExt;
                    let _ = reader.read_to_string(&mut text).await;
                    let text = text.trim();
                    if !text.is_empty() {
                        debug!(package = %key.1, "scrcpy: {text}");
                    }
                }
            });
        }

        self.open.insert(
            key,
            Window {
                label: label.to_string(),
                pid,
                child,
            },
        );

        Ok(pid)
    }

    /// Closes one window.
    pub async fn stop(&mut self, serial: &str, package: &str) -> bool {
        let key = (serial.to_string(), package.to_string());
        match self.open.remove(&key) {
            Some(mut window) => {
                let _ = window.child.kill().await;
                info!(%serial, %package, "ventana cerrada");
                true
            }
            None => false,
        }
    }

    /// Closes every window belonging to a device.
    ///
    /// Called when the phone goes away: the processes would die on their own
    /// once scrcpy noticed, but leaving that to a timeout means seconds of
    /// frozen windows the person can still click on.
    pub async fn stop_all(&mut self, serial: &str) -> Vec<String> {
        let keys: Vec<WindowKey> = self
            .open
            .keys()
            .filter(|(device, _)| device == serial)
            .cloned()
            .collect();

        let mut closed = Vec::new();
        for key in keys {
            if let Some(mut window) = self.open.remove(&key) {
                let _ = window.child.kill().await;
                closed.push(key.1);
            }
        }
        if !closed.is_empty() {
            info!(%serial, count = closed.len(), "ventanas cerradas al desconectarse el teléfono");
        }
        closed
    }

    /// Collects windows whose process has ended on its own.
    ///
    /// Returns the ones that were reaped, so the daemon can tell the panel.
    pub fn reap(&mut self) -> Vec<WindowKey> {
        let mut gone = Vec::new();
        self.open.retain(|key, window| match window.child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    warn!(
                        package = %key.1,
                        "scrcpy terminó con {status}; probá `scrcpy -s {} --new-display --start-app={}` a mano para ver por qué",
                        key.0, key.1
                    );
                }
                gone.push(key.clone());
                false
            }
            Ok(None) => true,
            Err(err) => {
                warn!(%err, package = %key.1, "no se pudo consultar el proceso, se descarta");
                gone.push(key.clone());
                false
            }
        });
        gone
    }
}
