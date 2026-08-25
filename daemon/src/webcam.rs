//! The phone's camera as an ordinary webcam.
//!
//! scrcpy can already read a phone camera and write raw frames into a V4L2
//! device; this module is the part that makes it usable without a terminal:
//! find the loopback device, ask the phone what its cameras can do, and keep
//! exactly one stream alive.
//!
//! Three things shape the design.
//!
//! **The loopback device is found by name, not by number.** `/dev/video0` is
//! whatever the kernel probed first — on a laptop that is the built-in webcam,
//! and writing there would be writing over a real device. The module is loaded
//! with a known `card_label` and looked up through sysfs, so the number can be
//! anything.
//!
//! **The module is not loaded here.** `modprobe` needs root and this is a user
//! service on the session bus; asking for a polkit prompt to start a webcam
//! would be worse than the problem. The package ships a `modules-load.d` entry
//! instead, and `exclusive_caps=1` keeps the device from advertising itself as
//! a camera until something is actually writing to it — so browsers do not
//! offer a dead device in their camera list.
//!
//! **One stream at a time.** A V4L2 device accepts a single producer. Starting
//! a second phone would not add a camera, it would corrupt the first, so the
//! bridge is a singleton and says so.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use vasak_connect_protocol::{Camera, CameraFacing, WebcamState, WEBCAM_CARD_LABEL};

/// Where the kernel publishes the name of every video device.
const V4L2_CLASS: &str = "/sys/class/video4linux";

/// Enumerating camera sizes makes the phone query every sensor mode. It is
/// slower than it looks — several seconds on the test device — and a timeout
/// here shows up as a camera picker that never fills.
const LIST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum WebcamError {
    /// scrcpy is not installed.
    Missing,
    /// No v4l2loopback device with our label. The module is not loaded, or a
    /// kernel update replaced the running kernel's modules and nobody rebooted.
    NoLoopback,
    /// Already streaming, and a V4L2 device takes one producer.
    Busy,
    TimedOut,
    Failed(String),
    Io(std::io::Error),
}

impl std::fmt::Display for WebcamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebcamError::Missing => write!(f, "scrcpy no está instalado"),
            WebcamError::NoLoopback => write!(
                f,
                "no hay un dispositivo de bucle de vídeo: falta cargar el módulo \
                 v4l2loopback (si acabás de actualizar el kernel, reiniciá)"
            ),
            WebcamError::Busy => write!(
                f,
                "la cámara ya está en uso: un dispositivo de vídeo admite una sola fuente"
            ),
            WebcamError::TimedOut => write!(f, "el teléfono no respondió a tiempo"),
            WebcamError::Failed(msg) => write!(f, "scrcpy falló: {msg}"),
            WebcamError::Io(err) => write!(f, "no se pudo ejecutar scrcpy: {err}"),
        }
    }
}

impl From<std::io::Error> for WebcamError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::NotFound {
            WebcamError::Missing
        } else {
            WebcamError::Io(err)
        }
    }
}

/// The loopback device this service writes into, or `None` if the module is
/// not loaded.
///
/// Read fresh every time rather than cached at startup: the module can be
/// loaded after the service, and a cached `None` would mean the feature stays
/// broken until the session restarts.
pub fn loopback_device() -> Option<PathBuf> {
    let entries = std::fs::read_dir(V4L2_CLASS).ok()?;
    let mut found: Vec<String> = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("video") {
            continue;
        }
        let Ok(label) = std::fs::read_to_string(entry.path().join("name")) else {
            continue;
        };
        // The kernel pads the label out of the module parameter as given, so
        // compare trimmed: a trailing newline is always there.
        if label.trim() == WEBCAM_CARD_LABEL {
            found.push(name);
        }
    }

    // Sorted so that a machine which somehow ended up with two of them picks
    // the same one on every call instead of alternating with readdir order.
    found.sort();
    let name = found.first()?;
    Some(PathBuf::from("/dev").join(name))
}

/// Parses the camera block of `scrcpy --list-camera-sizes`.
///
/// The output looks like this, and both halves matter — the header line has the
/// facing and the frame rates, the indented lines have the sizes:
///
/// ```text
///     --camera-id=0    (back, 4096x3072, fps={10, 15, 20, 30, 60}, zoom-range=[1, 8])
///         - 4096x3072
///         - 4096x2304
/// ```
///
/// Anything that does not match is skipped rather than treated as an error:
/// scrcpy prints its own banner and adb's push progress into the same stream,
/// and a parser that rejects unexpected lines would break on the next release
/// that adds one.
pub fn parse_cameras(output: &str) -> Vec<Camera> {
    let mut cameras: Vec<Camera> = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("--camera-id=") {
            // `0    (back, 4096x3072, fps={10, 15, 20, 30, 60}, ...)`
            let mut parts = rest.splitn(2, '(');
            let id = parts.next().unwrap_or("").trim().to_string();
            if id.is_empty() {
                continue;
            }
            let detail = parts.next().unwrap_or("");

            let facing = detail
                .split(',')
                .next()
                .map(CameraFacing::parse)
                .unwrap_or(CameraFacing::External);

            let fps = detail
                .split_once("fps={")
                .and_then(|(_, tail)| tail.split_once('}'))
                .map(|(list, _)| {
                    list.split(',')
                        .filter_map(|n| n.trim().parse::<u32>().ok())
                        .collect::<Vec<u32>>()
                })
                .unwrap_or_default();

            cameras.push(Camera {
                id,
                facing,
                sizes: Vec::new(),
                fps,
            });
            continue;
        }

        // `- 1280x720`, which belongs to the camera whose header came last.
        if let Some(size) = trimmed.strip_prefix("- ") {
            let size = size.trim();
            if is_size(size) {
                if let Some(camera) = cameras.last_mut() {
                    camera.sizes.push(size.to_string());
                }
            }
        }
    }

    cameras
}

/// Whether a token is a `WIDTHxHEIGHT` pair.
///
/// Checked rather than assumed: the sizes feed straight into a scrcpy argument,
/// and a stray word from a future release would become an unparseable flag.
fn is_size(text: &str) -> bool {
    match text.split_once('x') {
        Some((w, h)) => {
            !w.is_empty()
                && !h.is_empty()
                && w.bytes().all(|b| b.is_ascii_digit())
                && h.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Asks a phone what its cameras are.
pub async fn list_cameras(serial: &str) -> Result<Vec<Camera>, WebcamError> {
    debug!(%serial, "consultando cámaras");

    let call = Command::new("scrcpy")
        .args(["-s", serial, "--list-camera-sizes"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();

    let output = match timeout(LIST_TIMEOUT, call).await {
        Ok(result) => result?,
        Err(_) => return Err(WebcamError::TimedOut),
    };

    if !output.status.success() {
        let msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(WebcamError::Failed(if msg.is_empty() {
            format!("código {}", output.status)
        } else {
            msg
        }));
    }

    // scrcpy prints the camera list on stdout; the server's own log lines land
    // there too, which is why the parser ignores what it does not recognise.
    Ok(parse_cameras(&String::from_utf8_lossy(&output.stdout)))
}

struct Running {
    serial: String,
    camera_id: String,
    size: String,
    child: Child,
}

/// The single camera stream, if there is one.
#[derive(Default)]
pub struct WebcamBridge {
    running: Option<Running>,
}

impl WebcamBridge {
    /// What to report over D-Bus.
    ///
    /// The loopback path is filled in even when nothing is streaming, so a
    /// settings screen can grey the control out and explain why instead of
    /// letting somebody press a button that cannot work.
    pub fn state(&self) -> WebcamState {
        let device = loopback_device()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();

        match &self.running {
            Some(running) => WebcamState {
                active: true,
                device,
                serial: running.serial.clone(),
                camera_id: running.camera_id.clone(),
                size: running.size.clone(),
            },
            None => WebcamState {
                active: false,
                device,
                serial: String::new(),
                camera_id: String::new(),
                size: String::new(),
            },
        }
    }

    /// Which phone is feeding the bridge, if any.
    pub fn serial(&self) -> Option<&str> {
        self.running.as_ref().map(|running| running.serial.as_str())
    }

    /// Starts writing a phone camera into the loopback device.
    ///
    /// `size` may be empty, in which case the phone picks. Passing a size the
    /// sensor does not support is the usual way this fails, so callers should
    /// take it from [`list_cameras`] rather than from a list of common
    /// resolutions.
    pub fn start(
        &mut self,
        serial: &str,
        camera_id: &str,
        size: &str,
        fps: u32,
    ) -> Result<String, WebcamError> {
        if self.running.is_some() {
            return Err(WebcamError::Busy);
        }

        let device = loopback_device().ok_or(WebcamError::NoLoopback)?;
        let device = device.to_string_lossy().into_owned();

        let mut command = Command::new("scrcpy");
        command
            .args(["-s", serial])
            // Read the camera instead of the screen. Without this scrcpy
            // mirrors the display, which is a different feature entirely.
            .arg("--video-source=camera")
            .arg(format!("--camera-id={camera_id}"))
            .arg(format!("--v4l2-sink={device}"))
            // No window and no playback: this is a pipe into a device node, and
            // a preview window would be a second consumer nobody asked for.
            .arg("--no-window")
            .arg("--no-video-playback")
            // A phone camera has no microphone stream worth bridging here, and
            // requesting audio makes the whole session fail on devices that
            // cannot provide it alongside the camera.
            .arg("--no-audio")
            // The default buffer trades latency for smoothness. A webcam is
            // watched live by someone talking, so latency is the thing that
            // matters; 0 keeps it as low as the encoder allows.
            .arg("--v4l2-buffer=0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        if !size.is_empty() {
            command.arg(format!("--camera-size={size}"));
        }
        if fps > 0 {
            command.arg(format!("--camera-fps={fps}"));
        }

        let mut child = command.spawn().map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                WebcamError::Missing
            } else {
                WebcamError::Io(err)
            }
        })?;

        let stderr = child.stderr.take();
        info!(%serial, %camera_id, %device, "cámara conectada");

        tokio::spawn(async move {
            if let Some(stderr) = stderr {
                // Kept at debug for the same reason as the app windows: adb
                // writes its push progress here, so treating the stream as
                // errors turns every normal start into a warning. A real
                // failure surfaces through `reap`, which sees the exit status.
                use tokio::io::AsyncReadExt;
                let mut reader = tokio::io::BufReader::new(stderr);
                let mut text = String::new();
                let _ = reader.read_to_string(&mut text).await;
                let text = text.trim();
                if !text.is_empty() {
                    debug!("scrcpy (cámara): {text}");
                }
            }
        });

        self.running = Some(Running {
            serial: serial.to_string(),
            camera_id: camera_id.to_string(),
            size: size.to_string(),
            child,
        });

        Ok(device)
    }

    /// Stops the stream. Returns whether there was one.
    pub async fn stop(&mut self) -> bool {
        match self.running.take() {
            Some(mut running) => {
                let _ = running.child.kill().await;
                info!(serial = %running.serial, "cámara desconectada");
                true
            }
            None => false,
        }
    }

    /// Stops the stream if it belongs to this device.
    ///
    /// Called when a phone goes away: the loopback device would otherwise keep
    /// a dead producer attached, and the next `start` would refuse as busy.
    pub async fn stop_if_device(&mut self, serial: &str) -> bool {
        if self.serial() == Some(serial) {
            self.stop().await
        } else {
            false
        }
    }

    /// Notices a stream that ended on its own.
    ///
    /// Returns true if one was collected, so the daemon can announce it. The
    /// common cause is the phone locking or another app grabbing the camera,
    /// and without this the bridge would report itself busy forever.
    pub fn reap(&mut self) -> bool {
        let Some(running) = self.running.as_mut() else {
            return false;
        };
        match running.child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    warn!(
                        serial = %running.serial,
                        "la cámara terminó con {status}; probá \
                         `scrcpy -s {} --video-source=camera --camera-id={} --v4l2-sink=…` a mano",
                        running.serial, running.camera_id
                    );
                }
                self.running = None;
                true
            }
            Ok(None) => false,
            Err(err) => {
                warn!(%err, "no se pudo consultar el proceso de la cámara, se descarta");
                self.running = None;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `scrcpy 4.1 --list-camera-sizes` on a motorola edge 40,
    /// banner lines included, because those are exactly what a stricter parser
    /// would trip over.
    const REAL_OUTPUT: &str = "\
[server] INFO: Device: [motorola] motorola motorola edge 40 (Android 15)
[server] INFO: List of cameras:
    --camera-id=0    (back, 4096x3072, fps={10, 15, 20, 30, 60}, zoom-range=[1, 8])
        - 4096x3072
        - 3840x2160
        - 1280x720
    --camera-id=1    (front, 3264x2448, fps={10, 15, 20, 24, 30}, zoom-range=[1, 4])
        - 3264x2448
        - 1280x720
scrcpy 4.1 <https://github.com/Genymobile/scrcpy>
INFO: ADB device found:
INFO:     -->   (usb)  ZY22HB6KPB                      device  motorola_edge_40
";

    #[test]
    fn both_cameras_are_found() {
        let cameras = parse_cameras(REAL_OUTPUT);
        assert_eq!(cameras.len(), 2);
        assert_eq!(cameras[0].id, "0");
        assert_eq!(cameras[0].facing, CameraFacing::Back);
        assert_eq!(cameras[1].id, "1");
        assert_eq!(cameras[1].facing, CameraFacing::Front);
    }

    #[test]
    fn sizes_go_to_the_camera_they_follow() {
        let cameras = parse_cameras(REAL_OUTPUT);
        assert_eq!(cameras[0].sizes, ["4096x3072", "3840x2160", "1280x720"]);
        assert_eq!(cameras[1].sizes, ["3264x2448", "1280x720"]);
    }

    #[test]
    fn frame_rates_come_from_the_header() {
        let cameras = parse_cameras(REAL_OUTPUT);
        assert_eq!(cameras[0].fps, [10, 15, 20, 30, 60]);
        assert_eq!(cameras[1].fps, [10, 15, 20, 24, 30]);
    }

    #[test]
    fn the_banner_does_not_become_a_camera() {
        // "INFO: ADB device found:" and the scrcpy version line are in the
        // sample; if either were parsed we would have more than two cameras.
        assert_eq!(parse_cameras(REAL_OUTPUT).len(), 2);
    }

    #[test]
    fn nothing_is_invented_from_empty_output() {
        assert!(parse_cameras("").is_empty());
        assert!(parse_cameras("scrcpy 4.1\nINFO: nada\n").is_empty());
    }

    #[test]
    fn an_unknown_facing_is_external_rather_than_a_lost_camera() {
        let cameras = parse_cameras("    --camera-id=7    (periscope, 800x600, fps={30})\n");
        assert_eq!(cameras.len(), 1);
        assert_eq!(cameras[0].facing, CameraFacing::External);
        assert_eq!(cameras[0].id, "7");
    }

    #[test]
    fn a_word_where_a_size_should_be_is_not_passed_through() {
        let cameras = parse_cameras(
            "    --camera-id=0    (back, 800x600, fps={30})\n        - unavailable\n        - 800x600\n",
        );
        assert_eq!(cameras[0].sizes, ["800x600"]);
    }

    #[test]
    fn sizes_before_any_camera_are_dropped_instead_of_panicking() {
        assert!(parse_cameras("        - 1280x720\n").is_empty());
    }
}
