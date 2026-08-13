//! The VasakOS Android device service.
//!
//! Watches for phones, lists what is installed on them, and opens their apps as
//! ordinary windows on this desktop — one window per app, not a phone screen in
//! a box.
//!
//! It draws nothing. The panel menu, the notification centre and the settings
//! screen all live in applications that already exist, and none of them can
//! render into another's window; there is no interface for a process here to
//! own. That is why this is a plain Rust daemon and not a Tauri application:
//! a WebKit runtime resident for a service with no window is the mistake
//! already documented for two other daemons in this system.
//!
//! Runs on the session bus. Everything it touches — the phone, the adb server,
//! the windows, the list of known devices — belongs to the logged-in user.

mod adb;
mod hotplug;
mod notify;
mod registry;
mod windows;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};
use zbus::fdo::Error as FdoError;
use zbus::object_server::SignalEmitter;
use zbus::{connection, interface};

use registry::Registry;
use vasak_connect_protocol::{
    App, Device, DeviceState, RunningApp, SERVICE_NAME, SERVICE_PATH,
};
use windows::WindowManager;

/// How often finished scrcpy processes are collected.
///
/// A closed window should disappear from the panel promptly, but this runs
/// forever, so it is a compromise rather than a tight loop: one wakeup per
/// second in a service that is otherwise idle is exactly the cost this project
/// has been removing elsewhere.
const REAP_INTERVAL: Duration = Duration::from_secs(2);

/// After udev reports a device, adb needs a moment before it lists it.
const SETTLE: Duration = Duration::from_millis(600);

struct State {
    devices: HashMap<String, Device>,
    /// Cached per device. Listing takes seconds, and the menu is opened far
    /// more often than apps are installed.
    apps: HashMap<String, Vec<App>>,
    windows: WindowManager,
    registry: Registry,
}

impl State {
    fn device(&self, serial: &str) -> Result<&Device, FdoError> {
        self.devices.get(serial).ok_or_else(|| {
            FdoError::Failed(format!("no hay ningún dispositivo con el serial {serial}"))
        })
    }
}

struct ConnectService {
    state: Arc<Mutex<State>>,
}

#[interface(name = "ar.net.vasak.os.Connect")]
impl ConnectService {
    /// Every phone the service can currently see.
    async fn list_devices(&self) -> Vec<Device> {
        self.state.lock().await.devices.values().cloned().collect()
    }

    /// Phones this person has accepted before, whether or not they are here now.
    ///
    /// This is what the settings screen shows. A device that is not connected
    /// still has to be listed, or there is no way to forget one.
    async fn list_known_devices(&self) -> Vec<(String, String, String, String)> {
        let state = self.state.lock().await;
        state
            .registry
            .all()
            .map(|(serial, known)| {
                (
                    serial.clone(),
                    if known.alias.is_empty() {
                        known.model.clone()
                    } else {
                        known.alias.clone()
                    },
                    known.first_seen.clone(),
                    known.last_address.clone(),
                )
            })
            .collect()
    }

    /// The apps installed on a device.
    ///
    /// Answers from cache when it can. `refresh` forces a re-read, which is
    /// what the menu should do after the person installs something on the
    /// phone — there is no signal for that.
    async fn list_apps(&self, serial: &str, refresh: bool) -> Result<Vec<App>, FdoError> {
        {
            let state = self.state.lock().await;
            let device = state.device(serial)?;
            if device.state == DeviceState::Unauthorized {
                return Err(FdoError::Failed(
                    "el teléfono todavía no aceptó la depuración USB: mirá la pantalla del dispositivo"
                        .into(),
                ));
            }
            if device.state != DeviceState::Ready {
                return Err(FdoError::Failed(format!(
                    "el dispositivo está {}",
                    device.state.as_str()
                )));
            }
            if !refresh {
                if let Some(cached) = state.apps.get(serial) {
                    return Ok(cached.clone());
                }
            }
        }

        // The lock is released while adb works: listing takes seconds and
        // holding it would freeze the panel and every other caller.
        let listed = adb::list_apps(serial)
            .await
            .map_err(|err| FdoError::Failed(err.to_string()))?;

        let apps: Vec<App> = listed
            .into_iter()
            .map(|(package, label, system)| App {
                package,
                label,
                system,
                icon: String::new(),
            })
            .collect();

        let mut state = self.state.lock().await;
        state.apps.insert(serial.to_string(), apps.clone());
        Ok(apps)
    }

    /// Opens an app in its own window.
    async fn launch_app(&self, serial: &str, package: &str) -> Result<u32, FdoError> {
        let mut state = self.state.lock().await;
        let device = state.device(serial)?.clone();

        if device.state != DeviceState::Ready {
            return Err(FdoError::Failed(format!(
                "el dispositivo está {}",
                device.state.as_str()
            )));
        }

        let label = state
            .apps
            .get(serial)
            .and_then(|apps| apps.iter().find(|app| app.package == package))
            .map(|app| app.label.clone())
            .unwrap_or_else(|| package.to_string());

        state
            .windows
            .launch(serial, package, &label, device.transport)
            .map_err(|err| FdoError::Failed(err.to_string()))
    }

    async fn stop_app(&self, serial: &str, package: &str) -> bool {
        self.state.lock().await.windows.stop(serial, package).await
    }

    /// Every app open in a window right now.
    async fn list_running(&self) -> Vec<RunningApp> {
        let state = self.state.lock().await;
        state
            .windows
            .list()
            .map(|((serial, package), window)| RunningApp {
                serial: serial.clone(),
                package: package.clone(),
                label: window.label.clone(),
                pid: window.pid,
            })
            .collect()
    }

    /// Renames a device in the settings screen.
    async fn set_alias(&self, serial: &str, alias: &str) -> bool {
        let mut state = self.state.lock().await;
        let changed = state.registry.set_alias(serial, alias);
        if changed {
            state.registry.save();
        }
        changed
    }

    /// Drops a device from the known list.
    ///
    /// This does **not** revoke adb's authorisation, which lives on the phone
    /// and is the thing that actually grants access. Saying otherwise in the
    /// interface would be a lie: revoking for real means "Revoke USB debugging
    /// authorisations" in the phone's developer options.
    async fn forget_device(&self, serial: &str) -> bool {
        let mut state = self.state.lock().await;
        let removed = state.registry.forget(serial);
        if removed {
            state.registry.save();
        }
        removed
    }

    #[zbus(signal)]
    async fn device_added(emitter: &SignalEmitter<'_>, device: Device) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn device_removed(emitter: &SignalEmitter<'_>, serial: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn device_changed(emitter: &SignalEmitter<'_>, device: Device) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn app_closed(emitter: &SignalEmitter<'_>, serial: &str, package: &str)
        -> zbus::Result<()>;
}

fn now_iso8601() -> String {
    // Seconds since the epoch, formatted by hand. Pulling in a date library to
    // stamp one field in a config file is not worth the dependency.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Reconciles what adb sees with what the service believes, and announces the
/// difference.
///
/// Everything funnels through here — udev events, the periodic sweep, the
/// initial scan — so there is one place where a device is considered to have
/// arrived or left, instead of three that can disagree.
async fn refresh_devices(
    state: &Arc<Mutex<State>>,
    emitter: &SignalEmitter<'_>,
    connection: &zbus::Connection,
) {
    let seen = match adb::devices().await {
        Ok(devices) => devices,
        Err(adb::AdbError::Missing) => {
            error!("adb no está instalado: el servicio no puede hacer nada");
            return;
        }
        Err(err) => {
            warn!(%err, "no se pudo consultar adb");
            return;
        }
    };

    let mut announcements: Vec<(String, String)> = Vec::new();
    let mut gone: Vec<String> = Vec::new();

    {
        let mut state = state.lock().await;
        let now = now_iso8601();

        let mut fresh: HashMap<String, Device> = HashMap::new();
        for mut device in seen {
            device.trusted = state.registry.is_known(&device.serial);

            // A device reached over the network often reports no model, and a
            // menu entry called "172.19.30.45:5555" tells nobody which phone
            // that is. The name recorded the first time it was plugged in is
            // the one the person recognises.
            if device.model.is_empty() {
                if let Some(known) = state.registry.get(&device.serial) {
                    device.model = if known.alias.is_empty() {
                        known.model.clone()
                    } else {
                        known.alias.clone()
                    };
                }
            }

            // A phone waiting for the debugging prompt is not yet a device the
            // person owns: remembering it here would mark it trusted before
            // they ever tapped "Allow".
            if device.state == DeviceState::Ready {
                let first_time = !state.registry.is_known(&device.serial);
                state
                    .registry
                    .remember(&device.serial, &device.model, &device.address, &now);
                if first_time {
                    state.registry.save();
                }
            }

            let previous = state.devices.get(&device.serial);
            match previous {
                None => announcements.push((device.serial.clone(), device.model.clone())),
                Some(old) if old.state != device.state => {
                    let _ = ConnectService::device_changed(emitter, device.clone()).await;
                }
                Some(_) => {}
            }

            fresh.insert(device.serial.clone(), device);
        }

        for serial in state.devices.keys() {
            if !fresh.contains_key(serial) {
                gone.push(serial.clone());
            }
        }

        state.devices = fresh;

        // The app list belongs to a device that is no longer here; keeping it
        // would show a menu for a phone that is gone.
        for serial in &gone {
            state.apps.remove(serial);
        }
    }

    for (serial, model) in announcements {
        let device = {
            let state = state.lock().await;
            state.devices.get(&serial).cloned()
        };
        let Some(device) = device else { continue };

        let _ = ConnectService::device_added(emitter, device.clone()).await;

        match device.state {
            DeviceState::Unauthorized => {
                notify::send(
                    connection,
                    &format!("{model} conectado"),
                    "Aceptá la depuración USB en la pantalla del teléfono para poder usar sus aplicaciones.",
                    notify::PHONE_ICON,
                )
                .await;
            }
            DeviceState::Ready => {
                notify::send(
                    connection,
                    &format!("{model} conectado"),
                    "Sus aplicaciones ya están disponibles en el menú.",
                    notify::PHONE_ICON,
                )
                .await;
            }
            _ => {}
        }
    }

    for serial in gone {
        let closed = {
            let mut state = state.lock().await;
            state.windows.stop_all(&serial).await
        };
        for package in closed {
            let _ = ConnectService::app_closed(emitter, &serial, &package).await;
        }
        info!(%serial, "teléfono desconectado");
        let _ = ConnectService::device_removed(emitter, &serial).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The crate name comes from the compiler rather than a literal: the binary
    // is `vasak-connect` but the package is `vasak-connect-daemon`, and writing
    // either by hand gives a filter that matches no target at all. That is not
    // a loud failure — it is simply a service that logs nothing, which is how
    // the first version of this shipped with an empty journal.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=info", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .init();

    let state = Arc::new(Mutex::new(State {
        devices: HashMap::new(),
        apps: HashMap::new(),
        windows: WindowManager::default(),
        registry: Registry::load(),
    }));

    let connection = connection::Builder::session()?
        .name(SERVICE_NAME)?
        .serve_at(SERVICE_PATH, ConnectService { state: state.clone() })?
        .build()
        .await?;

    let emitter = SignalEmitter::new(&connection, SERVICE_PATH)?;
    info!("servicio en {SERVICE_NAME}");

    // A phone plugged in before the service started produces no udev event, so
    // the first look has to be explicit. The adb server is only started if
    // something is actually there — checked by asking udev, not by running adb.
    if any_android_attached() {
        debug!("hay un teléfono conectado desde antes de arrancar");
        if let Err(err) = adb::start_server().await {
            warn!(%err, "no se pudo iniciar el servidor de adb");
        }
        refresh_devices(&state, &emitter, &connection).await;
    }

    let mut hotplug = match hotplug::watch() {
        Ok(rx) => rx,
        Err(err) => {
            error!(%err, "sin udev no hay detección automática; sólo responderá a consultas");
            tokio::sync::mpsc::channel(1).1
        }
    };

    let mut reaper = interval(REAP_INTERVAL);

    loop {
        tokio::select! {
            Some(event) = hotplug.recv() => {
                match event {
                    hotplug::HotplugEvent::Attached { serial, model } => {
                        info!(%serial, %model, "udev: conectado");
                        if let Err(err) = adb::start_server().await {
                            warn!(%err, "no se pudo iniciar el servidor de adb");
                            continue;
                        }
                        // adb does not see the device the instant udev does.
                        sleep(SETTLE).await;
                        refresh_devices(&state, &emitter, &connection).await;
                    }
                    hotplug::HotplugEvent::Detached { serial } => {
                        debug!(?serial, "udev: desconectado");
                        refresh_devices(&state, &emitter, &connection).await;
                    }
                }
            }

            _ = reaper.tick() => {
                let finished = {
                    let mut state = state.lock().await;
                    state.windows.reap()
                };
                for (serial, package) in finished {
                    debug!(%serial, %package, "la ventana se cerró");
                    let _ = ConnectService::app_closed(&emitter, &serial, &package).await;
                }
            }
        }
    }
}

/// Whether any USB device currently exposes the ADB interface.
///
/// Asked at startup so the adb server is not woken for a machine with no phone
/// attached — the whole point of the service costing nothing while idle.
fn any_android_attached() -> bool {
    let Ok(mut enumerator) = udev::Enumerator::new() else {
        return false;
    };
    if enumerator.match_subsystem("usb").is_err() {
        return false;
    }
    match enumerator.scan_devices() {
        Ok(devices) => devices.into_iter().any(|device| {
            device
                .property_value("ID_USB_INTERFACES")
                .and_then(|v| v.to_str())
                .is_some_and(|interfaces| interfaces.contains(":ff4201:"))
        }),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_formats_correctly() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn a_leap_day_is_not_off_by_one() {
        // 2024-02-29 is 19782 days after the epoch.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn the_stamp_has_the_shape_the_config_expects() {
        let stamp = now_iso8601();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z'));
        assert_eq!(stamp.as_bytes()[10], b'T');
    }
}
