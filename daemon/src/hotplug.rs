//! Noticing that a phone was plugged in, without asking anybody.
//!
//! The service is meant to cost nothing while there is no device, so it does
//! not poll `adb devices`. It parks on udev's netlink socket instead: no
//! wakeups, no CPU, and the kernel hands over the event the instant the cable
//! goes in.
//!
//! This runs on a thread of its own rather than as a Tokio task. `udev::Socket`
//! is a raw file descriptor wrapper that is not `Send`, and its iterator is
//! non-blocking — the crate's own documentation says to `poll()` the descriptor
//! — so it cannot be moved into the runtime and cannot be awaited. One thread
//! blocked in `poll` costs a stack and nothing else.

use std::io;
use std::os::unix::io::AsRawFd;

use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// The USB interface descriptor Android exposes when debugging is on:
/// vendor-specific class `ff`, subclass `42`, protocol `01`.
///
/// Matching on this instead of a vendor id list is what keeps the rule to one
/// line. The `android-udev` packages ship hundreds of vendor ids and still miss
/// devices; this triple is defined by the ADB protocol itself, so it is the
/// same on every phone from every manufacturer. Verified against a Motorola
/// edge 40, which reports `ID_USB_INTERFACES=:ff4201:`.
pub const ADB_INTERFACE: &str = ":ff4201:";

#[derive(Debug, Clone)]
pub enum HotplugEvent {
    /// A device exposing the ADB interface appeared. The serial is udev's
    /// `ID_SERIAL_SHORT`, which is the same string adb reports.
    Attached { serial: String, model: String },
    /// It went away. udev gives no properties on removal for some devices, so
    /// the serial may be missing — the daemon then reconciles against adb.
    Detached { serial: Option<String> },
}

/// Watches udev and reports Android devices.
///
/// Returns immediately; events arrive on the channel. Dropping the receiver
/// stops the thread on its next event.
pub fn watch() -> io::Result<mpsc::Receiver<HotplugEvent>> {
    let (tx, rx) = mpsc::channel(16);

    // The socket is built inside the thread because none of udev's handles are
    // `Send` — they wrap raw C pointers — so one created out here could not be
    // moved in. A rendezvous channel carries the outcome back, so a netlink
    // socket that cannot be opened is still reported to the caller instead of
    // disappearing into a log line on a thread nobody is watching.
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<io::Result<()>>(0);

    std::thread::Builder::new()
        .name("udev-hotplug".into())
        .spawn(move || {
            let socket = match udev::MonitorBuilder::new()
                .and_then(|builder| builder.match_subsystem("usb"))
                .and_then(|builder| builder.listen())
            {
                Ok(socket) => {
                    let _ = ready_tx.send(Ok(()));
                    socket
                }
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };

            let fd = socket.as_raw_fd();
            loop {
                let mut poll_fd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };

                // -1: wait indefinitely. This is the line that makes the
                // service free while nothing is happening.
                let ready = unsafe { libc::poll(&mut poll_fd, 1, -1) };
                if ready < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    error!(%err, "se perdió el socket de udev; no habrá detección automática");
                    return;
                }

                // One notification can cover several queued events.
                for event in socket.iter() {
                    let Some(parsed) = classify(&event) else { continue };
                    if tx.blocking_send(parsed).is_err() {
                        debug!("nadie escucha los eventos de udev, se deja de observar");
                        return;
                    }
                }
            }
        })?;

    // Blocks only until the thread has built the socket, which is immediate.
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(rx),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(io::Error::other("el hilo de udev terminó antes de arrancar")),
    }
}

fn classify(event: &udev::Event) -> Option<HotplugEvent> {
    let prop = |key: &str| {
        event
            .property_value(key)
            .and_then(|v| v.to_str())
            .map(str::to_owned)
    };

    let serial = prop("ID_SERIAL_SHORT");

    match event.event_type() {
        udev::EventType::Add => {
            // Only devices in debugging mode carry the ADB interface. A phone
            // plugged in for charging or file transfer enumerates too, and
            // reacting to it would mean starting the adb server for something
            // that will never answer.
            let interfaces = prop("ID_USB_INTERFACES")?;
            if !interfaces.contains(ADB_INTERFACE) {
                debug!(%interfaces, "dispositivo USB sin interfaz ADB, se ignora");
                return None;
            }
            let serial = serial?;
            let model = prop("ID_MODEL")
                .map(|m| m.replace('_', " "))
                .unwrap_or_default();
            info!(%serial, %model, "teléfono conectado");
            Some(HotplugEvent::Attached { serial, model })
        }
        udev::EventType::Remove => {
            // On removal udev often has no properties left to give, so this
            // cannot filter on the ADB interface. Reporting every USB removal
            // and letting the daemon check its own list against adb is cheaper
            // than missing the one that mattered.
            Some(HotplugEvent::Detached { serial })
        }
        _ => None,
    }
}
