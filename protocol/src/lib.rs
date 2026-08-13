//! The contract between the device service, the panel and the settings screen.
//!
//! Everything that travels over D-Bus is defined here once so the three sides
//! cannot drift apart: a field renamed on one end stops compiling on the other
//! instead of silently becoming a device that never matches.

use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

// ── Bus addresses ───────────────────────────────────────────────────────────

/// The service runs on the **session** bus, as the logged-in user.
///
/// Unlike the permission service, nothing here needs root or another user's
/// processes: the phone belongs to whoever is sitting at the machine, the adb
/// server is per-user, the scrcpy windows have to appear in *that* session, and
/// the list of trusted devices is personal configuration. A system service
/// would have to hand all of that back to the session anyway, and would need
/// polkit to do it.
pub const SERVICE_NAME: &str = "ar.net.vasak.os.Connect";
pub const SERVICE_PATH: &str = "/ar/net/vasak/os/Connect";
pub const SERVICE_INTERFACE: &str = "ar.net.vasak.os.Connect";

// ── Devices ─────────────────────────────────────────────────────────────────

/// How the daemon is reaching a device.
///
/// The same phone can be plugged in *and* reachable over the network, with the
/// same serial but two different adb identifiers. Everything is keyed by serial
/// so it appears once in the menu, and this says which route is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[zvariant(signature = "s")]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Usb,
    Tcp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Usb => "usb",
            Transport::Tcp => "tcp",
        }
    }
}

/// What adb reports about a device it can see.
///
/// `Unauthorized` is the interesting one: the cable is in and the interface is
/// up, but nobody has tapped "Allow USB debugging" on the phone. It is not an
/// error and it is not a working device — showing it as either one is how a
/// user ends up staring at a menu that never fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[zvariant(signature = "s")]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    /// Connected and authorised; apps can be listed and launched.
    Ready,
    /// Waiting for the person to accept the debugging prompt on the phone.
    Unauthorized,
    /// Seen at the USB level, but adb cannot talk to it yet.
    Connecting,
    /// adb knows the device but it is not usable (booting, sleeping, lost).
    Offline,
}

impl DeviceState {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceState::Ready => "ready",
            DeviceState::Unauthorized => "unauthorized",
            DeviceState::Connecting => "connecting",
            DeviceState::Offline => "offline",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct Device {
    /// Stable identity of the phone. Survives replugging, changing transport
    /// and rebooting, which is why everything else is keyed by it.
    pub serial: String,
    /// What to show a person: "motorola edge 40", not "lyriq_g".
    pub model: String,
    pub transport: Transport,
    pub state: DeviceState,
    /// Whether this device has been accepted before. A phone the user already
    /// approved should just work; a new one is worth announcing.
    pub trusted: bool,
    /// Only meaningful for `Transport::Tcp`; empty over USB.
    pub address: String,
}

// ── Applications ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct App {
    /// Android package name, e.g. `org.telegram.messenger`.
    pub package: String,
    /// Human name in the phone's language, as Android reports it.
    pub label: String,
    /// Shipped with the system rather than installed by the user. The menu
    /// hides these by default: a list of 128 entries where 39 are
    /// "Configuración de Bluetooth" is not a menu, it is a haystack.
    pub system: bool,
    /// Absolute path to a cached icon, or empty when there is none.
    ///
    /// Empty is the normal case in 0.1.0 — see the README. The field exists now
    /// so adding extraction later does not change the contract.
    pub icon: String,
}

/// An app currently open in its own window on this desktop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct RunningApp {
    pub serial: String,
    pub package: String,
    pub label: String,
    /// PID of the scrcpy process drawing the window.
    pub pid: u32,
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Reasons a request cannot be honoured, phrased so the caller can decide
/// whether to retry, ask the user something, or give up.
pub mod errors {
    /// adb is installed but the device is not talking yet.
    pub const NOT_READY: &str = "ar.net.vasak.os.Connect.NotReady";
    /// No device with that serial.
    pub const NO_DEVICE: &str = "ar.net.vasak.os.Connect.NoDevice";
    /// The person has not accepted the debugging prompt on the phone.
    pub const UNAUTHORIZED: &str = "ar.net.vasak.os.Connect.Unauthorized";
    /// `adb` or `scrcpy` is missing from the system.
    pub const MISSING_TOOL: &str = "ar.net.vasak.os.Connect.MissingTool";
    /// The app refused to start, or scrcpy could not create a virtual display.
    pub const LAUNCH_FAILED: &str = "ar.net.vasak.os.Connect.LaunchFailed";
}
