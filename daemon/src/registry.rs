//! Which phones this person has accepted before.
//!
//! Deliberately thin. adb already has a trust mechanism — an RSA key pair, and
//! the "Allow USB debugging?" prompt on the phone — and it is the one that
//! actually decides whether a connection works. Inventing a second one here
//! would create two answers to the same question that drift apart, and the one
//! stored in this file would be the one that cannot enforce anything.
//!
//! So this records only what adb does *not*: a name the person recognises, when
//! the device was first seen, and whether they want it treated as familiar
//! (connect quietly) or as new (announce it).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnownDevice {
    pub model: String,
    /// A name the user chose; falls back to the model when empty.
    #[serde(default)]
    pub alias: String,
    /// ISO-8601, first time it was seen.
    #[serde(default)]
    pub first_seen: String,
    /// Last address it answered on. This is what makes reconnecting possible on
    /// networks where mDNS does not reach — a segmented office wifi, for
    /// instance — where discovery is impossible but a direct connection is not.
    #[serde(default)]
    pub last_address: String,
    /// Packages the person pinned to the menu.
    #[serde(default)]
    pub favourites: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    devices: BTreeMap<String, KnownDevice>,
}

impl Registry {
    /// `~/.config/vasak/connect.json`, next to the rest of the session's
    /// configuration.
    pub fn path() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("vasak").join("connect.json"))
    }

    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            warn!("sin HOME ni XDG_CONFIG_HOME: los dispositivos conocidos no se van a recordar");
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|err| {
                // A corrupt file must not stop the service: the worst case is
                // that every phone looks new again, which is recoverable.
                warn!(%err, ?path, "no se pudo leer la lista de dispositivos, se arranca vacía");
                Self::default()
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(err) => {
                warn!(%err, ?path, "no se pudo abrir la lista de dispositivos");
                Self::default()
            }
        }
    }

    pub fn save(&self) {
        let Some(path) = Self::path() else { return };
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                warn!(%err, ?parent, "no se pudo crear el directorio de configuración");
                return;
            }
        }
        let Ok(text) = serde_json::to_string_pretty(self) else { return };

        // Written through a temporary file: a crash midway through would
        // otherwise leave a truncated file, and the next start would decide
        // that no phone had ever been trusted.
        let tmp = path.with_extension("json.tmp");
        if let Err(err) = std::fs::write(&tmp, text) {
            warn!(%err, "no se pudo guardar la lista de dispositivos");
            return;
        }
        if let Err(err) = std::fs::rename(&tmp, &path) {
            warn!(%err, "no se pudo reemplazar la lista de dispositivos");
            let _ = std::fs::remove_file(&tmp);
        }
        debug!(?path, "lista de dispositivos guardada");
    }

    pub fn is_known(&self, serial: &str) -> bool {
        self.devices.contains_key(serial)
    }

    pub fn get(&self, serial: &str) -> Option<&KnownDevice> {
        self.devices.get(serial)
    }

    pub fn all(&self) -> impl Iterator<Item = (&String, &KnownDevice)> {
        self.devices.iter()
    }

    /// Records a device, or refreshes what is known about one.
    pub fn remember(&mut self, serial: &str, model: &str, address: &str, now: &str) {
        let entry = self.devices.entry(serial.to_string()).or_insert_with(|| KnownDevice {
            first_seen: now.to_string(),
            ..Default::default()
        });
        if !model.is_empty() {
            entry.model = model.to_string();
        }
        if !address.is_empty() {
            entry.last_address = address.to_string();
        }
    }

    pub fn forget(&mut self, serial: &str) -> bool {
        self.devices.remove(serial).is_some()
    }

    pub fn set_alias(&mut self, serial: &str, alias: &str) -> bool {
        match self.devices.get_mut(serial) {
            Some(device) => {
                device.alias = alias.to_string();
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembering_twice_keeps_the_first_sighting() {
        let mut registry = Registry::default();
        registry.remember("ZY22HB6KPB", "motorola edge 40", "", "2026-08-13T10:00:00Z");
        registry.remember("ZY22HB6KPB", "motorola edge 40", "", "2026-09-01T10:00:00Z");
        assert_eq!(registry.get("ZY22HB6KPB").unwrap().first_seen, "2026-08-13T10:00:00Z");
    }

    #[test]
    fn an_empty_model_does_not_erase_a_known_one() {
        // A device seen over TCP may report no model; that is not a reason to
        // forget the name shown in the settings screen.
        let mut registry = Registry::default();
        registry.remember("ZY22HB6KPB", "motorola edge 40", "", "2026-08-13T10:00:00Z");
        registry.remember("ZY22HB6KPB", "", "172.19.30.45:5555", "2026-08-13T11:00:00Z");
        let device = registry.get("ZY22HB6KPB").unwrap();
        assert_eq!(device.model, "motorola edge 40");
        assert_eq!(device.last_address, "172.19.30.45:5555");
    }

    #[test]
    fn forgetting_reports_whether_there_was_anything_to_forget() {
        let mut registry = Registry::default();
        registry.remember("A", "x", "", "now");
        assert!(registry.forget("A"));
        assert!(!registry.forget("A"));
    }
}
