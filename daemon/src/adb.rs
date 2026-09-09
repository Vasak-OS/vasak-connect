//! Everything that talks to `adb`.
//!
//! This shells out to the `adb` binary rather than speaking its wire protocol.
//! The protocol is undocumented and changes between platform-tools releases,
//! and the binary is a hard dependency anyway because scrcpy needs it: writing
//! a second implementation would buy nothing and add a way for the two to
//! disagree about which devices exist.
//!
//! One rule runs through the whole module: **never start the adb server just to
//! ask a question.** `adb devices` silently starts a daemon that then stays
//! resident. The service is supposed to cost nothing while no phone is plugged
//! in, so the server is only started once udev has said there is something to
//! talk to.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, warn};

use vasak_connect_protocol::{Device, DeviceState, Transport};

/// Long enough for a phone that is booting or waiting on the debugging prompt,
/// short enough that a wedged adb does not hang the whole service.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Listing apps makes the phone walk its whole package database. On the test
/// device (128 apps) it takes a few seconds; a slow phone with more takes
/// longer, and timing out turns a slow menu into an empty one.
const LIST_APPS_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug)]
pub enum AdbError {
    /// `adb` is not installed.
    Missing,
    /// The call took too long.
    TimedOut,
    /// adb ran and failed; the string is whatever it said.
    Failed(String),
    Io(std::io::Error),
}

impl std::fmt::Display for AdbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdbError::Missing => write!(f, "adb no está instalado"),
            AdbError::TimedOut => write!(f, "adb no respondió a tiempo"),
            AdbError::Failed(msg) => write!(f, "adb falló: {msg}"),
            AdbError::Io(err) => write!(f, "no se pudo ejecutar adb: {err}"),
        }
    }
}

impl From<std::io::Error> for AdbError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::NotFound {
            AdbError::Missing
        } else {
            AdbError::Io(err)
        }
    }
}

async fn run(args: &[&str], limit: Duration) -> Result<String, AdbError> {
    debug!(?args, "adb");
    let child = Command::new("adb")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();

    let output = match timeout(limit, child).await {
        Ok(result) => result?,
        Err(_) => return Err(AdbError::TimedOut),
    };

    if !output.status.success() {
        let msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(AdbError::Failed(if msg.is_empty() {
            format!("código {}", output.status)
        } else {
            msg
        }));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Starts the adb server if it is not already up.
///
/// Called when udev reports a device, never at startup.
pub async fn start_server() -> Result<(), AdbError> {
    run(&["start-server"], CALL_TIMEOUT).await.map(|_| ())
}

/// Everything adb can currently see.
///
/// The serial reported here is the same `ID_SERIAL_SHORT` udev gives for a USB
/// device, which is what lets the two views of the same phone be matched
/// without asking the phone anything.
pub async fn devices() -> Result<Vec<Device>, AdbError> {
    let out = run(&["devices", "-l"], CALL_TIMEOUT).await?;
    Ok(parse_devices(&out))
}

fn parse_devices(out: &str) -> Vec<Device> {
    let mut devices = Vec::new();

    for line in out.lines() {
        let line = line.trim_end();
        // The first line is a header, and adb prints notices ("* daemon
        // started successfully") on the same stream.
        if line.is_empty() || line.starts_with("List of devices") || line.starts_with('*') {
            continue;
        }

        let mut fields = line.split_whitespace();
        let Some(id) = fields.next() else { continue };
        let Some(status) = fields.next() else { continue };

        let state = match status {
            "device" => DeviceState::Ready,
            "unauthorized" => DeviceState::Unauthorized,
            "offline" => DeviceState::Offline,
            // "authorizing", "connecting", "recovery", "sideload"… none of them
            // can list apps, and all of them may become usable in a moment.
            _ => DeviceState::Connecting,
        };

        // `adb connect` identifies network devices as host:port, and that is
        // also their "serial" as far as adb is concerned. The real serial only
        // arrives in the `-l` fields, and not always.
        let over_tcp = id.contains(':') && id.rsplit(':').next().is_some_and(|p| p.parse::<u16>().is_ok());

        let mut model = String::new();
        let mut serial = String::new();
        for field in fields {
            if let Some(value) = field.strip_prefix("model:") {
                model = value.replace('_', " ");
            }
        }

        if !over_tcp {
            serial = id.to_string();
        }

        devices.push(Device {
            serial: if serial.is_empty() { id.to_string() } else { serial },
            model,
            transport: if over_tcp { Transport::Tcp } else { Transport::Usb },
            state,
            trusted: false, // filled in by the registry, which owns that answer
            address: if over_tcp { id.to_string() } else { String::new() },
        });
    }

    devices
}

/// The apps installed on a device, with their names in the phone's language.
///
/// This asks scrcpy rather than adb. Android has no shell command that returns
/// an app's display name — `pm list packages` gives package names only — and
/// scrcpy's server already reads them from PackageManager to implement
/// `--start-app`. Parsing its output is far less work than shipping a companion
/// APK for the same answer, which is what comparable projects end up doing.
pub async fn list_apps(serial: &str) -> Result<Vec<(String, String, bool)>, AdbError> {
    let output = Command::new("scrcpy")
        .args(["-s", serial, "--list-apps"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();

    let output = match timeout(LIST_APPS_TIMEOUT, output).await {
        Ok(result) => result.map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                AdbError::Missing
            } else {
                AdbError::Io(err)
            }
        })?,
        Err(_) => return Err(AdbError::TimedOut),
    };

    if !output.status.success() {
        let msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(AdbError::Failed(msg));
    }

    Ok(parse_apps(&String::from_utf8_lossy(&output.stdout)))
}

/// Parses `scrcpy --list-apps`.
///
/// The format is ` * Label   package` for system apps and ` - Label  package`
/// for user ones, with the package right-aligned in a fixed column. A label
/// longer than that column pushes the package onto the *next* line, which is
/// the case this has to get right — it happens on the very first entry of the
/// test device:
///
/// ```text
///  * Accesibilidad con interruptores
///                                   com.google.android.accessibility.switchaccess
/// ```
fn parse_apps(out: &str) -> Vec<(String, String, bool)> {
    let mut apps = Vec::new();
    let mut pending: Option<(String, bool)> = None;

    for line in out.lines() {
        let trimmed = line.trim();

        // A continuation line: only the package, indented under the label.
        if let Some((label, system)) = pending.take() {
            if !trimmed.is_empty() && looks_like_package(trimmed) {
                apps.push((trimmed.to_string(), label, system));
                continue;
            }
            // Not a continuation after all — drop the entry rather than pair a
            // label with the wrong package.
            warn!(%label, "app sin paquete en la salida de scrcpy");
        }

        let Some(rest) = trimmed
            .strip_prefix("* ")
            .map(|r| (r, true))
            .or_else(|| trimmed.strip_prefix("- ").map(|r| (r, false)))
        else {
            continue;
        };
        let (rest, system) = rest;

        // The package is the last whitespace-separated token, and package names
        // never contain spaces — so whatever precedes it is the label, spaces
        // and all.
        match rest.rsplit_once(char::is_whitespace) {
            Some((label, package)) if looks_like_package(package) => {
                apps.push((package.to_string(), label.trim().to_string(), system));
            }
            // No package on this line: it wrapped.
            _ => pending = Some((rest.trim().to_string(), system)),
        }
    }

    apps
}

/// A cheap shape test, not a validator.
///
/// It only has to tell a package name apart from a piece of a label, and every
/// real package has at least one dot and no spaces.
fn looks_like_package(text: &str) -> bool {
    !text.is_empty()
        && text.contains('.')
        && !text.contains(char::is_whitespace)
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Salidas con la forma que `adb devices -l` produce de verdad.
    ///
    /// Hace falta un generador y no alcanza con texto al azar: un aparato de
    /// red necesita un `host:puerto` con puerto que entre en un `u16` y un
    /// segundo campo con el estado, y la probabilidad de que eso salga de una
    /// cadena arbitraria es nula. Sin esto, las propiedades sobre el transporte
    /// y la serie no llegan a mirar nunca la rama que les importa — lo
    /// comprobé rompiendo el código a propósito y viéndolas pasar igual.
    fn salida_de_adb() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;

        let usb = "[A-Z0-9]{6,12}".prop_map(|s| s.to_string());
        let tcp = ("[0-9]{1,3}(\\.[0-9]{1,3}){3}", 1u32..70000).prop_map(|(h, p)| format!("{h}:{p}"));
        let id = prop_oneof![usb, tcp];

        let estado = prop_oneof![
            Just("device".to_string()),
            Just("unauthorized".to_string()),
            Just("offline".to_string()),
            "[a-z]{3,12}".prop_map(|s| s.to_string()),
        ];

        let extras = proptest::option::of("model:[A-Za-z0-9_]{1,20}".prop_map(|s| s.to_string()));

        let linea = (id, estado, extras).prop_map(|(id, estado, extras)| match extras {
            Some(e) => format!("{id} {estado} {e}"),
            None => format!("{id} {estado}"),
        });

        proptest::collection::vec(linea, 0..5)
            .prop_map(|lineas| format!("List of devices attached\n{}\n", lineas.join("\n")))
    }

    // Parte del fuzzing de los analizadores privilegiados que pide
    // Vasak-OS/website#5. Éste es el que lee **desde afuera del equipo**: el
    // número de serie, el nombre del modelo y los nombres de paquete los elige
    // el teléfono, y con `adb connect` el teléfono puede estar en cualquier
    // parte de la red.
    proptest::proptest! {
        /// Ninguna salida, venga como venga, hace caer a los analizadores.
        #[test]
        fn parse_devices_nunca_entra_en_panico(texto in ".{0,400}") {
            let _ = parse_devices(&texto);
        }

        #[test]
        fn parse_apps_nunca_entra_en_panico(texto in ".{0,400}") {
            let _ = parse_apps(&texto);
        }

        /// Ni una salida con la forma de `adb devices -l` y los campos al
        /// voleo, que es lo que una cadena al azar casi nunca produce.
        #[test]
        fn una_linea_con_forma_de_dispositivo_tampoco(
            id in ".{0,40}",
            estado in ".{0,20}",
            modelo in ".{0,40}",
        ) {
            let salida = format!("List of devices attached\n{id} {estado} model:{modelo}\n");
            let _ = parse_devices(&salida);
        }

        /// El número de serie nunca sale vacío.
        ///
        /// Todo se indexa por serie: el registro de confiados, las ventanas
        /// abiertas, la cámara. Dos aparatos con la serie vacía serían el mismo
        /// para todo el servicio, y confiar en uno confiaría en el otro.
        ///
        /// Va con el generador de líneas armadas y no con texto al azar. Con
        /// texto al azar esta prueba **pasaba con el error puesto**: hace falta
        /// un `host:puerto` con puerto válido y un segundo campo para producir
        /// un aparato de red, y eso no sale de `.{0,300}` ni por casualidad.
        #[test]
        fn la_serie_nunca_queda_vacia(salida in salida_de_adb()) {
            for dispositivo in parse_devices(&salida) {
                proptest::prop_assert!(!dispositivo.serial.is_empty(), "{salida:?}");
            }
        }

        /// Lo que llega por red trae dirección; lo que llega por cable, no.
        ///
        /// De eso depende a dónde se reconecta el servicio. Una dirección vacía
        /// en un aparato marcado como de red haría que intente `adb connect ""`.
        #[test]
        fn el_transporte_y_la_direccion_van_juntos(salida in salida_de_adb()) {
            for dispositivo in parse_devices(&salida) {
                match dispositivo.transport {
                    Transport::Tcp => proptest::prop_assert!(!dispositivo.address.is_empty()),
                    Transport::Usb => proptest::prop_assert!(dispositivo.address.is_empty()),
                }
            }
        }

        /// Todo paquete que sale de acá tiene forma de paquete.
        ///
        /// Es la propiedad que importa de las tres. El nombre se interpola en
        /// un argumento de scrcpy —`--start-app=+{package}` en `windows.rs`—,
        /// así que lo que salga de este analizador termina en la línea de
        /// órdenes de otro programa. No hay shell de por medio, con lo cual no
        /// hay inyección posible, pero que el juego de caracteres esté acotado
        /// a letras, números, punto, guion y guion bajo es lo que hace que eso
        /// siga siendo cierto si alguien cambia cómo se arma esa orden.
        #[test]
        fn todo_paquete_tiene_forma_de_paquete(texto in ".{0,400}") {
            for (paquete, _, _) in parse_apps(&texto) {
                proptest::prop_assert!(looks_like_package(&paquete), "{paquete:?}");
            }
        }

        /// Y una etiqueta nunca se cuela como paquete.
        ///
        /// Emparejar mal el par etiqueta/paquete significa lanzar una
        /// aplicación distinta de la que se tocó en el menú.
        #[test]
        fn una_etiqueta_con_espacios_no_pasa_por_paquete(
            etiqueta in "[a-zA-Z ]{1,30}",
            paquete in "[a-z]{1,8}\\.[a-z]{1,8}",
        ) {
            let salida = format!(" * {etiqueta} {paquete}\n");
            for (p, _, _) in parse_apps(&salida) {
                proptest::prop_assert_eq!(&p, &paquete);
            }
        }
    }

    #[test]
    fn reads_a_usb_device() {
        let out = "List of devices attached\n\
                   ZY22HB6KPB             device usb:1-2 product:lyriq_g model:motorola_edge_40 device:lyriq\n";
        let devices = parse_devices(out);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "ZY22HB6KPB");
        assert_eq!(devices[0].model, "motorola edge 40");
        assert_eq!(devices[0].transport, Transport::Usb);
        assert_eq!(devices[0].state, DeviceState::Ready);
    }

    #[test]
    fn a_phone_waiting_for_the_prompt_is_not_an_error() {
        let devices = parse_devices("List of devices attached\nZY22HB6KPB   unauthorized usb:1-2\n");
        assert_eq!(devices[0].state, DeviceState::Unauthorized);
    }

    #[test]
    fn network_devices_carry_their_address() {
        let devices = parse_devices("List of devices attached\n172.19.30.45:5555 device model:motorola_edge_40\n");
        assert_eq!(devices[0].transport, Transport::Tcp);
        assert_eq!(devices[0].address, "172.19.30.45:5555");
    }

    #[test]
    fn ignores_the_daemon_notice() {
        // adb prints this on stdout the first time it starts the server.
        let devices = parse_devices("* daemon not running; starting now at tcp:5037\n* daemon started successfully\nList of devices attached\n");
        assert!(devices.is_empty());
    }

    #[test]
    fn reads_apps_on_one_line() {
        let apps = parse_apps(" * Ajustes                        com.android.settings\n - Telegram   org.telegram.messenger\n");
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0], ("com.android.settings".into(), "Ajustes".into(), true));
        assert_eq!(apps[1], ("org.telegram.messenger".into(), "Telegram".into(), false));
    }

    #[test]
    fn reads_an_app_whose_label_pushed_the_package_to_the_next_line() {
        let apps = parse_apps(
            " * Accesibilidad con interruptores\n                                  com.google.android.accessibility.switchaccess\n",
        );
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].0, "com.google.android.accessibility.switchaccess");
        assert_eq!(apps[0].1, "Accesibilidad con interruptores");
        assert!(apps[0].2);
    }

    #[test]
    fn skips_the_banner_scrcpy_prints_first() {
        let apps = parse_apps(
            "[server] INFO: Device: [motorola] motorola motorola edge 40 (Android 15)\n\
             [server] INFO: List of apps:\n\
             - Firefox  org.mozilla.firefox\n",
        );
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].0, "org.mozilla.firefox");
    }

    #[test]
    fn a_label_with_spaces_survives() {
        let apps = parse_apps(" - Google Play Store   com.android.vending\n");
        assert_eq!(apps[0].1, "Google Play Store");
    }
}
