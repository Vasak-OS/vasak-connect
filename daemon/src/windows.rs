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
//! * `--flex-display` es lo que hace que la ventana se pueda agrandar: scrcpy
//!   redimensiona la pantalla virtual para que siga al tamaño de la ventana.
//!   Necesita **scrcpy 4.0 o más nuevo**, donde la opción se estrenó; en 3.x no
//!   existe y scrcpy sale en el arranque sin abrir ninguna ventana. Por eso el
//!   paquete pide esa versión y no la 3.0 que alcanzaba para `--new-display`.
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

/// El tamaño en píxeles con que abre una ventana.
///
/// Es sólo el punto de partida —`--flex-display` la sigue desde ahí—, y es
/// conservador a propósito: entra en una pantalla de portátil de 1366×768 sin
/// que el compositor tenga que recortarla.
const ANCHO_INICIAL: u32 = 1000;
const ALTO_INICIAL: u32 = 700;

/// La densidad de la pantalla virtual, en dpi.
///
/// **Esto es lo que decide si la app se re-acomoda al redimensionar la
/// ventana.** scrcpy sigue el tamaño de la ventana pero deja la densidad fija:
/// al redimensionar cambia la resolución y nada más. Así que este número decide
/// para siempre a cuántos dp equivale cada píxel, y Android elige el diseño de
/// una app por dp, nunca por píxeles.
///
/// Con los 220 dpi que había antes, una ventana de 1000×700 le llegaba a
/// Android como 727×509 dp. El lado menor —509 dp— queda por debajo de los
/// 600 dp desde donde Android entrega recursos de tablet, así que la app se
/// dibujaba como en un teléfono y agrandar la ventana no la movía de ahí: para
/// cruzar el umbral había que pasar los 825 px de alto, más de lo que mide la
/// mayoría de las ventanas. La pantalla crecía y la app seguía siendo un
/// teléfono estirado.
///
/// A 160 dpi —la densidad base de Android, y la que scrcpy usa por defecto para
/// estas pantallas— un dp es exactamente un píxel, así que el umbral cae donde
/// uno lo espera: 600 px de lado menor y la app pasa a diseño de tablet.
///
/// El precio es que los elementos se dibujan 1,375 veces más chicos que antes.
/// No hay forma de tener las dos cosas: una densidad alta agranda los elementos
/// y a la vez le miente a la app sobre cuánto espacio tiene. Tenerlas juntas
/// necesita que scrcpy pueda cambiar la densidad al redimensionar, que hoy es
/// una propuesta abierta (Genymobile/scrcpy#6784).
const DENSIDAD: u32 = 160;

/// Los dp que mide una cantidad de píxeles a una densidad dada.
///
/// Es la cuenta que hace Android para elegir los recursos de una app:
/// `dp = px × 160 / dpi`. Está en una función para poder afirmarla en un test,
/// que es lo único que impide que la densidad vuelva a subir sin que nadie note
/// el efecto — el síntoma no es un error, es una app que se ve bien y se dibuja
/// como si estuviera en un teléfono.
fn en_dp(pixeles: u32, densidad: u32) -> u32 {
    pixeles * 160 / densidad
}

/// El «smallest width» de Android: el lado menor, en dp.
///
/// Es el que gobierna los recursos `sw<N>dp` y no cambia al rotar, así que es el
/// que decide si una app se dibuja como teléfono o como tablet. Mirar sólo el
/// ancho es el error fácil: a 220 dpi una ventana de 1000×700 tenía 727 dp de
/// ancho —suficiente para varios diseños— y aun así quedaba en teléfono, porque
/// lo que la dejaba afuera era el alto.
fn menor_lado_dp(ancho: u32, alto: u32, densidad: u32) -> u32 {
    en_dp(ancho.min(alto), densidad)
}

/// El argumento con que se le pide a scrcpy la pantalla virtual.
fn nueva_pantalla(ancho: u32, alto: u32, densidad: u32) -> String {
    format!("--new-display={ancho}x{alto}/{densidad}")
}

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
            .arg(nueva_pantalla(ANCHO_INICIAL, ALTO_INICIAL, DENSIDAD))
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

        match transport {
            // Over the network the link is both slower and lossier, so the
            // defaults — tuned for USB — produce a stuttering window.
            Transport::Tcp => {
                command
                    .arg("--video-codec=h265")
                    .arg("--video-bit-rate=4M")
                    .arg("--max-fps=30");
            }
            // Por USB el ancho de banda no es el límite, y ahora la ventana
            // puede crecer: con los 8 Mb/s que scrcpy trae por defecto, una
            // ventana grande se ve en bloques. Subirlo es lo que la propia
            // documentación de scrcpy recomienda para estas pantallas.
            Transport::Usb => {
                command.arg("--video-bit-rate=16M");
            }
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
        // En dp, que es la unidad en la que Android decide el diseño de la app.
        // Se registra porque «la app se ve como en un teléfono» no deja rastro
        // en ningún log: los píxeles se ven en la pantalla y los dp no.
        debug!(
            ancho_dp = en_dp(ANCHO_INICIAL, DENSIDAD),
            lado_menor_dp = menor_lado_dp(ANCHO_INICIAL, ALTO_INICIAL, DENSIDAD),
            "tamaño inicial de la pantalla virtual"
        );

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Desde cuántos dp de lado menor Android entrega recursos de tablet: el
    /// calificador `sw600dp`.
    const UMBRAL_TABLET_DP: u32 = 600;

    /// Desde cuántos dp de ancho la clase de ventana de Material 3 es
    /// «expandida», que es donde una app muestra dos paneles en lugar de uno.
    const UMBRAL_EXPANDIDO_DP: u32 = 840;

    #[test]
    fn un_pixel_es_un_dp_en_la_densidad_base() {
        assert_eq!(en_dp(1000, 160), 1000);
        assert_eq!(en_dp(600, 160), 600);
    }

    #[test]
    fn la_ventana_inicial_le_llega_a_android_como_tablet() {
        assert!(
            menor_lado_dp(ANCHO_INICIAL, ALTO_INICIAL, DENSIDAD) >= UMBRAL_TABLET_DP,
            "el lado menor da {} dp",
            menor_lado_dp(ANCHO_INICIAL, ALTO_INICIAL, DENSIDAD)
        );
    }

    #[test]
    fn y_con_espacio_para_dos_paneles() {
        assert!(en_dp(ANCHO_INICIAL, DENSIDAD) >= UMBRAL_EXPANDIDO_DP);
    }

    #[test]
    fn la_densidad_que_teniamos_dejaba_la_app_en_diseno_de_telefono() {
        // El bug, tal como se veía: la ventana se agrandaba y la app seguía
        // dibujándose como en un teléfono. A 220 dpi el ancho alcanzaba de
        // sobra y el alto no, y manda el lado menor.
        assert_eq!(en_dp(1000, 220), 727);
        assert_eq!(menor_lado_dp(1000, 700, 220), 509);
        assert!(menor_lado_dp(1000, 700, 220) < UMBRAL_TABLET_DP);
    }

    #[test]
    fn a_220_dpi_habia_que_pasar_los_825_px_de_alto() {
        // Que es más de lo que mide la mayoría de las ventanas, y explica por
        // qué agrandar no cambiaba nada en la práctica.
        assert!(menor_lado_dp(1400, 824, 220) < UMBRAL_TABLET_DP);
        assert!(menor_lado_dp(1400, 825, 220) >= UMBRAL_TABLET_DP);
    }

    #[test]
    fn ahora_el_umbral_cae_donde_se_lo_espera() {
        // A la densidad base el umbral está en píxeles redondos: 600 de lado
        // menor. Es lo que hace que redimensionar sea predecible en lugar de
        // tener un punto de quiebre que nadie puede adivinar.
        assert!(menor_lado_dp(1000, 599, DENSIDAD) < UMBRAL_TABLET_DP);
        assert!(menor_lado_dp(1000, 600, DENSIDAD) >= UMBRAL_TABLET_DP);
    }

    #[test]
    fn el_lado_menor_no_es_siempre_el_alto() {
        // Una ventana más alta que ancha existe —alguien la acomoda al costado
        // de la pantalla— y ahí el que decide es el ancho.
        assert_eq!(menor_lado_dp(500, 1200, DENSIDAD), 500);
    }

    #[test]
    fn el_argumento_nombra_tamano_y_densidad() {
        assert_eq!(nueva_pantalla(1000, 700, 160), "--new-display=1000x700/160");
    }
}
