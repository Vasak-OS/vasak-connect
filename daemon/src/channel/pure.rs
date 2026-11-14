//! Toda la lógica del canal que se decide **sin** red, TLS, D-Bus ni llavero.
//!
//! Está junta y aislada a propósito: es lo que se puede probar de verdad —y lo
//! que la puerta de cobertura mira—, mientras que el código que toca sockets,
//! rustls o el Secret Service queda fino y delega acá cada decisión. Si una
//! regla de seguridad se puede escribir como una función de entradas a salida
//! (qué huella aceptar, qué marco rechazar, qué `Hello` es válido), vive en este
//! módulo y no en el medio de un bucle de lectura.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use vasak_connect_protocol::wire::{self, DeviceKind, Message, PeerInfo, PROTOCOL_VERSION};

// ── Huellas e identidad ──────────────────────────────────────────────────────

/// La huella de un certificado: SHA-256 de su DER, en hexadecimal con dos
/// puntos y en mayúsculas, como la imprime OpenSSL.
///
/// Es el mismo formato que promete [`PeerInfo::fingerprint`], para poder comparar
/// la que anuncia el par con la que presenta su certificado sin reformatear.
pub fn fingerprint_from_der(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(digest.len() * 3);
    for (i, byte) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

/// El identificador estable del aparato, derivado de su huella.
///
/// Son los mismos bytes del SHA-256 que la huella, sin los dos puntos y en
/// minúsculas: estable mientras el certificado no cambie, y sin un segundo valor
/// que persistir y mantener sincronizado con la huella.
pub fn device_id_from_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(char::is_ascii_hexdigit)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Normaliza una huella para compararla: sin espacios y en mayúsculas. Dos
/// huellas que sólo difieren en el caso o en bordes en blanco son la misma.
fn normalize_fingerprint(fingerprint: &str) -> String {
    fingerprint.trim().to_ascii_uppercase()
}

/// Si dos huellas identifican al mismo certificado, sin que las desalinee el
/// caso de las letras.
pub fn fingerprints_equal(a: &str, b: &str) -> bool {
    normalize_fingerprint(a) == normalize_fingerprint(b)
}

// ── Enmarcado de la sesión de control ────────────────────────────────────────

/// Tope de un marco, en bytes. Un marco que lo pase se rechaza sin reservar la
/// memoria que pide: así un par (o algo que se haga pasar por uno) no tira el
/// servicio anunciando un largo enorme.
///
/// 1 MiB sobra para los mensajes de control de este canal —el más grande es un
/// `Hello` con unos pocos campos de texto—; los bytes de los archivos van por
/// otra conexión (ver [`wire::FileOffer`]) y no por acá.
pub const MAX_FRAME: usize = 1 << 20;

/// Por qué un marco no se pudo leer. Todo son datos de red: la respuesta a
/// cualquiera de estos es cerrar la sesión, nunca entrar en pánico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// El largo anunciado pasa [`MAX_FRAME`].
    TooLarge(usize),
    /// Un marco de largo cero: no hay cuerpo que decodificar.
    Empty,
    /// El cuerpo no es un [`Message`] válido (corrupto o de una versión
    /// incompatible).
    Malformed,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooLarge(len) => {
                write!(
                    f,
                    "el marco anuncia {len} bytes, más que el tope de {MAX_FRAME}"
                )
            }
            FrameError::Empty => write!(f, "marco de largo cero"),
            FrameError::Malformed => write!(f, "el cuerpo del marco no es un mensaje válido"),
        }
    }
}

impl std::error::Error for FrameError {}

/// El largo que anuncia la cabecera de cuatro bytes, en big-endian.
pub fn frame_len(header: [u8; 4]) -> usize {
    u32::from_be_bytes(header) as usize
}

/// Valida el largo anunciado antes de reservar un solo byte: ni vacío ni por
/// encima del tope.
pub fn check_frame_len(len: usize) -> Result<usize, FrameError> {
    if len == 0 {
        Err(FrameError::Empty)
    } else if len > MAX_FRAME {
        Err(FrameError::TooLarge(len))
    } else {
        Ok(len)
    }
}

/// Serializa un mensaje con su largo delante: cuatro bytes big-endian y después
/// el JSON de [`wire::encode`]. Es lo inverso de leer la cabecera y el cuerpo.
pub fn encode_frame(message: &Message) -> Vec<u8> {
    let body = wire::encode(message);
    let mut framed = Vec::with_capacity(4 + body.len());
    // Los mensajes de control de este canal son chicos y los armamos nosotros,
    // así que el largo entra en u32 de sobra; el tope se hace valer al **leer**,
    // que es donde el largo lo elige el otro lado.
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

/// Reconstruye el mensaje de un cuerpo ya leído. Un cuerpo inválido es dato de
/// red, así que devuelve error en vez de caerse.
pub fn decode_frame(body: &[u8]) -> Result<Message, FrameError> {
    wire::decode(body).map_err(|_| FrameError::Malformed)
}

// ── Pareo y confianza ────────────────────────────────────────────────────────

/// Qué hacer con el certificado que presentó el otro lado, una vez calculada su
/// huella y buscada la que tenemos fijada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    /// Par ya pareado y el certificado es el mismo: la sesión es de confianza.
    Trusted,
    /// Par sin parear: se acepta la conexión pero no se confía hasta parear.
    Unpaired,
    /// Par pareado que presenta **otro** certificado: se rechaza. Es el caso que
    /// atrapa a un intermediario o a un aparato reaprovisionado haciéndose pasar
    /// por uno de confianza.
    Reject,
}

/// La decisión de confianza sobre un certificado presentado.
///
/// Esta es la frontera de seguridad del canal, escrita como una función pura: la
/// capa de TLS acepta cualquier certificado autofirmado (no hay CA) y **acá** se
/// decide, comparando contra la huella fijada en el pareo.
pub fn evaluate_peer_cert(
    presented_fingerprint: &str,
    pinned_fingerprint: Option<&str>,
) -> TrustDecision {
    match pinned_fingerprint {
        Some(pinned) if fingerprints_equal(pinned, presented_fingerprint) => TrustDecision::Trusted,
        Some(_) => TrustDecision::Reject,
        None => TrustDecision::Unpaired,
    }
}

/// Si una versión de protocolo que anuncia el par es compatible con la nuestra.
///
/// Hoy es igualdad exacta —hay una sola versión—; vive en su propia función para
/// que, cuando haya más de una, la regla de compatibilidad quede en un solo
/// lugar y no repartida por el código de red.
pub fn protocol_compatible(peer_version: u16) -> bool {
    peer_version == PROTOCOL_VERSION
}

/// Por qué se rechaza el `Hello` de un par.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    /// La versión de protocolo del par no es compatible con la nuestra.
    IncompatibleVersion(u16),
    /// La huella que el par declara en el `Hello` no es la del certificado con el
    /// que está hablando. Un par honesto declara la suya; que no coincida es
    /// señal de que alguien está repitiendo un `Hello` ajeno.
    FingerprintMismatch,
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloError::IncompatibleVersion(v) => {
                write!(f, "versión de protocolo incompatible del par: {v}")
            }
            HelloError::FingerprintMismatch => {
                write!(
                    f,
                    "la huella declarada en el Hello no es la del certificado"
                )
            }
        }
    }
}

impl std::error::Error for HelloError {}

/// Valida el `Hello` de un par contra la huella que su certificado presentó de
/// verdad en el TLS.
///
/// Comprueba dos cosas antes de seguir: que las versiones se entiendan, y que la
/// huella que el par declara sea la del certificado con el que está hablando. Lo
/// segundo ata el `Hello` a la conexión: sin eso, un par podría declarar la
/// huella de otro y hacerse pasar por él a nivel de aplicación aunque el
/// certificado del TLS fuera distinto.
///
/// El `device_id` que el par declara **no** se valida acá a propósito: no se
/// confía en él. El canal lo deriva por su cuenta de la huella del certificado
/// con [`device_id_from_fingerprint`] y usa ése, así que el que elija el par da
/// igual y no hace falta rechazarlo (lo que además ataría la identidad a un campo
/// que el par controla).
pub fn verify_hello(peer: &PeerInfo, tls_fingerprint: &str) -> Result<(), HelloError> {
    if !protocol_compatible(peer.protocol_version) {
        return Err(HelloError::IncompatibleVersion(peer.protocol_version));
    }
    if !fingerprints_equal(&peer.fingerprint, tls_fingerprint) {
        return Err(HelloError::FingerprintMismatch);
    }
    Ok(())
}

/// El código que las dos pantallas muestran durante el pareo, sobre nuestra
/// huella y la del par. Reexporta el del contrato para que el código del canal
/// no vuelva a implementarlo.
pub fn verification_code(own_fingerprint: &str, peer_fingerprint: &str) -> String {
    wire::verification_code(own_fingerprint, peer_fingerprint)
}

// ── Máquina de estados del pareo ─────────────────────────────────────────────
//
// La invariante que esta máquina hace cumplir: **un par se fija como de confianza
// SÓLO cuando la persona local confirma el código** (`PairingEvent::LocalConfirm
// { accept: true }` sobre un pareo pendiente). Ningún mensaje del par —ni un
// `PairResponse { accepted: true }` no pedido— vuelve a un par de confianza por
// sí solo. Toda la lógica del pareo pasa por `advance_pairing`, que es pura: el
// código de red sólo aplica lo que ésta decide (mandar un mensaje, fijar, avisar).

/// El estado del pareo de una sesión.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PairingState {
    /// Sin pareo en curso.
    #[default]
    Idle,
    /// Nosotros pedimos parear y esperamos: que la persona local confirme el
    /// código, y que el par conteste que acepta. `peer_accepted` dice si el par ya
    /// contestó que sí; aun así no se fija hasta la confirmación local.
    OutgoingPending { code: String, peer_accepted: bool },
    /// El par pidió parear y esperamos la confirmación local.
    IncomingPending { code: String },
}

/// Lo que mueve la máquina de pareo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingEvent {
    /// La persona local pidió iniciar el pareo (`request_pairing`).
    LocalInitiate { code: String },
    /// Llegó un `PairRequest` del par.
    PeerRequest { code: String },
    /// Llegó un `PairResponse` del par.
    PeerResponse { accepted: bool },
    /// La persona local confirmó o rechazó (`confirm_pairing`).
    LocalConfirm { accept: bool },
}

/// Qué hacer tras un evento: a qué estado pasar, qué mandarle al par, si fijarlo
/// como de confianza, y si avisar a la persona con un código.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingAction {
    pub next: PairingState,
    /// Mensaje a mandarle al par, si corresponde.
    pub send: Option<Message>,
    /// Fijar al par como de confianza. **Sólo es `true` en respuesta a
    /// `LocalConfirm { accept: true }` sobre un pareo pendiente.**
    pub pin: bool,
    /// Código a mostrarle a la persona (emitir `pairing_requested`), si hay que
    /// pedirle una confirmación.
    pub notify_code: Option<String>,
}

impl PairingAction {
    /// Un no-op: se queda como está y no hace nada. Es la respuesta a cualquier
    /// evento que no corresponde al estado —entre ellos un `PairResponse` sin un
    /// pedido saliente pendiente, que es justo lo que no debe fijar nada.
    fn noop(state: &PairingState) -> Self {
        PairingAction {
            next: state.clone(),
            send: None,
            pin: false,
            notify_code: None,
        }
    }
}

/// La transición de la máquina de pareo. Pura: no toca red, estado compartido ni
/// reloj; devuelve qué hacer y el código de red lo aplica.
pub fn advance_pairing(state: &PairingState, event: PairingEvent) -> PairingAction {
    match (state, event) {
        // Iniciamos nosotros: mandamos el pedido y le mostramos el código a la
        // persona para que lo confirme.
        (PairingState::Idle, PairingEvent::LocalInitiate { code }) => PairingAction {
            next: PairingState::OutgoingPending {
                code: code.clone(),
                peer_accepted: false,
            },
            send: Some(Message::PairRequest {
                verification: code.clone(),
            }),
            pin: false,
            notify_code: Some(code),
        },

        // El par pide parear: mostramos el código y esperamos la confirmación
        // local. No se fija nada acá.
        (PairingState::Idle, PairingEvent::PeerRequest { code }) => PairingAction {
            next: PairingState::IncomingPending { code: code.clone() },
            send: None,
            pin: false,
            notify_code: Some(code),
        },

        // El par acepta nuestro pedido: lo anotamos, pero **no se fija**: falta la
        // confirmación local. Se vuelve a mostrar el código para que la persona
        // pueda confirmar.
        (
            PairingState::OutgoingPending { code, .. },
            PairingEvent::PeerResponse { accepted: true },
        ) => PairingAction {
            next: PairingState::OutgoingPending {
                code: code.clone(),
                peer_accepted: true,
            },
            send: None,
            pin: false,
            notify_code: Some(code.clone()),
        },

        // El par rechaza nuestro pedido: se cancela.
        (PairingState::OutgoingPending { .. }, PairingEvent::PeerResponse { accepted: false }) => {
            PairingAction {
                next: PairingState::Idle,
                send: None,
                pin: false,
                notify_code: None,
            }
        }

        // La persona confirma un pedido saliente: **acá sí se fija**. No hace
        // falta avisarle nada más al par: pareó cuando su propia persona aceptó.
        (PairingState::OutgoingPending { .. }, PairingEvent::LocalConfirm { accept: true }) => {
            PairingAction {
                next: PairingState::Idle,
                send: None,
                pin: true,
                notify_code: None,
            }
        }

        // La persona confirma un pedido entrante: se fija y se le contesta que sí
        // al par.
        (PairingState::IncomingPending { .. }, PairingEvent::LocalConfirm { accept: true }) => {
            PairingAction {
                next: PairingState::Idle,
                send: Some(Message::PairResponse { accepted: true }),
                pin: true,
                notify_code: None,
            }
        }

        // La persona rechaza un pedido entrante: se le avisa al par que no.
        (PairingState::IncomingPending { .. }, PairingEvent::LocalConfirm { accept: false }) => {
            PairingAction {
                next: PairingState::Idle,
                send: Some(Message::PairResponse { accepted: false }),
                pin: false,
                notify_code: None,
            }
        }

        // La persona rechaza un pedido saliente: se cancela sin fijar.
        (PairingState::OutgoingPending { .. }, PairingEvent::LocalConfirm { accept: false }) => {
            PairingAction {
                next: PairingState::Idle,
                send: None,
                pin: false,
                notify_code: None,
            }
        }

        // Todo lo demás no corresponde al estado y no hace nada. En particular, un
        // `PairResponse` sin un pedido saliente pendiente (estado `Idle`) es un
        // no-op: no fija, no avisa. Es el caso que cierra el agujero de fijar un
        // par porque mandó `accepted: true` sin que nadie se lo pidiera.
        (state, _) => PairingAction::noop(state),
    }
}

// ── Límites contra abuso (DoS) ───────────────────────────────────────────────

/// Si se admite una conexión nueva, dado cuántas sesiones hay abiertas y el tope.
/// Un par (o algo que se haga pasar por varios) no debe poder abrir sesiones sin
/// fin y agotar la memoria del servicio.
pub fn accept_new_session(current: usize, max: usize) -> bool {
    current < max
}

/// Si una sesión agotó su presupuesto de keepalive: mandó `Ping` y el par no
/// contestó `Pong` las últimas `max` veces seguidas. Una sesión así se cierra en
/// vez de quedar colgada ocupando memoria.
pub fn keepalive_exhausted(missed_pongs: u32, max: u32) -> bool {
    missed_pongs >= max
}

/// Qué hacer con una conexión que llega, según si ya hay una sesión con ese par.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAdmission {
    /// No hay sesión con ese par y hay lugar: se admite.
    Admit,
    /// Ya hay una sesión con ese par: se reemplaza (y hay que **terminar la
    /// vieja**, o quedaría colgada). El reemplazo no cuenta contra el tope: no
    /// suma una sesión, cambia la que hay.
    Replace,
    /// No hay sesión con ese par y no hay lugar: se rechaza.
    Reject,
}

/// Decide si una conexión nueva se admite, reemplaza a la que hay o se rechaza.
///
/// La clave para no dejar colgar tareas: un par que reconecta con el mismo
/// certificado cae en `Replace`, no en una entrada nueva —así el mapa no crece—,
/// pero el reemplazo obliga a terminar la sesión vieja. Y una conexión de un par
/// distinto sólo entra si no se pasó el tope.
pub fn admit_session(slot_occupied: bool, current_count: usize, max: usize) -> SessionAdmission {
    if slot_occupied {
        SessionAdmission::Replace
    } else if accept_new_session(current_count, max) {
        SessionAdmission::Admit
    } else {
        SessionAdmission::Reject
    }
}

/// Si la entrada que hay para un par en el mapa de sesiones es la de **esta**
/// sesión, comparando el id único de sesión.
///
/// Lo usa la limpieza al cerrar: si entró una sesión de reemplazo, la vieja no
/// debe borrar del mapa la entrada de la nueva. Sólo borra si sigue siendo la
/// suya.
pub fn owns_session_slot(current: Option<u64>, mine: u64) -> bool {
    current == Some(mine)
}

/// Recalcula localmente el código de verificación de un pareo **entrante** y lo
/// compara con el que mandó el par.
///
/// El pinning es TOFU (se confía la primera vez), así que este código es la única
/// defensa humana contra un intermediario en el primer pareo: tiene que salir de
/// las dos huellas que vemos nosotros, no del dato que manda el par —si no, un
/// intermediario podría hacer coincidir las dos pantallas—. Devuelve el código
/// local a mostrar si coincide con el declarado, o `None` si no, en cuyo caso el
/// pareo se ignora.
pub fn checked_incoming_code(
    own_fingerprint: &str,
    peer_fingerprint: &str,
    claimed: &str,
) -> Option<String> {
    let local = verification_code(own_fingerprint, peer_fingerprint);
    (local == claimed).then_some(local)
}

// ── Anuncio mDNS: registro TXT ───────────────────────────────────────────────

/// El registro TXT con el que nos anunciamos, como pares clave/valor listos para
/// `mdns-sd`. Lleva lo justo para pintar el aparato y decidir si vale la pena
/// conectarse, sin abrir todavía el TLS.
pub fn build_txt(peer: &PeerInfo) -> Vec<(String, String)> {
    vec![
        (wire::txt::DEVICE_ID.to_string(), peer.device_id.clone()),
        (wire::txt::NAME.to_string(), peer.name.clone()),
        (wire::txt::KIND.to_string(), peer.kind.as_str().to_string()),
        (
            wire::txt::PROTOCOL.to_string(),
            peer.protocol_version.to_string(),
        ),
        (wire::txt::FINGERPRINT.to_string(), peer.fingerprint.clone()),
    ]
}

/// Reconstruye lo que anuncia un par desde su registro TXT.
///
/// Devuelve `None` si falta alguna clave imprescindible (id, nombre o huella) o
/// si la versión no es un número: un anuncio así no sirve para parear ni para
/// mostrar, y es mejor ignorarlo que listar un aparato a medias. Un `kind`
/// desconocido **no** descarta el anuncio —cae en [`DeviceKind::Unknown`]—,
/// igual que en el contrato.
pub fn parse_peer_txt(properties: &HashMap<String, String>) -> Option<PeerInfo> {
    let get = |key: &str| {
        properties
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    };
    let device_id = get(wire::txt::DEVICE_ID)?.to_string();
    let name = get(wire::txt::NAME)?.to_string();
    let fingerprint = get(wire::txt::FINGERPRINT)?.to_string();
    let protocol_version = get(wire::txt::PROTOCOL)?.parse().ok()?;
    let kind = properties
        .get(wire::txt::KIND)
        .map(|k| DeviceKind::parse(k))
        .unwrap_or(DeviceKind::Unknown);
    Some(PeerInfo {
        device_id,
        name,
        kind,
        protocol_version,
        fingerprint,
    })
}

// ── Nombre del equipo ────────────────────────────────────────────────────────

/// El nombre que ve la persona del otro lado, sacado del contenido de
/// `/etc/hostname`.
///
/// Se separa de la lectura del archivo para poder probar la regla: un hostname
/// vacío, en blanco o ausente cae a un nombre genérico en vez de anunciarse como
/// un aparato sin nombre.
pub fn self_name(etc_hostname: Option<&str>) -> String {
    etc_hostname
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("VasakOS")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(fingerprint: &str) -> PeerInfo {
        PeerInfo {
            device_id: "abc123".into(),
            name: "Pixel 8".into(),
            kind: DeviceKind::Phone,
            protocol_version: PROTOCOL_VERSION,
            fingerprint: fingerprint.into(),
        }
    }

    #[test]
    fn la_huella_sigue_el_formato_de_openssl() {
        // SHA-256 de la entrada vacía, conocido.
        assert_eq!(
            fingerprint_from_der(b""),
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
        );
        let fp = fingerprint_from_der(b"cert");
        assert_eq!(fp.len(), 32 * 3 - 1);
        assert_eq!(fp, fp.to_ascii_uppercase());
    }

    #[test]
    fn el_id_del_aparato_sale_de_la_huella_sin_dos_puntos_y_en_minusculas() {
        assert_eq!(device_id_from_fingerprint("AB:CD:0F"), "abcd0f");
        let fp = fingerprint_from_der(b"cert");
        let id = device_id_from_fingerprint(&fp);
        assert_eq!(id.len(), 64);
        assert!(!id.contains(':'));
    }

    #[test]
    fn las_huellas_se_comparan_sin_importar_caso_ni_bordes() {
        assert!(fingerprints_equal("AB:CD", " ab:cd "));
        assert!(!fingerprints_equal("AB:CD", "AB:CE"));
    }

    #[test]
    fn el_largo_del_marco_es_big_endian() {
        assert_eq!(frame_len([0, 0, 1, 0]), 256);
        assert_eq!(frame_len([0, 0, 0, 0]), 0);
    }

    #[test]
    fn un_marco_vacio_se_rechaza() {
        assert_eq!(check_frame_len(0), Err(FrameError::Empty));
    }

    #[test]
    fn un_marco_sobre_el_tope_se_rechaza_sin_reservar_memoria() {
        assert_eq!(MAX_FRAME, 1024 * 1024);
        assert_eq!(check_frame_len(MAX_FRAME), Ok(MAX_FRAME));
        assert_eq!(
            check_frame_len(MAX_FRAME + 1),
            Err(FrameError::TooLarge(MAX_FRAME + 1))
        );
        // Un largo de 4 GiB anunciado en la cabecera.
        assert_eq!(
            check_frame_len(frame_len([0xFF; 4])),
            Err(FrameError::TooLarge(u32::MAX as usize))
        );
    }

    #[test]
    fn un_mensaje_codificado_se_decodifica_igual() {
        let messages = [
            Message::Ping,
            Message::Hello(peer("AA:BB")),
            Message::Clipboard {
                text: "hola ñandú".into(),
            },
        ];
        for message in messages {
            let framed = encode_frame(&message);
            let header: [u8; 4] = framed[..4].try_into().unwrap();
            assert_eq!(frame_len(header), framed.len() - 4);
            assert_eq!(decode_frame(&framed[4..]), Ok(message));
        }
    }

    #[test]
    fn un_cuerpo_corrupto_o_truncado_es_error_y_no_panico() {
        assert_eq!(decode_frame(b"no es json"), Err(FrameError::Malformed));
        assert_eq!(decode_frame(b"{\"type\":"), Err(FrameError::Malformed));
        let framed = encode_frame(&Message::Hello(peer("AA")));
        let body = &framed[4..];
        assert_eq!(
            decode_frame(&body[..body.len() / 2]),
            Err(FrameError::Malformed)
        );
    }

    #[test]
    fn los_errores_de_marco_se_explican_en_texto() {
        assert!(FrameError::TooLarge(5).to_string().contains('5'));
        assert!(!FrameError::Empty.to_string().is_empty());
        assert!(!FrameError::Malformed.to_string().is_empty());
    }

    #[test]
    fn un_par_pareado_con_la_misma_huella_es_de_confianza() {
        assert_eq!(
            evaluate_peer_cert("AA:BB", Some("aa:bb")),
            TrustDecision::Trusted
        );
    }

    #[test]
    fn un_par_pareado_con_otra_huella_se_rechaza() {
        assert_eq!(
            evaluate_peer_cert("AA:BB", Some("CC:DD")),
            TrustDecision::Reject
        );
    }

    #[test]
    fn un_par_sin_fijar_queda_sin_parear() {
        assert_eq!(evaluate_peer_cert("AA:BB", None), TrustDecision::Unpaired);
    }

    #[test]
    fn solo_la_version_del_protocolo_propia_es_compatible() {
        assert!(protocol_compatible(PROTOCOL_VERSION));
        assert!(!protocol_compatible(PROTOCOL_VERSION + 1));
    }

    #[test]
    fn un_hello_valido_pasa() {
        assert_eq!(verify_hello(&peer("AA:BB"), "aa:bb"), Ok(()));
    }

    #[test]
    fn un_hello_de_version_incompatible_se_rechaza() {
        let mut p = peer("AA:BB");
        p.protocol_version = PROTOCOL_VERSION + 1;
        assert_eq!(
            verify_hello(&p, "AA:BB"),
            Err(HelloError::IncompatibleVersion(PROTOCOL_VERSION + 1))
        );
    }

    #[test]
    fn un_hello_con_huella_que_no_es_la_del_tls_se_rechaza() {
        assert_eq!(
            verify_hello(&peer("AA:BB"), "CC:DD"),
            Err(HelloError::FingerprintMismatch)
        );
        assert!(!HelloError::FingerprintMismatch.to_string().is_empty());
        assert!(HelloError::IncompatibleVersion(9).to_string().contains('9'));
    }

    #[test]
    fn el_codigo_de_verificacion_es_el_del_contrato() {
        assert_eq!(
            verification_code("AA", "BB"),
            wire::verification_code("AA", "BB")
        );
    }

    fn txt_map(peer: &PeerInfo) -> HashMap<String, String> {
        build_txt(peer).into_iter().collect()
    }

    #[test]
    fn el_registro_txt_va_y_vuelve() {
        let original = peer("AA:BB");
        assert_eq!(parse_peer_txt(&txt_map(&original)), Some(original));
    }

    #[test]
    fn un_anuncio_al_que_le_faltan_claves_se_ignora() {
        for key in [
            wire::txt::DEVICE_ID,
            wire::txt::NAME,
            wire::txt::FINGERPRINT,
            wire::txt::PROTOCOL,
        ] {
            let mut map = txt_map(&peer("AA:BB"));
            map.remove(key);
            assert_eq!(parse_peer_txt(&map), None, "sin {key}");
            // Presente pero vacía es lo mismo que ausente.
            map.insert(key.to_string(), String::new());
            assert_eq!(parse_peer_txt(&map), None, "{key} vacía");
        }
    }

    #[test]
    fn un_anuncio_con_version_no_numerica_se_ignora() {
        let mut map = txt_map(&peer("AA:BB"));
        map.insert(wire::txt::PROTOCOL.to_string(), "uno".into());
        assert_eq!(parse_peer_txt(&map), None);
    }

    #[test]
    fn un_tipo_desconocido_o_ausente_no_descarta_el_anuncio() {
        let mut map = txt_map(&peer("AA:BB"));
        map.insert(wire::txt::KIND.to_string(), "fridge".into());
        assert_eq!(parse_peer_txt(&map).unwrap().kind, DeviceKind::Unknown);
        map.remove(wire::txt::KIND);
        assert_eq!(parse_peer_txt(&map).unwrap().kind, DeviceKind::Unknown);
    }

    #[test]
    fn el_nombre_del_equipo_cae_a_uno_generico_si_no_hay() {
        assert_eq!(self_name(Some("lince\n")), "lince");
        assert_eq!(self_name(Some("  \n")), "VasakOS");
        assert_eq!(self_name(Some("")), "VasakOS");
        assert_eq!(self_name(None), "VasakOS");
    }

    fn pending_out() -> PairingState {
        PairingState::OutgoingPending {
            code: "123456".into(),
            peer_accepted: false,
        }
    }

    fn pending_in() -> PairingState {
        PairingState::IncomingPending {
            code: "123456".into(),
        }
    }

    #[test]
    fn un_pair_response_no_pedido_no_fija_a_nadie() {
        // El bug crítico: sin un pedido saliente pendiente, un `accepted: true`
        // del par no puede volver a ese par de confianza.
        let action = advance_pairing(
            &PairingState::Idle,
            PairingEvent::PeerResponse { accepted: true },
        );
        assert!(!action.pin);
        assert_eq!(action.next, PairingState::Idle);
        assert_eq!(action.send, None);
        assert_eq!(action.notify_code, None);
    }

    #[test]
    fn iniciar_el_pareo_manda_el_pedido_y_muestra_el_codigo_sin_fijar() {
        let action = advance_pairing(
            &PairingState::Idle,
            PairingEvent::LocalInitiate { code: "111".into() },
        );
        assert!(!action.pin);
        assert_eq!(
            action.next,
            PairingState::OutgoingPending {
                code: "111".into(),
                peer_accepted: false
            }
        );
        assert_eq!(
            action.send,
            Some(Message::PairRequest {
                verification: "111".into()
            })
        );
        assert_eq!(action.notify_code.as_deref(), Some("111"));
    }

    #[test]
    fn un_pedido_del_par_muestra_el_codigo_y_espera_sin_fijar() {
        let action = advance_pairing(
            &PairingState::Idle,
            PairingEvent::PeerRequest { code: "222".into() },
        );
        assert!(!action.pin);
        assert_eq!(
            action.next,
            PairingState::IncomingPending { code: "222".into() }
        );
        assert_eq!(action.notify_code.as_deref(), Some("222"));
        assert_eq!(action.send, None);
    }

    #[test]
    fn el_par_que_acepta_nuestro_pedido_se_anota_pero_no_se_fija() {
        let action = advance_pairing(
            &pending_out(),
            PairingEvent::PeerResponse { accepted: true },
        );
        assert!(!action.pin);
        assert_eq!(
            action.next,
            PairingState::OutgoingPending {
                code: "123456".into(),
                peer_accepted: true
            }
        );
        assert_eq!(action.notify_code.as_deref(), Some("123456"));
    }

    #[test]
    fn confirmar_un_pedido_saliente_fija_al_par() {
        let action = advance_pairing(&pending_out(), PairingEvent::LocalConfirm { accept: true });
        assert!(action.pin);
        assert_eq!(action.next, PairingState::Idle);
    }

    #[test]
    fn confirmar_un_pedido_entrante_fija_y_contesta_que_si() {
        let action = advance_pairing(&pending_in(), PairingEvent::LocalConfirm { accept: true });
        assert!(action.pin);
        assert_eq!(action.next, PairingState::Idle);
        assert_eq!(action.send, Some(Message::PairResponse { accepted: true }));
    }

    #[test]
    fn confirmar_sin_nada_pendiente_no_fija() {
        for accept in [true, false] {
            let action =
                advance_pairing(&PairingState::Idle, PairingEvent::LocalConfirm { accept });
            assert!(!action.pin, "accept={accept}");
            assert_eq!(action.next, PairingState::Idle);
            assert_eq!(action.send, None);
        }
    }

    #[test]
    fn los_rechazos_no_fijan_y_vuelven_a_reposo() {
        let par_rechaza = advance_pairing(
            &pending_out(),
            PairingEvent::PeerResponse { accepted: false },
        );
        assert!(!par_rechaza.pin);
        assert_eq!(par_rechaza.next, PairingState::Idle);

        let local_rechaza_saliente =
            advance_pairing(&pending_out(), PairingEvent::LocalConfirm { accept: false });
        assert!(!local_rechaza_saliente.pin);
        assert_eq!(local_rechaza_saliente.next, PairingState::Idle);

        let local_rechaza_entrante =
            advance_pairing(&pending_in(), PairingEvent::LocalConfirm { accept: false });
        assert!(!local_rechaza_entrante.pin);
        assert_eq!(local_rechaza_entrante.next, PairingState::Idle);
        assert_eq!(
            local_rechaza_entrante.send,
            Some(Message::PairResponse { accepted: false })
        );
    }

    #[test]
    fn un_pair_response_con_un_pedido_entrante_no_fija() {
        let action = advance_pairing(&pending_in(), PairingEvent::PeerResponse { accepted: true });
        assert!(!action.pin);
        assert_eq!(action.next, pending_in());
    }

    #[test]
    fn solo_se_admiten_sesiones_por_debajo_del_tope() {
        assert!(accept_new_session(0, 3));
        assert!(accept_new_session(2, 3));
        assert!(!accept_new_session(3, 3));
        assert!(!accept_new_session(4, 3));
    }

    #[test]
    fn el_keepalive_se_agota_al_alcanzar_el_maximo() {
        assert!(!keepalive_exhausted(0, 3));
        assert!(!keepalive_exhausted(2, 3));
        assert!(keepalive_exhausted(3, 3));
        assert!(keepalive_exhausted(4, 3));
    }

    #[test]
    fn en_el_tope_un_par_nuevo_se_rechaza_y_uno_existente_reemplaza() {
        // La defensa contra el DoS: en el tope no entran pares nuevos, pero quien
        // ya tiene sesión puede reconectar sin que el mapa crezca.
        assert_eq!(admit_session(false, 3, 3), SessionAdmission::Reject);
        assert_eq!(admit_session(false, 9, 3), SessionAdmission::Reject);
        assert_eq!(admit_session(true, 3, 3), SessionAdmission::Replace);
    }

    #[test]
    fn con_lugar_y_sin_sesion_previa_se_admite() {
        assert_eq!(admit_session(false, 0, 3), SessionAdmission::Admit);
        assert_eq!(admit_session(false, 2, 3), SessionAdmission::Admit);
    }

    #[test]
    fn un_slot_ocupado_siempre_reemplaza() {
        assert_eq!(admit_session(true, 0, 3), SessionAdmission::Replace);
        assert_eq!(admit_session(true, 1, 3), SessionAdmission::Replace);
        assert_eq!(admit_session(true, 99, 3), SessionAdmission::Replace);
    }

    #[test]
    fn la_limpieza_solo_borra_la_entrada_propia() {
        assert!(owns_session_slot(Some(7), 7));
        // Entró una sesión de reemplazo: la vieja no es dueña del slot.
        assert!(!owns_session_slot(Some(8), 7));
        assert!(!owns_session_slot(None, 7));
    }

    #[test]
    fn un_codigo_declarado_que_no_coincide_se_ignora() {
        let real = verification_code("AA:BB", "CC:DD");
        assert_eq!(checked_incoming_code("AA:BB", "CC:DD", "000000"), None);
        assert_eq!(checked_incoming_code("AA:BB", "CC:DD", ""), None);
        // Un intermediario que declara el código de otro par de huellas.
        let ajeno = verification_code("AA:BB", "EE:FF");
        assert_ne!(ajeno, real);
        assert_eq!(checked_incoming_code("AA:BB", "CC:DD", &ajeno), None);
    }

    #[test]
    fn un_codigo_correcto_devuelve_el_recalculado_localmente() {
        let real = verification_code("AA:BB", "CC:DD");
        assert_eq!(
            checked_incoming_code("AA:BB", "CC:DD", &real),
            Some(real.clone())
        );
        // El código no depende de cuál huella es la propia.
        assert_eq!(
            checked_incoming_code("CC:DD", "AA:BB", &real),
            Some(real.clone())
        );
        // Lo declarado se compara exacto: con espacios no es el mismo código, y lo
        // que se devuelve nunca es el texto del par.
        assert_eq!(
            checked_incoming_code("AA:BB", "CC:DD", &format!(" {real} ")),
            None
        );
    }
}
