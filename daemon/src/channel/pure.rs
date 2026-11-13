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
