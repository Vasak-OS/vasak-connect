//! Toda la lógica del canal que se decide **sin** red, TLS, D-Bus ni llavero.
//!
//! Está junta y aislada a propósito: es lo que se puede probar de verdad —y lo
//! que la puerta de cobertura mira—, mientras que el código que toca sockets,
//! rustls o el Secret Service queda fino y delega acá cada decisión. Si una
//! regla de seguridad se puede escribir como una función de entradas a salida
//! (qué huella aceptar, qué marco rechazar, qué `Hello` es válido), vive en este
//! módulo y no en el medio de un bucle de lectura.

use std::collections::HashMap;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vasak_connect_protocol::wire::{
    self, BatteryStatus, DeviceKind, Message, PeerInfo, PROTOCOL_VERSION,
};

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

/// Si una clave guardada y un certificado en disco son el **mismo par**,
/// comparando la huella que se guardó junto a la clave con la del certificado.
///
/// Es la defensa contra un corte entre guardar la clave y escribir el
/// certificado: si quedan de generaciones distintas, sus huellas no coinciden y
/// el par se regenera entero en vez de arrancar con una clave y un certificado
/// que no se corresponden —con los que el TLS fallaría siempre—. Sin huella
/// guardada (`None`) se considera inconsistente, para forzar la regeneración.
pub fn identity_pair_matches(stored_cert_fingerprint: Option<&str>, cert_der: &[u8]) -> bool {
    match stored_cert_fingerprint {
        Some(stored) => fingerprints_equal(stored, &fingerprint_from_der(cert_der)),
        None => false,
    }
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

// ── SAS con compromiso (RFC 6189) ────────────────────────────────────────────
//
// El pareo ya no deriva un código de dos huellas públicas de larga vida —que un
// intermediario on-path podría grindear offline hasta que las dos pantallas
// coincidan—. Ahora las dos puntas hacen un Diffie-Hellman efímero (X25519) y el
// SAS sale del secreto compartido, atado además a las dos huellas de certificado.
// El iniciador se **compromete** a su clave DH antes de ver la del par
// (commit-then-reveal), así no puede elegirla después para forzar un SAS: sin el
// compromiso, grindear 10^6 claves hasta un SAS de seis dígitos sería barato.

/// El compromiso a una clave DH efímera: `hex(SHA-256(dh_pub))`.
///
/// El iniciador lo manda en el `PairRequest` antes de revelar su clave. Como es
/// un hash de la clave, no deja deducirla, pero lo ata: al revelar la clave, el
/// respondedor comprueba que su hash sea éste ([`verify_commitment`]).
pub fn sas_commitment(dh_pub: &[u8]) -> String {
    hex::encode(Sha256::digest(dh_pub))
}

/// Comprueba que una clave DH revelada corresponda al compromiso recibido,
/// recomputando `SHA-256(dh_pub)` y comparándolo **en tiempo constante**.
///
/// La comparación en tiempo constante evita filtrar por tiempo cuántos
/// caracteres del compromiso coinciden; un compromiso con otro largo del
/// esperado da `false` sin más (el largo no es secreto). Que dé `false` es la
/// señal de que el par reveló una clave distinta de la que se comprometió —un
/// intermediario—, y el pareo se aborta.
pub fn verify_commitment(expected_hex: &str, dh_pub: &[u8]) -> bool {
    let computed = hex::encode(Sha256::digest(dh_pub));
    computed.as_bytes().ct_eq(expected_hex.as_bytes()).into()
}

/// Deriva el SAS de seis dígitos que las dos pantallas muestran, idéntico en
/// ambos lados.
///
/// Sale de HKDF-SHA256 sobre el secreto compartido del DH, con un label de
/// dominio como sal e `info = init_pub || resp_pub || init_fp || resp_fp`. El
/// orden es **siempre el iniciador primero** —los dos lados saben quién inició—,
/// así las dos puntas derivan el mismo número. Incluir las dos huellas de
/// certificado ata el SAS acordado a los certificados exactos que se van a fijar:
/// si un intermediario cambiara un certificado después de acordar el SAS, el
/// número no coincidiría.
pub fn derive_sas(
    shared: &[u8],
    init_pub: &[u8],
    resp_pub: &[u8],
    init_fp: &str,
    resp_fp: &str,
) -> String {
    let hk = Hkdf::<Sha256>::new(Some(b"VASAK-SAS-v2"), shared);
    let mut info =
        Vec::with_capacity(init_pub.len() + resp_pub.len() + init_fp.len() + resp_fp.len());
    info.extend_from_slice(init_pub);
    info.extend_from_slice(resp_pub);
    info.extend_from_slice(init_fp.as_bytes());
    info.extend_from_slice(resp_fp.as_bytes());
    let mut okm = [0u8; 8];
    // `expand` sólo falla si se piden más de 255*32 bytes; ocho entran de sobra,
    // así que esto no puede fallar con un dato de red —es una invariante del
    // largo fijo, no una entrada—.
    hk.expand(&info, &mut okm)
        .expect("ocho bytes caben en un OKM de HKDF-SHA256");
    let value = u64::from_be_bytes(okm) % 1_000_000;
    format!("{value:06}")
}

// ── Máquina de estados del pareo ─────────────────────────────────────────────
//
// La invariante que esta máquina hace cumplir: **un par se fija como de confianza
// SÓLO cuando la persona local confirma el SAS** (`PairingEvent::LocalConfirm
// { accept: true }` sobre un pareo pendiente). Ningún mensaje del par —ni un
// `PairResponse { accepted: true }` no pedido— vuelve a un par de confianza por
// sí solo. Toda la lógica del pareo pasa por `advance_pairing`, que es pura: el
// código de red sólo aplica lo que ésta decide (mandar un mensaje, fijar, avisar,
// abortar). El SAS lo deriva el código del canal del secreto compartido del DH
// ([`derive_sas`]) y se lo pasa a esta máquina en el evento; acá sólo se enruta.

/// El estado del pareo de una sesión.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PairingState {
    /// Sin pareo en curso.
    #[default]
    Idle,
    /// Iniciador: mandamos el `PairRequest` con nuestro compromiso y esperamos
    /// que el par revele su clave DH (`PairDh`). Todavía no hay SAS: falta el
    /// aporte del par.
    OutgoingCommitted,
    /// Iniciador: ya revelamos nuestra clave y derivamos el SAS; esperamos la
    /// confirmación local y la respuesta del par. `peer_accepted` dice si el par
    /// ya contestó que sí; aun así no se fija hasta la confirmación local.
    OutgoingPending { sas: String, peer_accepted: bool },
    /// Iniciador: la persona local **ya confirmó** el SAS y falta la respuesta
    /// del par. Se fija recién cuando el par acepta: así, si la confirmación
    /// local llega antes que el `PairResponse`, un `accepted: false` posterior
    /// cancela en vez de dejar fijado a un par que rechazó.
    OutgoingConfirmed { sas: String },
    /// Respondedor: el par pidió parear y guardamos su compromiso; ya revelamos
    /// nuestra clave DH (`PairDh`) y esperamos que revele la suya (`PairReveal`)
    /// para verificar el compromiso. Todavía no hay SAS.
    IncomingCommitted { commitment: String },
    /// Respondedor: el par reveló su clave, el compromiso verificó y derivamos el
    /// SAS; esperamos la confirmación local.
    IncomingPending { sas: String },
}

/// Lo que mueve la máquina de pareo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingEvent {
    /// La persona local pidió iniciar el pareo (`request_pairing`). El canal ya
    /// generó la clave DH efímera y calculó el `commitment`.
    LocalInitiate { commitment: String },
    /// Llegó un `PairRequest` del par. El canal ya generó nuestra clave DH; pasa
    /// el `commitment` del par y nuestra clave pública en hex (`own_dh_pub`) para
    /// revelarla en el `PairDh`.
    PeerRequest {
        commitment: String,
        own_dh_pub: String,
    },
    /// Llegó un `PairDh` del par (reveló su clave, somos el iniciador). El canal
    /// ya computó el secreto compartido y derivó el SAS; `reveal` es nuestra
    /// clave en hex, a mandar en el `PairReveal`.
    PeerDh { reveal: String, sas: String },
    /// Llegó un `PairReveal` del par (reveló su clave, somos el respondedor).
    /// `revealed` son los bytes crudos de su clave, que se verifican contra el
    /// `commitment` guardado; `sas` es el que el canal derivó del secreto
    /// compartido.
    PeerReveal { revealed: Vec<u8>, sas: String },
    /// Llegó un `PairResponse` del par.
    PeerResponse { accepted: bool },
    /// La persona local confirmó o rechazó (`confirm_pairing`).
    LocalConfirm { accept: bool },
}

/// Qué hacer tras un evento: a qué estado pasar, qué mandarle al par, si fijarlo
/// como de confianza, si avisar a la persona con el SAS, y si abortar la sesión.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingAction {
    pub next: PairingState,
    /// Mensaje a mandarle al par, si corresponde.
    pub send: Option<Message>,
    /// Fijar al par como de confianza. **Sólo es `true` en respuesta a
    /// `LocalConfirm { accept: true }` sobre un pareo pendiente.**
    pub pin: bool,
    /// SAS a mostrarle a la persona (emitir `pairing_requested`), si hay que
    /// pedirle una confirmación.
    pub notify_code: Option<String>,
    /// Abortar: el compromiso no verificó (señal del intermediario). El canal
    /// cierra y resetea la sesión; nunca se fija nada.
    pub abort: bool,
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
            abort: false,
        }
    }

    /// Cancela el pareo: vuelve a reposo sin fijar nada. No cierra la sesión.
    fn cancel() -> Self {
        PairingAction {
            next: PairingState::Idle,
            send: None,
            pin: false,
            notify_code: None,
            abort: false,
        }
    }

    /// Fija al par y vuelve a reposo. Es la única salida con `pin: true`.
    fn pinned() -> Self {
        PairingAction {
            next: PairingState::Idle,
            send: None,
            pin: true,
            notify_code: None,
            abort: false,
        }
    }
}

/// La transición de la máquina de pareo. Pura: no toca red, estado compartido ni
/// reloj; devuelve qué hacer y el código de red lo aplica.
pub fn advance_pairing(state: &PairingState, event: PairingEvent) -> PairingAction {
    match (state, event) {
        // Iniciamos nosotros: mandamos el compromiso y esperamos la clave DH del
        // par. Todavía no hay SAS que mostrar.
        (PairingState::Idle, PairingEvent::LocalInitiate { commitment }) => PairingAction {
            next: PairingState::OutgoingCommitted,
            send: Some(Message::PairRequest { commitment }),
            pin: false,
            notify_code: None,
            abort: false,
        },

        // El par pide parear y se compromete: guardamos su compromiso y revelamos
        // nuestra clave DH. No se fija nada ni se muestra SAS: falta que el par
        // revele su clave para verificar el compromiso y derivar el SAS.
        (
            PairingState::Idle,
            PairingEvent::PeerRequest {
                commitment,
                own_dh_pub,
            },
        ) => PairingAction {
            next: PairingState::IncomingCommitted { commitment },
            send: Some(Message::PairDh { dh_pub: own_dh_pub }),
            pin: false,
            notify_code: None,
            abort: false,
        },

        // Somos el iniciador y el par reveló su clave: revelamos la nuestra, ya
        // derivamos el SAS y lo mostramos. Esperamos la confirmación local y el
        // `PairResponse`.
        (PairingState::OutgoingCommitted, PairingEvent::PeerDh { reveal, sas }) => PairingAction {
            next: PairingState::OutgoingPending {
                sas: sas.clone(),
                peer_accepted: false,
            },
            send: Some(Message::PairReveal { dh_pub: reveal }),
            pin: false,
            notify_code: Some(sas),
            abort: false,
        },

        // Somos el respondedor y el par reveló su clave: se verifica que su hash
        // coincida con el compromiso guardado, en tiempo constante. Si no
        // coincide, el par reveló una clave distinta de la que se comprometió —un
        // intermediario— y se aborta sin fijar nada. Si coincide, mostramos el SAS
        // y esperamos la confirmación local.
        (
            PairingState::IncomingCommitted { commitment },
            PairingEvent::PeerReveal { revealed, sas },
        ) => {
            if verify_commitment(commitment, &revealed) {
                PairingAction {
                    next: PairingState::IncomingPending { sas: sas.clone() },
                    send: None,
                    pin: false,
                    notify_code: Some(sas),
                    abort: false,
                }
            } else {
                PairingAction {
                    next: PairingState::Idle,
                    send: None,
                    pin: false,
                    notify_code: None,
                    abort: true,
                }
            }
        }

        // El par acepta nuestro pedido: lo anotamos, pero **no se fija**: falta la
        // confirmación local. Se vuelve a mostrar el SAS para que la persona pueda
        // confirmar.
        (
            PairingState::OutgoingPending { sas, .. },
            PairingEvent::PeerResponse { accepted: true },
        ) => PairingAction {
            next: PairingState::OutgoingPending {
                sas: sas.clone(),
                peer_accepted: true,
            },
            send: None,
            pin: false,
            notify_code: Some(sas.clone()),
            abort: false,
        },

        // El par rechaza nuestro pedido: se cancela.
        (PairingState::OutgoingPending { .. }, PairingEvent::PeerResponse { accepted: false }) => {
            PairingAction::cancel()
        }

        // La persona confirma un pedido saliente **que el par ya aceptó**: los dos
        // aceptaron, se fija. No hace falta avisarle nada más al par.
        (
            PairingState::OutgoingPending {
                peer_accepted: true,
                ..
            },
            PairingEvent::LocalConfirm { accept: true },
        ) => PairingAction::pinned(),

        // La persona confirma un pedido saliente **antes de que el par conteste**:
        // se anota la confirmación local y se espera; recién se fija cuando el par
        // acepte. Si el par rechaza después, se cancela sin haber fijado.
        (
            PairingState::OutgoingPending {
                sas,
                peer_accepted: false,
            },
            PairingEvent::LocalConfirm { accept: true },
        ) => PairingAction {
            next: PairingState::OutgoingConfirmed { sas: sas.clone() },
            send: None,
            pin: false,
            notify_code: None,
            abort: false,
        },

        // Ya confirmamos localmente y el par acepta: los dos aceptaron, se fija.
        (PairingState::OutgoingConfirmed { .. }, PairingEvent::PeerResponse { accepted: true }) => {
            PairingAction::pinned()
        }

        // Ya confirmamos localmente pero el par rechaza: se cancela sin fijar. Es
        // el caso que el bug dejaba pasar —fijaba igual—.
        (
            PairingState::OutgoingConfirmed { .. },
            PairingEvent::PeerResponse { accepted: false },
        ) => PairingAction::cancel(),

        // Ya confirmamos localmente y la persona se arrepiente: se cancela.
        (PairingState::OutgoingConfirmed { .. }, PairingEvent::LocalConfirm { accept: false }) => {
            PairingAction::cancel()
        }

        // La persona confirma un pedido entrante: se fija y se le contesta que sí
        // al par.
        (PairingState::IncomingPending { .. }, PairingEvent::LocalConfirm { accept: true }) => {
            PairingAction {
                next: PairingState::Idle,
                send: Some(Message::PairResponse { accepted: true }),
                pin: true,
                notify_code: None,
                abort: false,
            }
        }

        // La persona rechaza un pedido entrante: se le avisa al par que no.
        (PairingState::IncomingPending { .. }, PairingEvent::LocalConfirm { accept: false }) => {
            PairingAction {
                next: PairingState::Idle,
                send: Some(Message::PairResponse { accepted: false }),
                pin: false,
                notify_code: None,
                abort: false,
            }
        }

        // La persona rechaza un pedido saliente: se cancela sin fijar.
        (PairingState::OutgoingPending { .. }, PairingEvent::LocalConfirm { accept: false }) => {
            PairingAction::cancel()
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

/// La etiqueta de instancia DNS-SD para un `device_id`.
///
/// Una etiqueta DNS-SD no pasa de 63 octetos, así que se recorta a 40 **por
/// caracteres**, no por bytes: cortar `&id[..40]` a secas revienta con un
/// `panic` si el byte 40 cae en medio de un carácter multibyte, y el `device_id`
/// de descubrimiento sale de un anuncio ajeno. Con caracteres el corte siempre es
/// válido. Nuestros ids son hexadecimales (ASCII), pero esto lo deja a salvo de un
/// id hostil que no lo sea.
pub fn mdns_instance_label(device_id: &str) -> String {
    device_id.chars().take(40).collect()
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

/// Decide qué hacer con un estado de batería que empuja un par, en el borde de
/// confianza de la red.
///
/// Devuelve `None` —y no se muestra nada— si el par no está pareado: un aparato
/// sin parear no empuja estado nuestro. Si está pareado, el nivel se **recorta a
/// 0–100**: `level` es un `u8` que por el cable puede llegar hasta 255, y un par
/// malicioso o con un bug no debe poder pintar "237 %" en el panel.
pub fn sanitize_incoming_battery(paired: bool, raw: BatteryStatus) -> Option<BatteryStatus> {
    if !paired {
        return None;
    }
    Some(BatteryStatus {
        level: raw.level.min(100),
        charging: raw.charging,
    })
}

/// Decide qué hacer con un texto de portapapeles que empuja un par.
///
/// `None` si el par no está pareado —escribir en el portapapeles de quien usa el
/// sistema desde un aparato sin parear es una inyección— o si el texto es vacío,
/// que no aporta nada. El tope de tamaño ya lo pone el marco ([`MAX_FRAME`]).
pub fn accept_incoming_clipboard(paired: bool, text: String) -> Option<String> {
    if !paired || text.is_empty() {
        return None;
    }
    Some(text)
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

    // Las pruebas de la máquina de pareo con compromiso (iniciar, el ciclo
    // commit→reveal, la verificación del commitment y el aborto, fijar sólo con
    // la confirmación local en cualquier orden) las escribe `qa` sobre la API
    // nueva. Acá quedan sólo las dos invariantes que no dependen de la forma de
    // los estados: un mensaje del par en reposo no fija ni avisa.

    #[test]
    fn un_pair_response_no_pedido_no_fija_a_nadie() {
        // El bug crítico: sin un pedido saliente pendiente, un `accepted: true`
        // del par no puede volver a ese par de confianza.
        let action = advance_pairing(
            &PairingState::Idle,
            PairingEvent::PeerResponse { accepted: true },
        );
        assert!(!action.pin);
        assert!(!action.abort);
        assert_eq!(action.next, PairingState::Idle);
        assert_eq!(action.send, None);
        assert_eq!(action.notify_code, None);
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

    // ── SAS con compromiso (RFC 6189) ────────────────────────────────────────

    #[test]
    fn el_compromiso_es_el_sha256_en_hex_de_la_clave() {
        // SHA-256("abc"), vector conocido.
        assert_eq!(
            sas_commitment(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn el_compromiso_verifica_solo_con_la_clave_comprometida() {
        let key = [7u8; 32];
        let commitment = sas_commitment(&key);
        assert!(verify_commitment(&commitment, &key));

        let mut other = key;
        other[31] ^= 1;
        assert!(!verify_commitment(&commitment, &other));
    }

    #[test]
    fn un_compromiso_de_otro_largo_se_rechaza_sin_panico() {
        let key = [7u8; 32];
        let commitment = sas_commitment(&key);
        assert!(!verify_commitment("", &key));
        assert!(!verify_commitment(
            &commitment[..commitment.len() - 1],
            &key
        ));
        assert!(!verify_commitment(&format!("{commitment}00"), &key));
    }

    const SHARED: [u8; 32] = [1; 32];
    const INIT_PUB: [u8; 32] = [2; 32];
    const RESP_PUB: [u8; 32] = [3; 32];

    fn sas() -> String {
        derive_sas(&SHARED, &INIT_PUB, &RESP_PUB, "AA:BB", "CC:DD")
    }

    #[test]
    fn el_sas_es_determinista_y_de_seis_digitos() {
        assert_eq!(sas(), sas());
        for i in 0..50u8 {
            let s = derive_sas(&[i; 32], &INIT_PUB, &RESP_PUB, "AA:BB", "CC:DD");
            assert_eq!(s.len(), 6, "{s}");
            assert!(s.bytes().all(|b| b.is_ascii_digit()), "{s}");
        }
    }

    #[test]
    fn el_sas_cambia_si_cambia_cualquier_entrada() {
        let base = sas();
        let mut other_shared = SHARED;
        other_shared[0] ^= 1;
        let mut other_init = INIT_PUB;
        other_init[0] ^= 1;
        let mut other_resp = RESP_PUB;
        other_resp[0] ^= 1;
        let variants = [
            derive_sas(&other_shared, &INIT_PUB, &RESP_PUB, "AA:BB", "CC:DD"),
            derive_sas(&SHARED, &other_init, &RESP_PUB, "AA:BB", "CC:DD"),
            derive_sas(&SHARED, &INIT_PUB, &other_resp, "AA:BB", "CC:DD"),
            derive_sas(&SHARED, &INIT_PUB, &RESP_PUB, "AA:BC", "CC:DD"),
            derive_sas(&SHARED, &INIT_PUB, &RESP_PUB, "AA:BB", "CC:DE"),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(*v, base, "la variante {i} no cambió el SAS");
        }
    }

    #[test]
    fn los_dos_lados_derivan_el_mismo_sas_con_el_orden_iniciador_primero() {
        use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
        use ring::rand::SystemRandom;
        let rng = SystemRandom::new();
        let a = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let b = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let a_pub = a.compute_public_key().unwrap().as_ref().to_vec();
        let b_pub = b.compute_public_key().unwrap().as_ref().to_vec();
        let shared_a =
            agree_ephemeral(a, &UnparsedPublicKey::new(&X25519, &b_pub), |k| k.to_vec()).unwrap();
        let shared_b =
            agree_ephemeral(b, &UnparsedPublicKey::new(&X25519, &a_pub), |k| k.to_vec()).unwrap();
        assert_eq!(shared_a, shared_b);

        let initiator = derive_sas(&shared_a, &a_pub, &b_pub, "FP-INIT", "FP-RESP");
        let responder = derive_sas(&shared_b, &a_pub, &b_pub, "FP-INIT", "FP-RESP");
        assert_eq!(initiator, responder);
        // Y el orden importa: invertirlo da otro número.
        let swapped = derive_sas(&shared_a, &b_pub, &a_pub, "FP-RESP", "FP-INIT");
        assert_ne!(initiator, swapped);
    }

    #[test]
    fn iniciar_manda_el_compromiso_y_todavia_no_hay_sas_ni_se_fija() {
        let action = advance_pairing(
            &PairingState::Idle,
            PairingEvent::LocalInitiate {
                commitment: "c0ffee".into(),
            },
        );
        assert_eq!(action.next, PairingState::OutgoingCommitted);
        assert_eq!(
            action.send,
            Some(Message::PairRequest {
                commitment: "c0ffee".into()
            })
        );
        assert_eq!(action.notify_code, None);
        assert!(!action.pin);
        assert!(!action.abort);
    }

    #[test]
    fn el_iniciador_completa_commit_reveal_y_fija_solo_con_la_confirmacion_local() {
        let a = advance_pairing(
            &PairingState::Idle,
            PairingEvent::LocalInitiate {
                commitment: "cc".into(),
            },
        );
        let b = advance_pairing(
            &a.next,
            PairingEvent::PeerDh {
                reveal: "aa".into(),
                sas: "123456".into(),
            },
        );
        assert_eq!(
            b.send,
            Some(Message::PairReveal {
                dh_pub: "aa".into()
            })
        );
        assert_eq!(b.notify_code.as_deref(), Some("123456"));
        assert!(!b.pin && !b.abort);

        // La respuesta del par antes de la confirmación local no fija.
        let c = advance_pairing(&b.next, PairingEvent::PeerResponse { accepted: true });
        assert!(!c.pin);
        let d = advance_pairing(&c.next, PairingEvent::LocalConfirm { accept: true });
        assert!(d.pin);
        assert_eq!(d.next, PairingState::Idle);
    }

    #[test]
    fn el_iniciador_no_fija_en_ningun_orden_sin_los_dos_si() {
        let pending = PairingState::OutgoingPending {
            sas: "123456".into(),
            peer_accepted: false,
        };
        // Confirma local y luego el par acepta: fija recién al final.
        let a = advance_pairing(&pending, PairingEvent::LocalConfirm { accept: true });
        assert!(!a.pin);
        assert!(advance_pairing(&a.next, PairingEvent::PeerResponse { accepted: true }).pin);
        // Confirma local y luego el par rechaza: no fija.
        assert!(!advance_pairing(&a.next, PairingEvent::PeerResponse { accepted: false }).pin);
        // El par rechaza primero o la persona rechaza: no fija.
        assert!(!advance_pairing(&pending, PairingEvent::PeerResponse { accepted: false }).pin);
        assert!(!advance_pairing(&pending, PairingEvent::LocalConfirm { accept: false }).pin);
    }

    #[test]
    fn el_respondedor_revela_su_clave_y_espera_sin_sas() {
        let action = advance_pairing(
            &PairingState::Idle,
            PairingEvent::PeerRequest {
                commitment: "cc".into(),
                own_dh_pub: "bb".into(),
            },
        );
        assert_eq!(
            action.next,
            PairingState::IncomingCommitted {
                commitment: "cc".into()
            }
        );
        assert_eq!(
            action.send,
            Some(Message::PairDh {
                dh_pub: "bb".into()
            })
        );
        assert_eq!(action.notify_code, None);
        assert!(!action.pin && !action.abort);
    }

    #[test]
    fn el_respondedor_con_compromiso_valido_muestra_el_sas_y_fija_solo_al_confirmar() {
        let key = vec![9u8; 32];
        let committed = PairingState::IncomingCommitted {
            commitment: sas_commitment(&key),
        };
        let shown = advance_pairing(
            &committed,
            PairingEvent::PeerReveal {
                revealed: key,
                sas: "654321".into(),
            },
        );
        assert!(!shown.abort && !shown.pin);
        assert_eq!(shown.notify_code.as_deref(), Some("654321"));
        assert_eq!(
            shown.next,
            PairingState::IncomingPending {
                sas: "654321".into()
            }
        );

        let yes = advance_pairing(&shown.next, PairingEvent::LocalConfirm { accept: true });
        assert!(yes.pin);
        assert_eq!(yes.send, Some(Message::PairResponse { accepted: true }));

        let no = advance_pairing(&shown.next, PairingEvent::LocalConfirm { accept: false });
        assert!(!no.pin);
        assert_eq!(no.send, Some(Message::PairResponse { accepted: false }));
    }

    #[test]
    fn un_compromiso_que_no_coincide_aborta_sin_fijar_ni_mostrar_sas() {
        // El MITM revela una clave distinta de la comprometida (grindeada).
        let committed = PairingState::IncomingCommitted {
            commitment: sas_commitment(&[1u8; 32]),
        };
        let action = advance_pairing(
            &committed,
            PairingEvent::PeerReveal {
                revealed: vec![2u8; 32],
                sas: "000000".into(),
            },
        );
        assert!(action.abort);
        assert!(!action.pin);
        assert_eq!(action.next, PairingState::Idle);
        assert_eq!(action.notify_code, None);
        assert_eq!(action.send, None);
    }

    #[test]
    fn un_reveal_fuera_de_turno_no_hace_nada() {
        for state in [PairingState::Idle, PairingState::OutgoingCommitted] {
            let action = advance_pairing(
                &state,
                PairingEvent::PeerReveal {
                    revealed: vec![1],
                    sas: "111111".into(),
                },
            );
            assert!(!action.pin && !action.abort);
            assert_eq!(action.next, state);
            assert_eq!(action.notify_code, None);
        }
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
    fn el_par_guardado_que_coincide_con_el_certificado_es_consistente() {
        let fp = fingerprint_from_der(b"cert");
        assert!(identity_pair_matches(Some(&fp), b"cert"));
        assert!(identity_pair_matches(Some(&fp.to_lowercase()), b"cert"));
    }

    #[test]
    fn un_par_desparejo_o_sin_huella_obliga_a_regenerar() {
        let otra = fingerprint_from_der(b"otro cert");
        assert!(!identity_pair_matches(Some(&otra), b"cert"));
        assert!(!identity_pair_matches(None, b"cert"));
    }

    #[test]
    fn la_etiqueta_mdns_se_recorta_por_caracteres_y_no_entra_en_panico() {
        // 39 ASCII + una `é` de dos bytes: el byte 40 cae a mitad de carácter.
        let id = format!("{}{}", "a".repeat(39), "éxyz");
        let label = mdns_instance_label(&id);
        assert_eq!(label.chars().count(), 40);
        assert!(label.ends_with('é'));
        assert!(!label.contains('x'));
        // Un id corto queda igual; uno largo de ASCII se recorta a 40.
        assert_eq!(mdns_instance_label("abc"), "abc");
        assert_eq!(mdns_instance_label(&"f".repeat(64)), "f".repeat(40));
        // Todo multibyte: 40 caracteres, 80 bytes, sin partir ninguno.
        assert_eq!(mdns_instance_label(&"ñ".repeat(50)), "ñ".repeat(40));
    }

    #[test]
    fn el_cupo_reducido_corta_a_los_nuevos_sin_parear_pero_no_a_los_existentes() {
        // `effective_max` = MAX - reserva para los de confianza (8 de 32, p.ej.).
        let reduced = 24;
        assert_eq!(admit_session(false, 23, reduced), SessionAdmission::Admit);
        assert_eq!(admit_session(false, 24, reduced), SessionAdmission::Reject);
        assert_eq!(admit_session(false, 30, reduced), SessionAdmission::Reject);
        // Un par pareado que usa el cupo completo todavía entra, y uno con slot
        // reemplaza aunque el conteo pase el cupo reducido.
        assert_eq!(admit_session(false, 24, 32), SessionAdmission::Admit);
        assert_eq!(admit_session(true, 24, reduced), SessionAdmission::Replace);
    }

    #[test]
    fn la_bateria_de_un_par_sin_parear_se_ignora() {
        let raw = BatteryStatus {
            level: 50,
            charging: true,
        };
        assert_eq!(sanitize_incoming_battery(false, raw), None);
    }

    #[test]
    fn la_bateria_de_un_par_pareado_se_recorta_a_100() {
        let raw = BatteryStatus {
            level: 250,
            charging: false,
        };
        let out = sanitize_incoming_battery(true, raw).expect("pareado: se acepta");
        assert_eq!(out.level, 100);
        assert!(!out.charging);
    }

    #[test]
    fn la_bateria_valida_de_un_par_pareado_pasa_tal_cual() {
        let raw = BatteryStatus {
            level: 80,
            charging: true,
        };
        let out = sanitize_incoming_battery(true, raw).expect("pareado: se acepta");
        assert_eq!(out.level, 80);
        assert!(out.charging);
    }

    #[test]
    fn el_portapapeles_de_un_par_sin_parear_se_ignora() {
        assert_eq!(accept_incoming_clipboard(false, "hola".into()), None);
    }

    #[test]
    fn el_portapapeles_de_un_par_pareado_pasa_tal_cual() {
        assert_eq!(
            accept_incoming_clipboard(true, "hola mundo".into()),
            Some("hola mundo".to_string())
        );
    }

    #[test]
    fn el_portapapeles_vacio_de_un_par_pareado_se_ignora() {
        assert_eq!(accept_incoming_clipboard(true, String::new()), None);
    }
}
