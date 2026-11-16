//! El canal directo teléfono↔escritorio, estilo KDE Connect.
//!
//! Junta las piezas: la identidad TLS ([`identity`]), el transporte mutuo y el
//! enmarcado ([`transport`]), y toda la lógica que se decide sin entorno
//! ([`pure`]). Acá viven el descubrimiento por mDNS, el bucle que acepta
//! conexiones, el manejo de una sesión y el pareo, más la superficie que los
//! métodos de D-Bus de `main` llaman para listar pares, parear, confirmar y
//! desparear.
//!
//! El estado de ejecución del canal cuelga del mismo `State` tras el candado que
//! ya tiene el servicio: los métodos de D-Bus y las tareas del canal lo tocan
//! por ese candado, y nunca lo sostienen mientras esperan un socket.

pub mod identity;
pub mod pure;
pub mod transport;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{interval, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tracing::{debug, info, warn};
use vasak_connect_protocol::wire::{
    BatteryStatus, DeviceKind, Message, PeerInfo, PROTOCOL_VERSION,
};

use crate::{notify, State};
use identity::Identity;
use pure::{
    admit_session, advance_pairing, checked_incoming_code, device_id_from_fingerprint,
    evaluate_peer_cert, keepalive_exhausted, mdns_instance_label, owns_session_slot,
    parse_peer_txt, self_name, verification_code, PairingEvent, PairingState, SessionAdmission,
    TrustDecision,
};
use transport::{peer_fingerprint, read_frame, write_frame, MessageDecoder, SessionError};

/// Numerador de sesiones: le da a cada `handle_session` un id único, para que la
/// limpieza de una sesión vieja no toque la entrada de una de reemplazo.
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(0);

/// Cada cuánto se manda un `Ping` para mantener viva la sesión y notar un corte
/// que el socket todavía no reportó.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// Cuántos `Ping` seguidos sin `Pong` se toleran antes de cerrar la sesión. Una
/// sesión que dejó de contestar no debe quedar colgada ocupando memoria.
const MAX_MISSED_PONGS: u32 = 3;

/// Tope de sesiones abiertas a la vez.
const MAX_CONCURRENT_SESSIONS: usize = 32;

/// Sesiones reservadas para pares de confianza. Un par ya pareado, cuyo
/// certificado fijado verifica, no debe quedar afuera porque un atacante llenó el
/// cupo con sesiones sin parear: las sin parear sólo llegan hasta
/// `MAX_CONCURRENT_SESSIONS - TRUSTED_RESERVE`, y estas quedan para los de
/// confianza.
const TRUSTED_RESERVE: usize = 8;

/// Tope de conexiones a la vez, contando las que todavía no completaron el
/// handshake. Es un techo **antes** de arrancar la tarea de cada conexión, para
/// que un no autenticado no abra muchas dentro de `HANDSHAKE_TIMEOUT`.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Lo que se le da al handshake y al primer `Hello` para completarse. Una
/// conexión que abre el socket y no habla no debe retener una tarea para siempre.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Plazo de una escritura. Un par que manda pero no lee llena el buffer de envío
/// y dejaría una escritura colgada para siempre, con la sesión sin atender el
/// keepalive ni el cierre. Pasado esto, la sesión se da por muerta.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cuánto puede vivir una sesión sin completar el pareo. Una sesión sin parear que
/// se queda ocupando lugar se cierra: así no se puede tener el cupo lleno de
/// sesiones a medio parear para siempre.
const PAIR_TIMEOUT: Duration = Duration::from_secs(120);

/// Lo que un par anunció por mDNS y dónde alcanzarlo.
pub struct Discovered {
    pub peer: PeerInfo,
    pub address: SocketAddr,
    /// El nombre completo del servicio mDNS, para poder sacar la entrada cuando el
    /// par desaparece sin cortar su `device_id` por bytes.
    pub fullname: String,
}

/// Lo que se le puede mandar a una sesión en curso desde afuera (desde un método
/// de D-Bus): un mensaje, o la orden de cerrar.
enum Outbound {
    Send(Message),
    Shutdown,
}

/// Una sesión abierta con un par.
pub struct Session {
    pub name: String,
    pub kind: DeviceKind,
    /// La huella del certificado del par en esta sesión, para fijarla si se
    /// confirma el pareo sin volver a bajar a la capa de TLS.
    pub fingerprint: String,
    pub paired: bool,
    /// El estado del pareo de esta sesión. Toda la lógica pasa por
    /// [`advance_pairing`]: fijar al par depende de este estado, no de un mensaje
    /// suelto que mande el par.
    pair: PairingState,
    /// Id único de esta sesión. Distingue una sesión de su reemplazo para que la
    /// limpieza de la vieja no borre la entrada de la nueva.
    session_id: u64,
    /// Última batería que empujó el par, ya recortada a 0–100. `None` hasta el
    /// primer empuje. Deja que la pantalla de ajustes la consulte sin esperar al
    /// próximo evento.
    battery: Option<BatteryStatus>,
    outbound: mpsc::UnboundedSender<Outbound>,
}

/// Órdenes para la tarea del canal, que es la única que abre conexiones salientes.
enum Command {
    /// Conectarse a un par descubierto y pedirle pareo.
    RequestPairing(String),
}

/// El estado de ejecución del canal, tras el candado de `State`.
pub struct ChannelRuntime {
    pub identity: Arc<Identity>,
    pub name: String,
    pub discovered: HashMap<String, Discovered>,
    sessions: HashMap<String, Session>,
    commands: mpsc::UnboundedSender<Command>,
}

impl ChannelRuntime {
    /// Una línea por par para la pantalla de ajustes y el panel: id, nombre,
    /// categoría, huella, si está pareado y si está conectado ahora. Une lo
    /// descubierto, lo conectado y lo pareado, sin repetir un par que esté en más
    /// de una lista.
    pub fn peer_rows(&self, registry: &crate::registry::Registry) -> Vec<PeerRow> {
        let mut rows: HashMap<String, PeerRow> = HashMap::new();

        for (device_id, discovered) in &self.discovered {
            rows.insert(device_id.clone(), PeerRow::from_peer(&discovered.peer));
        }
        for (device_id, session) in &self.sessions {
            let row = rows.entry(device_id.clone()).or_insert_with(|| PeerRow {
                device_id: device_id.clone(),
                name: session.name.clone(),
                kind: session.kind.as_str().to_string(),
                fingerprint: session.fingerprint.clone(),
                paired: false,
                connected: false,
            });
            row.connected = true;
            if row.fingerprint.is_empty() {
                row.fingerprint = session.fingerprint.clone();
            }
        }
        for (device_id, known) in registry.paired_peers() {
            let row = rows.entry(device_id.clone()).or_insert_with(|| PeerRow {
                device_id: device_id.clone(),
                name: known.display_name().to_string(),
                kind: DeviceKind::Unknown.as_str().to_string(),
                fingerprint: known.fingerprint.clone(),
                paired: true,
                connected: false,
            });
            row.paired = true;
        }

        rows.into_values().collect()
    }

    /// Pide parear con un par. Vale tanto para uno descubierto (hay que discar)
    /// como para uno que ya tiene una sesión abierta sin parear (el pareo va por
    /// esa sesión): si no, un par entrante sin parear no podría iniciar el pareo, y
    /// uno saliente rechazado no podría reintentar. Devuelve si se conocía el par.
    pub fn request_pairing(&self, device_id: &str) -> bool {
        if !self.discovered.contains_key(device_id) && !self.sessions.contains_key(device_id) {
            return false;
        }
        self.commands
            .send(Command::RequestPairing(device_id.to_string()))
            .is_ok()
    }

    /// Manda un mensaje a una sesión abierta, si existe.
    fn send_to(&self, device_id: &str, message: Message) -> bool {
        match self.sessions.get(device_id) {
            Some(session) => session.outbound.send(Outbound::Send(message)).is_ok(),
            None => false,
        }
    }

    /// Manda un mensaje a cada par pareado y conectado. Devuelve a cuántos llegó.
    /// Es el camino del portapapeles saliente: lo que se copió en el escritorio va
    /// a los teléfonos de confianza, nunca a uno sin parear ni sólo descubierto.
    fn broadcast_paired(&self, message: Message) -> u32 {
        self.sessions
            .values()
            .filter(|session| session.paired)
            .filter(|session| {
                session
                    .outbound
                    .send(Outbound::Send(message.clone()))
                    .is_ok()
            })
            .count() as u32
    }

    /// Cierra una sesión abierta, si existe.
    fn shutdown(&self, device_id: &str) {
        if let Some(session) = self.sessions.get(device_id) {
            let _ = session.outbound.send(Outbound::Shutdown);
        }
    }
}

/// Una fila de par para D-Bus, aplanada a tipos simples.
pub struct PeerRow {
    pub device_id: String,
    pub name: String,
    pub kind: String,
    pub fingerprint: String,
    pub paired: bool,
    pub connected: bool,
}

impl PeerRow {
    fn from_peer(peer: &PeerInfo) -> Self {
        PeerRow {
            device_id: peer.device_id.clone(),
            name: peer.name.clone(),
            kind: peer.kind.as_str().to_string(),
            fingerprint: peer.fingerprint.clone(),
            paired: false,
            connected: false,
        }
    }
}

/// Lee el nombre del equipo de `/etc/hostname`, con la regla pura de
/// [`self_name`] para el caso vacío o ausente.
async fn read_self_name() -> String {
    let contents = tokio::fs::read_to_string("/etc/hostname").await.ok();
    self_name(contents.as_deref())
}

/// Nuestra propia tarjeta de presentación, a partir de la identidad y el nombre.
fn own_peer_info(identity: &Identity, name: &str) -> PeerInfo {
    PeerInfo {
        device_id: identity.device_id.clone(),
        name: name.to_string(),
        kind: DeviceKind::Desktop,
        protocol_version: PROTOCOL_VERSION,
        fingerprint: identity.fingerprint.clone(),
    }
}

/// Arranca el canal: carga la identidad, publica el anuncio mDNS, escucha
/// conexiones TLS y atiende las órdenes de pareo.
///
/// Si la identidad no se puede cargar ni crear (sin llavero, sin config), el
/// canal no arranca y se registra el motivo: el resto del servicio (adb, cámara,
/// ventanas) sigue funcionando. Un canal roto no tira el teléfono por USB.
pub async fn run(connection: zbus::Connection, state: Arc<Mutex<State>>) {
    let identity = match identity::load_or_create().await {
        Ok(identity) => Arc::new(identity),
        Err(err) => {
            warn!(%err, "no se pudo preparar la identidad TLS: el canal de red queda apagado");
            return;
        }
    };

    let name = read_self_name().await;
    info!(device_id = %identity.device_id, %name, "identidad del canal lista");

    let server_cfg = match transport::server_config(&identity) {
        Ok(cfg) => Arc::new(cfg),
        Err(err) => {
            warn!(%err, "configuración TLS de servidor inválida: canal apagado");
            return;
        }
    };
    let client_cfg = match transport::client_config(&identity) {
        Ok(cfg) => Arc::new(cfg),
        Err(err) => {
            warn!(%err, "configuración TLS de cliente inválida: canal apagado");
            return;
        }
    };

    let listener = match TcpListener::bind(("0.0.0.0", 0)).await {
        Ok(listener) => listener,
        Err(err) => {
            warn!(%err, "no se pudo abrir el puerto del canal: canal apagado");
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(err) => {
            warn!(%err, "no se pudo leer el puerto del canal: canal apagado");
            return;
        }
    };

    let (command_tx, mut command_rx) = mpsc::unbounded_channel::<Command>();

    {
        let mut guard = state.lock().await;
        guard.channel = Some(ChannelRuntime {
            identity: identity.clone(),
            name: name.clone(),
            discovered: HashMap::new(),
            sessions: HashMap::new(),
            commands: command_tx,
        });
    }

    // El descubrimiento por mDNS: anunciarse y navegar. Vive en su propia tarea
    // porque `mdns-sd` entrega los eventos por un canal propio.
    spawn_discovery(&identity, &name, port, state.clone(), connection.clone());

    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);

    // Techo de conexiones a la vez, incluidas las que todavía no completaron el
    // handshake. El permiso se toma **antes** de arrancar la tarea y se retiene
    // mientras dura la conexión, así un no autenticado no puede abrir muchas.
    let connections = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    info!(port, "canal escuchando");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, addr)) => {
                        let Ok(permit) = connections.clone().try_acquire_owned() else {
                            debug!(%addr, "tope de conexiones del canal alcanzado: se descarta");
                            continue;
                        };
                        debug!(%addr, "conexión entrante al canal");
                        let acceptor = acceptor.clone();
                        let state = state.clone();
                        let connection = connection.clone();
                        tokio::spawn(async move {
                            // El permiso se suelta al terminar la tarea: acota las
                            // conexiones en vuelo, no sólo las sesiones ya armadas.
                            let _permit = permit;
                            // El handshake tiene un plazo: una conexión que abre el
                            // socket y no completa el TLS no debe retener la tarea.
                            match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                                Ok(Ok(tls)) => {
                                    let (_, server_conn) = tls.get_ref();
                                    let fingerprint = peer_fingerprint(server_conn.peer_certificates());
                                    handle_session(tls, fingerprint, false, state, connection).await;
                                }
                                Ok(Err(err)) => debug!(%err, "handshake entrante fallido"),
                                Err(_) => debug!("handshake entrante sin completar a tiempo"),
                            }
                        });
                    }
                    Err(err) => warn!(%err, "fallo al aceptar una conexión"),
                }
            }

            Some(command) = command_rx.recv() => {
                match command {
                    Command::RequestPairing(device_id) => {
                        // Si ya hay una sesión abierta con ese par, el pareo va por
                        // ella (por la máquina de pareo, no mandando a mano). Se mira
                        // **antes** que la dirección descubierta: un par conectado se
                        // saca de `discovered`, así que si no se mirara primero no se
                        // podría parear a través de una sesión ya abierta.
                        let session_peer = {
                            let guard = state.lock().await;
                            guard.channel.as_ref()
                                .and_then(|ch| ch.sessions.get(&device_id))
                                .map(|s| (s.fingerprint.clone(), s.name.clone()))
                        };
                        if let Some((peer_fp, peer_name)) = session_peer {
                            let code = verification_code(&identity.fingerprint, &peer_fp);
                            if let Some(action) =
                                step_pairing(&state, &device_id, PairingEvent::LocalInitiate { code }).await
                            {
                                apply_pairing_over_outbound(
                                    action, &device_id, &peer_name, &peer_fp, &state, &connection,
                                )
                                .await;
                            }
                            continue;
                        }

                        // Si no hay sesión, hace falta la dirección descubierta para
                        // discar.
                        let address = {
                            let guard = state.lock().await;
                            guard.channel.as_ref()
                                .and_then(|ch| ch.discovered.get(&device_id))
                                .map(|d| d.address)
                        };
                        let Some(address) = address else { continue };
                        let Ok(permit) = connections.clone().try_acquire_owned() else {
                            debug!(%device_id, "tope de conexiones alcanzado: no se puede discar ahora");
                            continue;
                        };

                        let connector = connector.clone();
                        let state = state.clone();
                        let connection = connection.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(err) = dial_and_pair(connector, address, state, connection).await {
                                debug!(%err, %address, "no se pudo parear con el par");
                            }
                        });
                    }
                }
            }
        }
    }
}

/// Se conecta a un par y corre la sesión pidiendo pareo.
///
/// El connect TCP y el handshake TLS tienen un plazo: un par descubierto que
/// acepta el TCP pero nunca completa el TLS, de otro modo, dejaría esta tarea
/// colgada para siempre —y `unpair_peer` no la podría cerrar porque todavía no
/// hay sesión—. El plazo cubre sólo el armado; la sesión activa posterior tiene
/// sus propios cierres (keepalive, cierre de escritura).
async fn dial_and_pair(
    connector: TlsConnector,
    address: SocketAddr,
    state: Arc<Mutex<State>>,
    connection: zbus::Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // El nombre del servidor en el TLS no se valida (no hay CA, se fija la
    // huella), pero rustls pide uno bien formado.
    let server_name = rustls_pki_types::ServerName::try_from("vasak-connect")?.to_owned();
    let tls = timeout(HANDSHAKE_TIMEOUT, async {
        let tcp = TcpStream::connect(address).await?;
        connector.connect(server_name, tcp).await
    })
    .await
    .map_err(|_| "el par no completó la conexión a tiempo")??;
    let (_, client_conn) = tls.get_ref();
    let fingerprint = peer_fingerprint(client_conn.peer_certificates());
    handle_session(tls, fingerprint, true, state, connection).await;
    Ok(())
}

/// Atiende una sesión TLS ya establecida, venga de donde venga.
///
/// Intercambia `Hello`, decide la confianza y corre el bucle de la sesión:
/// `Ping`/`Pong` para mantenerla viva, y el pareo. Las decisiones salen de
/// [`pure`]; acá está sólo el movimiento de mensajes y el estado compartido.
async fn handle_session<S>(
    tls: S,
    fingerprint: Option<String>,
    initiate_pair: bool,
    state: Arc<Mutex<State>>,
    connection: zbus::Connection,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Some(fingerprint) = fingerprint else {
        debug!("el par no presentó certificado: se descarta");
        return;
    };

    let (mut reader, mut writer) = tokio::io::split(tls);

    // Identidad propia para el Hello.
    let own = {
        let guard = state.lock().await;
        let Some(ch) = guard.channel.as_ref() else {
            return;
        };
        own_peer_info(&ch.identity, &ch.name)
    };

    if send_with_deadline(&mut writer, &Message::Hello(own.clone()))
        .await
        .is_err()
    {
        debug!("no se pudo enviar el Hello");
        return;
    }

    // El `Hello` tiene un plazo: una conexión que abre el socket y no habla no
    // debe retener esta tarea para siempre.
    let peer = match timeout(HANDSHAKE_TIMEOUT, read_frame(&mut reader)).await {
        Ok(Ok(Message::Hello(peer))) => peer,
        Ok(Ok(other)) => {
            debug!(?other, "el primer mensaje no fue un Hello");
            return;
        }
        Ok(Err(err)) => {
            debug!(%err, "no llegó el Hello del par");
            return;
        }
        Err(_) => {
            debug!("el par no mandó el Hello a tiempo");
            return;
        }
    };

    if let Err(err) = pure::verify_hello(&peer, &fingerprint) {
        debug!(%err, "Hello rechazado");
        return;
    }

    // El `device_id` se deriva de la huella del certificado, **no** se toma el que
    // el par declara: así la identidad con la que se lo recuerda y se decide la
    // confianza queda atada al certificado, no a un campo que el par elige.
    let device_id = device_id_from_fingerprint(&fingerprint);

    // Decisión de confianza contra la huella fijada.
    let decision = {
        let guard = state.lock().await;
        let pinned = guard
            .registry
            .peer_fingerprint(&device_id)
            .map(str::to_string);
        evaluate_peer_cert(&fingerprint, pinned.as_deref())
    };
    if decision == TrustDecision::Reject {
        warn!(%device_id, "un par pareado presentó otro certificado: se rechaza");
        return;
    }
    let paired = decision == TrustDecision::Trusted;

    // Registrar la sesión y su canal de salida. El tope de sesiones acota el gasto
    // de memoria; un par que reconecta con el mismo certificado **reemplaza** su
    // sesión en vez de sumar una, y para que eso acote de verdad hay que terminar
    // la sesión vieja —si no, su tarea queda colgada hasta agotar el keepalive—.
    //
    // Las sesiones sin parear sólo llegan hasta `MAX - TRUSTED_RESERVE`: así un
    // atacante no puede llenar el cupo con sesiones sin parear y dejar afuera a un
    // par de confianza, que sí puede usar hasta `MAX`.
    let effective_max = if paired {
        MAX_CONCURRENT_SESSIONS
    } else {
        MAX_CONCURRENT_SESSIONS - TRUSTED_RESERVE
    };
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Outbound>();
    {
        let mut guard = state.lock().await;
        let Some(ch) = guard.channel.as_mut() else {
            return;
        };
        match admit_session(
            ch.sessions.contains_key(&device_id),
            ch.sessions.len(),
            effective_max,
        ) {
            SessionAdmission::Reject => {
                warn!(%device_id, "se alcanzó el tope de sesiones del canal: se rechaza");
                return;
            }
            SessionAdmission::Replace => {
                // Terminar la sesión vieja antes de poner la nueva. Su tarea sale
                // del bucle al recibir `Shutdown`; su limpieza no tocará esta
                // entrada porque compara el id de sesión.
                if let Some(old) = ch.sessions.get(&device_id) {
                    let _ = old.outbound.send(Outbound::Shutdown);
                }
            }
            SessionAdmission::Admit => {}
        }
        ch.discovered.remove(&device_id);
        ch.sessions.insert(
            device_id.clone(),
            Session {
                name: peer.name.clone(),
                kind: peer.kind,
                fingerprint: fingerprint.clone(),
                paired,
                pair: PairingState::Idle,
                session_id,
                battery: None,
                outbound: out_tx,
            },
        );
    }
    emit_peer_changed(&connection).await;
    info!(%device_id, paired, "sesión del canal abierta");

    // Si somos nosotros los que iniciamos el pareo, pedirlo ahora: la máquina de
    // pareo decide qué mandar y qué mostrarle a la persona.
    if initiate_pair && !paired {
        let code = verification_code(&own.fingerprint, &fingerprint);
        if let Some(action) =
            step_pairing(&state, &device_id, PairingEvent::LocalInitiate { code }).await
        {
            apply_pairing_over_writer(
                action,
                &device_id,
                &peer.name,
                &fingerprint,
                &mut writer,
                &state,
                &connection,
            )
            .await;
        }
    }

    // El bucle lee con un `FramedRead`: es cancel-safe, así que un `select!` que
    // gana con otro brazo a mitad de un marco no pierde los bytes ya leídos
    // —cosa que `read_frame` (dos `read_exact`) sí haría, corrompiendo el flujo—.
    let mut frames = FramedRead::new(reader, MessageDecoder);

    let mut keepalive = interval(KEEPALIVE);
    keepalive.tick().await; // el primer tick es inmediato; lo descartamos
    let mut missed_pongs: u32 = 0;

    // Plazo para completar el pareo: una sesión que se queda sin parear ocupando
    // lugar se cierra. Una vez pareada, el plazo se corre muy lejos y no vuelve a
    // disparar.
    let pair_deadline = tokio::time::sleep(PAIR_TIMEOUT);
    tokio::pin!(pair_deadline);

    loop {
        tokio::select! {
            incoming = frames.next() => {
                match incoming {
                    // El `Pong` es la respuesta al keepalive: pone a cero la cuenta
                    // de los que faltan. Se mira acá, en el bucle, porque la cuenta
                    // vive acá.
                    Some(Ok(Message::Pong)) => { missed_pongs = 0; }
                    Some(Ok(message)) => {
                        if !handle_message(message, &device_id, &peer, &own.fingerprint, &fingerprint, &mut writer, &state, &connection).await {
                            break;
                        }
                    }
                    Some(Err(err)) => {
                        debug!(%device_id, %err, "error de sesión: se cierra");
                        break;
                    }
                    None => {
                        debug!(%device_id, "el par cerró la sesión");
                        break;
                    }
                }
            }

            Some(out) = out_rx.recv() => {
                match out {
                    Outbound::Send(message) => {
                        if send_with_deadline(&mut writer, &message).await.is_err() {
                            break;
                        }
                    }
                    Outbound::Shutdown => break,
                }
            }

            _ = keepalive.tick() => {
                // Si el par no contestó los últimos `Ping`, se da por caído y se
                // cierra en vez de seguir mandando a una sesión muerta.
                if keepalive_exhausted(missed_pongs, MAX_MISSED_PONGS) {
                    debug!(%device_id, "el par dejó de contestar el keepalive: se cierra");
                    break;
                }
                if send_with_deadline(&mut writer, &Message::Ping).await.is_err() {
                    break;
                }
                missed_pongs += 1;
            }

            _ = &mut pair_deadline => {
                // Se cierra si todavía no completó el pareo; si ya está pareada, el
                // plazo se desactiva corriéndolo muy lejos.
                let still_unpaired = {
                    let guard = state.lock().await;
                    guard.channel.as_ref()
                        .and_then(|ch| ch.sessions.get(&device_id))
                        .map(|s| !s.paired)
                        .unwrap_or(true)
                };
                if still_unpaired {
                    debug!(%device_id, "la sesión no completó el pareo a tiempo: se cierra");
                    break;
                }
                pair_deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(86_400));
            }
        }
    }

    // Limpieza al cerrar. Se borra la entrada **sólo si sigue siendo la de esta
    // sesión**: si entró una de reemplazo con el mismo `device_id`, su entrada es
    // otra (otro `session_id`) y no hay que borrarla acá, o la sesión viva quedaría
    // inalcanzable.
    {
        let mut guard = state.lock().await;
        if let Some(ch) = guard.channel.as_mut() {
            let current = ch.sessions.get(&device_id).map(|s| s.session_id);
            if owns_session_slot(current, session_id) {
                ch.sessions.remove(&device_id);
            }
        }
    }
    emit_peer_changed(&connection).await;
    info!(%device_id, "sesión del canal cerrada");
}

/// Escribe un marco con un plazo. Un par que manda pero no lee llena el buffer de
/// envío y, sin plazo, dejaría esta escritura colgada para siempre, con la sesión
/// sin atender el keepalive ni el `Shutdown` del reemplazo —y su tarea y su socket
/// vivos fuera del mapa—. Pasado el plazo, se trata como error y la sesión cierra.
async fn send_with_deadline<W>(writer: &mut W, message: &Message) -> Result<(), SessionError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match timeout(WRITE_TIMEOUT, write_frame(writer, message)).await {
        Ok(result) => result,
        Err(_) => Err(SessionError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "la escritura no se completó a tiempo",
        ))),
    }
}

/// Procesa un mensaje entrante. Devuelve `false` si la sesión debe cerrarse.
///
/// `own_fingerprint` es la huella propia y `fingerprint` la del par en esta
/// sesión; con las dos se recalcula localmente el código del pareo entrante.
// Son muchos parámetros, pero cada uno es un dato distinto que el despacho de un
// mensaje necesita (quién, con qué huellas, por dónde contestar y a dónde emitir);
// juntarlos en una estructura sólo para la cuenta no lo haría más claro.
#[allow(clippy::too_many_arguments)]
async fn handle_message<W>(
    message: Message,
    device_id: &str,
    peer: &PeerInfo,
    own_fingerprint: &str,
    fingerprint: &str,
    writer: &mut W,
    state: &Arc<Mutex<State>>,
    connection: &zbus::Connection,
) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match message {
        Message::Ping => send_with_deadline(writer, &Message::Pong).await.is_ok(),
        // El `Pong` lo mira el bucle de la sesión (pone a cero el keepalive); si
        // llega acá, no hay nada que hacer.
        Message::Pong => true,
        Message::PairRequest { verification } => {
            // El código se **recalcula localmente** con las dos huellas: el que
            // manda el par no se muestra ni se cree. Si no coincide con el local, el
            // pareo se ignora —es la señal de un intermediario en el primer pareo—.
            let Some(code) = checked_incoming_code(own_fingerprint, fingerprint, &verification)
            else {
                debug!(%device_id, "código de pareo entrante no coincide con el recalculado: se ignora");
                return true;
            };

            // El par quiere parear. La máquina decide (estado `IncomingPending`,
            // mostrar el código); **no se fija nada** hasta la confirmación local.
            if let Some(action) = step_pairing(
                state,
                device_id,
                PairingEvent::PeerRequest { code: code.clone() },
            )
            .await
            {
                // El aviso del sistema es sólo para un pedido entrante nuevo, y con
                // el código recalculado localmente.
                if action.notify_code.is_some() {
                    notify::send(
                        connection,
                        &format!("{} quiere conectarse", peer.name),
                        &format!("Confirmá el código {code} para parear."),
                        notify::PHONE_ICON,
                    )
                    .await;
                }
                apply_pairing_over_writer(
                    action,
                    device_id,
                    &peer.name,
                    fingerprint,
                    writer,
                    state,
                    connection,
                )
                .await;
            }
            true
        }
        Message::PairResponse { accepted } => {
            // Honrar un `PairResponse` sólo tiene sentido si hay un pedido saliente
            // nuestro pendiente; si no, la máquina lo ignora. Y aun cuando es
            // válido, **no fija**: espera la confirmación local.
            if let Some(action) =
                step_pairing(state, device_id, PairingEvent::PeerResponse { accepted }).await
            {
                apply_pairing_over_writer(
                    action,
                    device_id,
                    &peer.name,
                    fingerprint,
                    writer,
                    state,
                    connection,
                )
                .await;
            }
            true
        }
        Message::Unpair => {
            {
                let mut guard = state.lock().await;
                // El par nos deshizo el pareo. Si no se guarda, al reiniciar lo
                // seguiríamos teniendo como de confianza, pero él ya nos olvidó y no
                // se va a conectar como pareado: best-effort y se registra.
                if guard.registry.unpin_peer(device_id) {
                    guard.registry.save_or_log();
                }
                if let Some(ch) = guard.channel.as_mut() {
                    if let Some(session) = ch.sessions.get_mut(device_id) {
                        session.paired = false;
                    }
                }
            }
            emit_peer_changed(connection).await;
            info!(%device_id, "el par deshizo el pareo");
            true
        }
        Message::Battery(raw) => {
            // Sólo de un par pareado, y con el nivel recortado a 0–100: la decisión
            // de confianza y el saneo están en [`pure::sanitize_incoming_battery`].
            let paired = session_paired(state, device_id).await;
            if let Some(status) = pure::sanitize_incoming_battery(paired, raw) {
                set_session_battery(state, device_id, status).await;
                emit_peer_battery(connection, device_id, status).await;
            }
            true
        }
        Message::Clipboard { text } => {
            // Sólo de un par pareado: escribir en el portapapeles local desde un
            // aparato sin parear es una inyección. El escritorio aplica el texto al
            // recibir la señal; el daemon no toca Wayland.
            let paired = session_paired(state, device_id).await;
            if let Some(text) = pure::accept_incoming_clipboard(paired, text) {
                emit_clipboard_received(connection, &text).await;
            }
            true
        }
        // La transferencia de archivos es de un PR posterior, y recién después de
        // que aterrice el SAS con compromiso (RFC 6189): hasta entonces un mal
        // pareo en la primera vez podría exponer los bytes. Ver `wire.rs`. Por
        // ahora se reconoce y se ignora sin cerrar la sesión.
        Message::FileOffer(_) | Message::FileResult { .. } => {
            debug!(%device_id, "transferencia de archivos aún no implementada; se ignora");
            true
        }
        // Un segundo `Hello` en la misma sesión no tiene sentido (ya se consumió en
        // el handshake); se ignora sin cerrar.
        Message::Hello(_) => true,
    }
}

/// Si la sesión con ese par está pareada ahora. Es la puerta de confianza para el
/// estado que empuja el par (batería, portapapeles).
async fn session_paired(state: &Arc<Mutex<State>>, device_id: &str) -> bool {
    let guard = state.lock().await;
    guard
        .channel
        .as_ref()
        .and_then(|ch| ch.sessions.get(device_id))
        .is_some_and(|session| session.paired)
}

/// Guarda la última batería que empujó el par, para que la consulta `peer_battery`
/// la devuelva sin esperar al próximo evento.
async fn set_session_battery(state: &Arc<Mutex<State>>, device_id: &str, status: BatteryStatus) {
    let mut guard = state.lock().await;
    if let Some(session) = guard
        .channel
        .as_mut()
        .and_then(|ch| ch.sessions.get_mut(device_id))
    {
        session.battery = Some(status);
    }
}

/// Hace avanzar la máquina de pareo de una sesión con un evento y guarda el
/// estado nuevo. Devuelve la acción a aplicar, o `None` si no hay sesión.
///
/// Es el único lugar donde se decide el pareo: la decisión es pura
/// ([`advance_pairing`]); acá sólo se lee y se escribe el estado de la sesión.
async fn step_pairing(
    state: &Arc<Mutex<State>>,
    device_id: &str,
    event: PairingEvent,
) -> Option<pure::PairingAction> {
    let mut guard = state.lock().await;
    let ch = guard.channel.as_mut()?;
    let session = ch.sessions.get_mut(device_id)?;
    let action = advance_pairing(&session.pair, event);
    session.pair = action.next.clone();
    Some(action)
}

/// Aplica una acción de pareo cuando se tiene el `writer` de la sesión a mano
/// (en el bucle o al iniciar): manda el mensaje que corresponda, avisa a la
/// persona con el código, y fija al par si la acción lo indica.
async fn apply_pairing_over_writer<W>(
    action: pure::PairingAction,
    device_id: &str,
    peer_name: &str,
    fingerprint: &str,
    writer: &mut W,
    state: &Arc<Mutex<State>>,
    connection: &zbus::Connection,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    if let Some(message) = &action.send {
        let _ = send_with_deadline(writer, message).await;
    }
    if let Some(code) = &action.notify_code {
        emit_pairing_requested(connection, device_id, peer_name, code).await;
    }
    if action.pin {
        pin_peer(state, device_id, peer_name, fingerprint).await;
        emit_peer_changed(connection).await;
        info!(%device_id, "par fijado tras la confirmación local");
    }
}

/// Aplica una acción de pareo cuando el mensaje va por el canal de salida de la
/// sesión (desde un método de D-Bus, sin el `writer` a mano). Mismo efecto que
/// [`apply_pairing_over_writer`], pero el envío va por [`ChannelRuntime::send_to`].
async fn apply_pairing_over_outbound(
    action: pure::PairingAction,
    device_id: &str,
    peer_name: &str,
    fingerprint: &str,
    state: &Arc<Mutex<State>>,
    connection: &zbus::Connection,
) {
    if action.pin {
        pin_peer(state, device_id, peer_name, fingerprint).await;
    }
    if let Some(message) = action.send {
        let guard = state.lock().await;
        if let Some(ch) = guard.channel.as_ref() {
            ch.send_to(device_id, message);
        }
    }
    if let Some(code) = &action.notify_code {
        emit_pairing_requested(connection, device_id, peer_name, code).await;
    }
    if action.pin {
        emit_peer_changed(connection).await;
        info!(%device_id, "par fijado tras la confirmación local");
    }
}

/// Fija un par como pareado en el registro y lo guarda.
async fn pin_peer(state: &Arc<Mutex<State>>, device_id: &str, name: &str, fingerprint: &str) {
    let mut guard = state.lock().await;
    let now = crate::now_iso8601();
    guard.registry.pin_peer(device_id, name, fingerprint, &now);
    // Si no se guarda, en memoria el par queda pareado para esta sesión; al
    // reiniciar habría que reparear, que falla seguro (no deja entrar a nadie de
    // más). Por eso es best-effort, a diferencia del desapareo.
    guard.registry.save_or_log();
    if let Some(ch) = guard.channel.as_mut() {
        if let Some(session) = ch.sessions.get_mut(device_id) {
            session.paired = true;
        }
    }
}

/// Anuncio mDNS: publica nuestro servicio y navega para encontrar pares.
fn spawn_discovery(
    identity: &Arc<Identity>,
    name: &str,
    port: u16,
    state: Arc<Mutex<State>>,
    connection: zbus::Connection,
) {
    use vasak_connect_protocol::wire::SERVICE_TYPE;

    let own = own_peer_info(identity, name);
    let device_id = identity.device_id.clone();

    tokio::spawn(async move {
        let daemon = match mdns_sd::ServiceDaemon::new() {
            Ok(daemon) => daemon,
            Err(err) => {
                warn!(%err, "sin mDNS: no hay descubrimiento automático");
                return;
            }
        };

        // Se anuncia y se escucha sólo por IPv4, para que lo anunciado y lo que se
        // escucha coincidan: el listener está en `0.0.0.0` (IPv4), y `enable_addr_auto`
        // anunciaría también las IPv6 de un host dual-stack —que el par podría
        // elegir y no poder conectar—.
        if let Err(err) = daemon.disable_interface(mdns_sd::IfKind::IPv6) {
            warn!(%err, "no se pudo limitar mDNS a IPv4");
        }

        // Etiqueta de instancia: el id es de 64 hex y una etiqueta DNS-SD no pasa
        // de 63 octetos, así que se recorta **por caracteres** (ver
        // `mdns_instance_label`); la identidad completa va en el TXT igual.
        let instance = mdns_instance_label(&device_id);
        let host = format!("{instance}.local.");
        let properties: Vec<(String, String)> = pure::build_txt(&own);

        match mdns_sd::ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", port, &properties[..]) {
            Ok(info) => {
                let info = info.enable_addr_auto();
                if let Err(err) = daemon.register(info) {
                    warn!(%err, "no se pudo publicar el anuncio mDNS");
                }
            }
            Err(err) => warn!(%err, "no se pudo armar el anuncio mDNS"),
        }

        let receiver = match daemon.browse(SERVICE_TYPE) {
            Ok(receiver) => receiver,
            Err(err) => {
                warn!(%err, "no se pudo navegar mDNS");
                return;
            }
        };

        while let Ok(event) = receiver.recv_async().await {
            match event {
                mdns_sd::ServiceEvent::ServiceResolved(info) => {
                    handle_resolved(info, &device_id, &state, &connection).await;
                }
                mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                    handle_removed(&fullname, &state, &connection).await;
                }
                _ => {}
            }
        }
    });
}

/// Un par resuelto por mDNS: se guarda en lo descubierto si es ajeno y bien
/// formado.
async fn handle_resolved(
    info: mdns_sd::ServiceInfo,
    own_device_id: &str,
    state: &Arc<Mutex<State>>,
    connection: &zbus::Connection,
) {
    let properties: HashMap<String, String> = info
        .get_properties()
        .iter()
        .map(|prop| (prop.key().to_string(), prop.val_str().to_string()))
        .collect();

    let Some(mut peer) = parse_peer_txt(&properties) else {
        return;
    };
    // El id con el que se recuerda al par se **deriva de la huella anunciada**, no
    // se usa el `device_id` que el par puso en el TXT: así coincide con el id
    // derivado del certificado que usa `handle_session` (para un par honesto, que
    // anuncia su huella de verdad), y no aparece el mismo aparato dos veces ni se
    // pierde el pedido de pareo por el id anunciado. La confianza la sigue
    // decidiendo el certificado del TLS, no el TXT.
    peer.device_id = device_id_from_fingerprint(&peer.fingerprint);

    // No descubrirse a sí mismo.
    if peer.device_id == own_device_id {
        return;
    }
    let Some(address) = info
        .get_addresses()
        .iter()
        .next()
        .map(|ip| SocketAddr::new(*ip, info.get_port()))
    else {
        return;
    };
    let fullname = info.get_fullname().to_string();

    {
        let mut guard = state.lock().await;
        if let Some(ch) = guard.channel.as_mut() {
            // Si ya hay sesión abierta con ese par, no hace falta listarlo como
            // "descubierto" aparte.
            if ch.sessions.contains_key(&peer.device_id) {
                return;
            }
            ch.discovered.insert(
                peer.device_id.clone(),
                Discovered {
                    peer,
                    address,
                    fullname,
                },
            );
        }
    }
    emit_peer_changed(connection).await;
}

/// Un par que desapareció del mDNS: se saca de lo descubierto por su nombre
/// completo de servicio, que es lo que trae el evento —sin cortar ningún id por
/// bytes—.
async fn handle_removed(fullname: &str, state: &Arc<Mutex<State>>, connection: &zbus::Connection) {
    let mut changed = false;
    {
        let mut guard = state.lock().await;
        if let Some(ch) = guard.channel.as_mut() {
            let gone: Vec<String> = ch
                .discovered
                .iter()
                .filter(|(_, discovered)| discovered.fullname == fullname)
                .map(|(id, _)| id.clone())
                .collect();
            for id in gone {
                ch.discovered.remove(&id);
                changed = true;
            }
        }
    }
    if changed {
        emit_peer_changed(connection).await;
    }
}

// ── Superficie para los metodos de D-Bus ─────────────────────────────────────

/// Confirma o rechaza un pareo **desde la persona local**. Es el único camino por
/// el que un par queda fijado como de confianza.
///
/// Sólo hace algo si hay un pareo pendiente para ese par (un pedido entrante o uno
/// saliente nuestro); un `confirm_pairing` sobre un par sin nada pendiente no fija
/// nada. La decisión (fijar, qué contestarle al par) sale de [`advance_pairing`].
/// Devuelve si había un pareo pendiente que resolver.
pub async fn confirm_pairing(
    state: &Arc<Mutex<State>>,
    connection: &zbus::Connection,
    device_id: &str,
    accept: bool,
) -> bool {
    // Hacer avanzar la máquina con la confirmación local, leyendo de paso nombre y
    // huella para fijar. Si no hay pareo pendiente (`Idle`), no se hace nada.
    let (action, name, fingerprint) = {
        let mut guard = state.lock().await;
        let Some(ch) = guard.channel.as_mut() else {
            return false;
        };
        let Some(session) = ch.sessions.get_mut(device_id) else {
            return false;
        };
        if matches!(session.pair, PairingState::Idle) {
            return false;
        }
        let name = session.name.clone();
        let fingerprint = session.fingerprint.clone();
        let action = advance_pairing(&session.pair, PairingEvent::LocalConfirm { accept });
        session.pair = action.next.clone();
        (action, name, fingerprint)
    };

    apply_pairing_over_outbound(action, device_id, &name, &fingerprint, state, connection).await;
    // Un rechazo cierra la sesión: ya se le mandó el `PairResponse { false }`.
    if !accept {
        let guard = state.lock().await;
        if let Some(ch) = guard.channel.as_ref() {
            ch.shutdown(device_id);
        }
        drop(guard);
        emit_peer_changed(connection).await;
    }
    true
}

/// Deshace el pareo de un par: borra la huella fijada y, si está conectado, le
/// avisa con `Unpair` y cierra la sesión.
///
/// Devuelve `Err` si el cambio **no se pudo guardar**: desparear es un cambio de
/// confianza, y reportarlo como hecho cuando no llegó al disco deja volver el pin
/// viejo al reiniciar —y con él un certificado revocado como de confianza—. Si no
/// se pudo guardar, se restaura el pin en memoria para que el estado vivo no
/// mienta respecto del disco. `Ok(false)` significa que no había nada que
/// desparear.
pub async fn unpair_peer(
    state: &Arc<Mutex<State>>,
    connection: &zbus::Connection,
    device_id: &str,
) -> Result<bool, String> {
    let removed = {
        let mut guard = state.lock().await;
        // Se copia la entrada antes de tocarla, para poder restaurarla si no se
        // puede guardar.
        let Some(previous) = guard.registry.paired_peer(device_id).cloned() else {
            return Ok(false);
        };
        guard.registry.unpin_peer(device_id);
        if let Err(err) = guard.registry.save() {
            // No se guardó: el desapareo no es durable, así que se restaura el par
            // en memoria para que el estado vivo y el disco digan lo mismo, y se
            // avisa para poder reintentar.
            guard.registry.pin_peer(
                device_id,
                &previous.model,
                &previous.fingerprint,
                &crate::now_iso8601(),
            );
            return Err(format!("no se pudo guardar el desapareo: {err}"));
        }
        if let Some(ch) = guard.channel.as_ref() {
            ch.send_to(device_id, Message::Unpair);
            ch.shutdown(device_id);
        }
        true
    };
    if removed {
        emit_peer_changed(connection).await;
    }
    Ok(removed)
}

/// Emite la señal de que cambió el conjunto de pares (descubierto, conectado o
/// pareado). Un solo evento que el panel usa para repintar la lista.
async fn emit_peer_changed(connection: &zbus::Connection) {
    let Ok(emitter) =
        zbus::object_server::SignalEmitter::new(connection, vasak_connect_protocol::SERVICE_PATH)
    else {
        return;
    };
    let _ = crate::ConnectService::peers_changed(&emitter).await;
}

/// Emite la señal de pedido de pareo con el código que la persona debe confirmar.
async fn emit_pairing_requested(
    connection: &zbus::Connection,
    device_id: &str,
    name: &str,
    code: &str,
) {
    let Ok(emitter) =
        zbus::object_server::SignalEmitter::new(connection, vasak_connect_protocol::SERVICE_PATH)
    else {
        return;
    };
    let _ = crate::ConnectService::pairing_requested(&emitter, device_id, name, code).await;
}

/// Emite la señal de que un par informó su batería. El panel y los ajustes la
/// pintan contra `device_id`.
async fn emit_peer_battery(connection: &zbus::Connection, device_id: &str, status: BatteryStatus) {
    let Ok(emitter) =
        zbus::object_server::SignalEmitter::new(connection, vasak_connect_protocol::SERVICE_PATH)
    else {
        return;
    };
    let _ = crate::ConnectService::peer_battery_changed(
        &emitter,
        device_id,
        status.level,
        status.charging,
    )
    .await;
}

/// Emite la señal de texto de portapapeles recibido. El escritorio decide
/// aplicarlo al portapapeles de Wayland; el daemon no lo toca.
async fn emit_clipboard_received(connection: &zbus::Connection, text: &str) {
    let Ok(emitter) =
        zbus::object_server::SignalEmitter::new(connection, vasak_connect_protocol::SERVICE_PATH)
    else {
        return;
    };
    let _ = crate::ConnectService::clipboard_received(&emitter, text).await;
}

/// Manda el texto copiado en el escritorio a cada par pareado y conectado.
/// Devuelve a cuántos llegó. Lo llama el escritorio por D-Bus cuando cambia el
/// portapapeles local.
pub async fn send_clipboard(state: &Arc<Mutex<State>>, text: &str) -> u32 {
    if text.is_empty() {
        return 0;
    }
    let guard = state.lock().await;
    match guard.channel.as_ref() {
        Some(ch) => ch.broadcast_paired(Message::Clipboard {
            text: text.to_string(),
        }),
        None => 0,
    }
}

/// La última batería conocida de un par: `(conocida, nivel, cargando)`. `conocida`
/// es `false` si el par nunca empujó su batería en esta sesión.
pub async fn peer_battery(state: &Arc<Mutex<State>>, device_id: &str) -> (bool, u8, bool) {
    let guard = state.lock().await;
    match guard
        .channel
        .as_ref()
        .and_then(|ch| ch.sessions.get(device_id))
        .and_then(|session| session.battery)
    {
        Some(status) => (true, status.level, status.charging),
        None => (false, 0, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    fn session(paired: bool, session_id: u64) -> (Session, mpsc::UnboundedReceiver<Outbound>) {
        let (outbound, rx) = mpsc::unbounded_channel();
        let session = Session {
            name: "Pixel 8".into(),
            kind: DeviceKind::Phone,
            fingerprint: String::new(),
            paired,
            pair: PairingState::default(),
            session_id,
            battery: None,
            outbound,
        };
        (session, rx)
    }

    fn runtime(sessions: Vec<(&str, Session)>) -> ChannelRuntime {
        let (commands, _) = mpsc::unbounded_channel();
        ChannelRuntime {
            identity: Arc::new(Identity {
                cert_der: CertificateDer::from(Vec::new()),
                key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(Vec::new())),
                fingerprint: String::new(),
                device_id: "yo".into(),
            }),
            name: "Escritorio".into(),
            discovered: HashMap::new(),
            sessions: sessions
                .into_iter()
                .map(|(id, s)| (id.to_string(), s))
                .collect(),
            commands,
        }
    }

    #[test]
    fn el_portapapeles_saliente_llega_solo_a_los_pares_pareados() {
        let (paired, mut paired_rx) = session(true, 1);
        let (unpaired, mut unpaired_rx) = session(false, 2);
        let rt = runtime(vec![("pareado", paired), ("sin-parear", unpaired)]);
        let msg = Message::Clipboard {
            text: "secreto".into(),
        };

        assert_eq!(rt.broadcast_paired(msg.clone()), 1);

        match paired_rx.try_recv() {
            Ok(Outbound::Send(got)) => assert_eq!(got, msg),
            _ => panic!("el par pareado debía recibir el mensaje"),
        }
        assert!(
            unpaired_rx.try_recv().is_err(),
            "el par sin parear no debe recibir nada"
        );
    }
}
