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
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::{interval, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};
use vasak_connect_protocol::wire::{DeviceKind, Message, PeerInfo, PROTOCOL_VERSION};

use crate::{notify, State};
use identity::Identity;
use pure::{
    accept_new_session, advance_pairing, device_id_from_fingerprint, evaluate_peer_cert,
    keepalive_exhausted, parse_peer_txt, self_name, verification_code, PairingEvent, PairingState,
    TrustDecision,
};
use transport::{peer_fingerprint, read_frame, write_frame, SessionError};

/// Cada cuánto se manda un `Ping` para mantener viva la sesión y notar un corte
/// que el socket todavía no reportó.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// Cuántos `Ping` seguidos sin `Pong` se toleran antes de cerrar la sesión. Una
/// sesión que dejó de contestar no debe quedar colgada ocupando memoria.
const MAX_MISSED_PONGS: u32 = 3;

/// Tope de sesiones abiertas a la vez. Lo abre cualquiera que alcance el puerto,
/// sin estar pareado, así que tiene un techo para que no se pueda agotar la
/// memoria del servicio abriendo conexiones sin fin.
const MAX_CONCURRENT_SESSIONS: usize = 32;

/// Lo que se le da al handshake y al primer `Hello` para completarse. Una
/// conexión que abre el socket y no habla no debe retener una tarea para siempre.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Lo que un par anunció por mDNS y dónde alcanzarlo.
pub struct Discovered {
    pub peer: PeerInfo,
    pub address: SocketAddr,
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

    /// Pide parear con un par descubierto. Devuelve si se conocía su dirección
    /// para intentarlo.
    pub fn request_pairing(&self, device_id: &str) -> bool {
        if !self.discovered.contains_key(device_id) {
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

    info!(port, "canal escuchando");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, addr)) => {
                        debug!(%addr, "conexión entrante al canal");
                        let acceptor = acceptor.clone();
                        let state = state.clone();
                        let connection = connection.clone();
                        tokio::spawn(async move {
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
                        let address = {
                            let guard = state.lock().await;
                            guard.channel.as_ref()
                                .and_then(|ch| ch.discovered.get(&device_id))
                                .map(|d| d.address)
                        };
                        let Some(address) = address else { continue };

                        // Si ya hay una sesión abierta con ese par, el pareo va
                        // por ella (por la máquina de pareo, no mandando a mano);
                        // sólo se abre una nueva si no la hay.
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

                        let connector = connector.clone();
                        let state = state.clone();
                        let connection = connection.clone();
                        tokio::spawn(async move {
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
async fn dial_and_pair(
    connector: TlsConnector,
    address: SocketAddr,
    state: Arc<Mutex<State>>,
    connection: zbus::Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpStream::connect(address).await?;
    // El nombre del servidor en el TLS no se valida (no hay CA, se fija la
    // huella), pero rustls pide uno bien formado.
    let server_name = rustls_pki_types::ServerName::try_from("vasak-connect")?.to_owned();
    let tls = connector.connect(server_name, tcp).await?;
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

    if let Err(err) = write_frame(&mut writer, &Message::Hello(own.clone())).await {
        debug!(%err, "no se pudo enviar el Hello");
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

    // Registrar la sesión y su canal de salida. Con un tope de sesiones abiertas:
    // reemplazar una del mismo par está bien, pero una conexión nueva de un par
    // distinto se rechaza si ya se llegó al techo, para que no se pueda agotar la
    // memoria abriendo conexiones sin fin.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Outbound>();
    {
        let mut guard = state.lock().await;
        let Some(ch) = guard.channel.as_mut() else {
            return;
        };
        let replacing = ch.sessions.contains_key(&device_id);
        if !replacing && !accept_new_session(ch.sessions.len(), MAX_CONCURRENT_SESSIONS) {
            warn!(%device_id, "se alcanzó el tope de sesiones del canal: se rechaza");
            return;
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

    let mut keepalive = interval(KEEPALIVE);
    keepalive.tick().await; // el primer tick es inmediato; lo descartamos
    let mut missed_pongs: u32 = 0;

    loop {
        tokio::select! {
            incoming = read_frame(&mut reader) => {
                match incoming {
                    // El `Pong` es la respuesta al keepalive: pone a cero la cuenta
                    // de los que faltan. Se mira acá, en el bucle, porque la cuenta
                    // vive acá.
                    Ok(Message::Pong) => { missed_pongs = 0; }
                    Ok(message) => {
                        if !handle_message(message, &device_id, &peer, &fingerprint, &mut writer, &state, &connection).await {
                            break;
                        }
                    }
                    Err(SessionError::Closed) => {
                        debug!(%device_id, "el par cerró la sesión");
                        break;
                    }
                    Err(err) => {
                        debug!(%device_id, %err, "error de sesión: se cierra");
                        break;
                    }
                }
            }

            Some(out) = out_rx.recv() => {
                match out {
                    Outbound::Send(message) => {
                        if write_frame(&mut writer, &message).await.is_err() {
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
                if write_frame(&mut writer, &Message::Ping).await.is_err() {
                    break;
                }
                missed_pongs += 1;
            }
        }
    }

    // Limpieza al cerrar.
    {
        let mut guard = state.lock().await;
        if let Some(ch) = guard.channel.as_mut() {
            ch.sessions.remove(&device_id);
        }
    }
    emit_peer_changed(&connection).await;
    info!(%device_id, "sesión del canal cerrada");
}

/// Procesa un mensaje entrante. Devuelve `false` si la sesión debe cerrarse.
async fn handle_message<W>(
    message: Message,
    device_id: &str,
    peer: &PeerInfo,
    fingerprint: &str,
    writer: &mut W,
    state: &Arc<Mutex<State>>,
    connection: &zbus::Connection,
) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match message {
        Message::Ping => write_frame(writer, &Message::Pong).await.is_ok(),
        // El `Pong` lo mira el bucle de la sesión (pone a cero el keepalive); si
        // llega acá, no hay nada que hacer.
        Message::Pong => true,
        Message::PairRequest { verification } => {
            // El par quiere parear. La máquina decide (estado `IncomingPending`,
            // mostrar el código); **no se fija nada** hasta la confirmación local.
            if let Some(action) = step_pairing(
                state,
                device_id,
                PairingEvent::PeerRequest {
                    code: verification.clone(),
                },
            )
            .await
            {
                // El aviso del sistema es sólo para un pedido entrante nuevo.
                if action.notify_code.is_some() {
                    notify::send(
                        connection,
                        &format!("{} quiere conectarse", peer.name),
                        &format!("Confirmá el código {verification} para parear."),
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
                if guard.registry.unpin_peer(device_id) {
                    guard.registry.save();
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
        // El resto (batería, portapapeles, archivos) es de un PR posterior; por
        // ahora se reconoce y se ignora sin cerrar la sesión.
        other => {
            debug!(%device_id, ?other, "mensaje aún no manejado");
            true
        }
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
        let _ = write_frame(writer, message).await;
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
    guard.registry.save();
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

        // Etiqueta de instancia: el id es de 64 hex y una etiqueta DNS-SD no
        // pasa de 63 octetos, así que se recorta; la identidad completa va en el
        // TXT igual.
        let instance = &device_id[..device_id.len().min(40)];
        let host = format!("{instance}.local.");
        let properties: Vec<(String, String)> = pure::build_txt(&own);

        match mdns_sd::ServiceInfo::new(SERVICE_TYPE, instance, &host, "", port, &properties[..]) {
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

    let Some(peer) = parse_peer_txt(&properties) else {
        return;
    };
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

    {
        let mut guard = state.lock().await;
        if let Some(ch) = guard.channel.as_mut() {
            // Si ya hay sesión abierta con ese par, no hace falta listarlo como
            // "descubierto" aparte.
            if ch.sessions.contains_key(&peer.device_id) {
                return;
            }
            ch.discovered
                .insert(peer.device_id.clone(), Discovered { peer, address });
        }
    }
    emit_peer_changed(connection).await;
}

/// Un par que desapareció del mDNS: se saca de lo descubierto si no hay sesión.
async fn handle_removed(fullname: &str, state: &Arc<Mutex<State>>, connection: &zbus::Connection) {
    // El fullname empieza con la etiqueta de instancia, que son los primeros
    // caracteres del device_id: se busca por prefijo entre lo descubierto.
    let mut changed = false;
    {
        let mut guard = state.lock().await;
        if let Some(ch) = guard.channel.as_mut() {
            let gone: Vec<String> = ch
                .discovered
                .keys()
                .filter(|id| fullname.starts_with(&id[..id.len().min(40)]))
                .cloned()
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
pub async fn unpair_peer(
    state: &Arc<Mutex<State>>,
    connection: &zbus::Connection,
    device_id: &str,
) -> bool {
    let removed = {
        let mut guard = state.lock().await;
        let removed = guard.registry.unpin_peer(device_id);
        if removed {
            guard.registry.save();
        }
        if let Some(ch) = guard.channel.as_ref() {
            ch.send_to(device_id, Message::Unpair);
            ch.shutdown(device_id);
        }
        removed
    };
    if removed {
        emit_peer_changed(connection).await;
    }
    removed
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
