//! El contrato de red entre la app del teléfono y el daemon del escritorio.
//!
//! Lo que hay en [`crate`] (al lado de este módulo) es el contrato de **D-Bus**:
//! viaja entre el daemon y los paneles de VasakOS, que están en la misma
//! máquina, y por eso usa `zbus`. Esto es otra cosa: viaja por la red, entre
//! dos aparatos, y lo tiene que entender también la app móvil —que vive en otro
//! repositorio y no puede depender de `zbus`—. Por eso el módulo es
//! deliberadamente pobre en dependencias: `serde` y `serde_json`, nada que no
//! compile en Android o iOS. El cálculo del SAS (compromiso DH, derivación) vive
//! del lado del daemon; acá sólo viaja la forma de los mensajes.
//!
//! El modelo copia el de KDE Connect porque está probado: cada aparato tiene
//! una identidad de larga vida (un certificado autofirmado), el descubrimiento
//! es por mDNS, el pareo intercambia y fija las huellas de los certificados, y
//! a partir de ahí todo va por un TLS mutuo. La seguridad la da el *pinning* del
//! certificado; lo de este archivo es sólo la forma de los mensajes.

use serde::{Deserialize, Serialize};

/// Versión del protocolo de red. Se anuncia en el descubrimiento y se manda en
/// [`Message::Hello`]; dos puntas con versiones incompatibles se descartan antes
/// de intentar parear, en vez de fallar a mitad de una conversación.
///
/// La versión 2 trae el SAS con compromiso (RFC 6189): el pareo dejó de mandar
/// un código derivado de las huellas y pasó a un intercambio Diffie-Hellman
/// efímero con compromiso. Una punta con la versión 1 se rechaza limpio en el
/// `Hello` en vez de hablar un pareo que ya no existe.
pub const PROTOCOL_VERSION: u16 = 2;

/// El tipo de servicio DNS-SD que el daemon publica y la app busca.
///
/// Con el punto final, como lo quiere la librería de mDNS: es un nombre de
/// dominio absoluto, no un prefijo.
pub const SERVICE_TYPE: &str = "_vasakconnect._tcp.local.";

/// Claves del registro TXT del anuncio mDNS. Bastan para pintar el aparato en la
/// lista y decidir si vale la pena conectarse, sin abrir todavía el TLS.
pub mod txt {
    pub const DEVICE_ID: &str = "id";
    pub const NAME: &str = "name";
    pub const KIND: &str = "kind";
    pub const PROTOCOL: &str = "proto";
    pub const FINGERPRINT: &str = "fp";
}

/// Qué es el aparato del otro lado. Sólo cambia el ícono y el texto que ve la
/// persona; no cambia el protocolo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Phone,
    Tablet,
    Desktop,
    /// Un aparato que se anunció con una palabra que esta versión no conoce. Se
    /// lista igual —con un ícono genérico— en vez de descartarlo.
    Unknown,
}

impl DeviceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceKind::Phone => "phone",
            DeviceKind::Tablet => "tablet",
            DeviceKind::Desktop => "desktop",
            DeviceKind::Unknown => "unknown",
        }
    }

    /// Cualquier cosa que no se reconozca cae en [`DeviceKind::Unknown`] en vez
    /// de ser un error: un teléfono con una categoría nueva se sigue pudiendo
    /// parear.
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "phone" => DeviceKind::Phone,
            "tablet" => DeviceKind::Tablet,
            "desktop" => DeviceKind::Desktop,
            _ => DeviceKind::Unknown,
        }
    }
}

/// Lo que cada punta dice de sí misma al abrir la conexión.
///
/// La `fingerprint` es la del certificado TLS con el que está hablando. Se
/// manda también acá —y no sólo se lee del TLS— para poder compararla con la
/// fijada en el pareo sin bajar a la capa de transporte en cada mensaje.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Identidad estable del aparato. Sobrevive a reinicios y a cambios de red;
    /// es la clave por la que se lo recuerda como de confianza.
    pub device_id: String,
    /// Lo que se le muestra a la persona: "Pixel 8 de Joaco", no el `device_id`.
    pub name: String,
    pub kind: DeviceKind,
    pub protocol_version: u16,
    /// Huella SHA-256 del certificado, en hexadecimal con dos puntos, como la
    /// imprime OpenSSL.
    pub fingerprint: String,
}

/// Estado de la batería del teléfono, empujado al escritorio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatteryStatus {
    /// Porcentaje, 0–100.
    pub level: u8,
    pub charging: bool,
}

/// El ofrecimiento de un archivo. Los bytes **no** van por acá.
///
/// El control va por JSON, que es cómodo de leer y de versionar; meter los
/// bytes de un archivo ahí los infla en base64 y hace lentos los mensajes
/// chicos. Igual que KDE Connect, el que envía abre un puerto TLS aparte y
/// anuncia acá dónde; el que recibe se conecta y lee exactamente `size` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOffer {
    /// Identifica la transferencia para casar el ofrecimiento, la aceptación y
    /// el resultado.
    pub id: String,
    /// Nombre propuesto. El que envía NO garantiza que no tenga barras ni `..`:
    /// el que recibe decide la carpeta y **debe sanitizar el nombre** antes de
    /// unirlo a una ruta, o un par malicioso escribe fuera de ella (path
    /// traversal). El contrato sólo transporta el nombre; validarlo es del
    /// receptor (daemon, PR del canal).
    pub name: String,
    pub size: u64,
    /// Tipo MIME declarado, o vacío si el que envía no lo sabe.
    pub mime: String,
    /// Puerto TCP donde esperan los bytes, en la misma dirección que la sesión
    /// de control.
    pub payload_port: u16,
}

/// Todo lo que viaja por la sesión de control, en un solo tipo etiquetado.
///
/// `tag = "type"` hace que cada mensaje lleve su nombre adentro
/// (`{"type":"ping"}`), que es lo que mira el otro lado para despachar. Un
/// `Message` nuevo que una versión vieja no conoce falla al deserializar, no se
/// interpreta mal: por eso primero se negocia [`PROTOCOL_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// Primer mensaje de cada punta: quién soy.
    Hello(PeerInfo),
    /// Pedido de pareo (lo manda el iniciador). `commitment` es
    /// `hex(SHA-256(A))`, el compromiso a la clave DH efímera `A` del iniciador,
    /// que **no** se revela todavía. Comprometerse antes de ver la clave del par
    /// es lo que impide grindear el SAS offline (RFC 6189).
    PairRequest {
        commitment: String,
    },
    /// Respuesta del respondedor al `PairRequest`: revela su clave DH efímera
    /// `B` en `hex(B)`. Como el respondedor todavía no vio `A`, revelarla acá no
    /// le da nada que grindear al iniciador.
    PairDh {
        dh_pub: String,
    },
    /// El iniciador revela su clave DH efímera `A` en `hex(A)`, recién después de
    /// ver `B`. El respondedor verifica que `SHA-256(A)` coincida con el
    /// `commitment` del `PairRequest`; si no, aborta (es la señal del
    /// intermediario).
    PairReveal {
        dh_pub: String,
    },
    /// Respuesta final del pareo, tras comparar el SAS en las dos pantallas.
    PairResponse {
        accepted: bool,
    },
    /// Deshacer el pareo. El que lo recibe olvida la huella fijada.
    Unpair,
    Ping,
    Pong,
    Battery(BatteryStatus),
    /// Texto copiado en una punta, para pegar en la otra.
    Clipboard {
        text: String,
    },
    FileOffer(FileOffer),
    /// Cómo terminó una transferencia, para la punta que ofreció.
    FileResult {
        id: String,
        ok: bool,
    },
}

/// Serializa un mensaje a bytes JSON. El marco (largo o salto de línea) lo pone
/// el transporte; acá sólo va el cuerpo.
pub fn encode(message: &Message) -> Vec<u8> {
    // `to_vec` sobre un enum derivado no puede fallar: no hay claves no-string
    // ni flotantes que no sean número. Si alguna vez falla, es un bug del tipo,
    // no un dato de red, y vale que explote en las pruebas.
    serde_json::to_vec(message).expect("Message siempre serializa")
}

/// Reconstruye un mensaje desde los bytes de un marco. El error es dato de red
/// (un marco corrupto o de una versión incompatible), así que se devuelve para
/// que el que llama decida cerrar la sesión en vez de caerse.
pub fn decode(bytes: &[u8]) -> Result<Message, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerInfo {
        PeerInfo {
            device_id: "abc-123".into(),
            name: "Pixel 8 de Joaco".into(),
            kind: DeviceKind::Phone,
            protocol_version: PROTOCOL_VERSION,
            fingerprint: "AA:BB:CC".into(),
        }
    }

    fn offer() -> FileOffer {
        FileOffer {
            id: "t1".into(),
            name: "foto.jpg".into(),
            size: 4_000_000_000,
            mime: "image/jpeg".into(),
            payload_port: 1716,
        }
    }

    fn every_message() -> Vec<Message> {
        vec![
            Message::Hello(peer()),
            Message::PairRequest {
                commitment: "ab12".into(),
            },
            Message::PairDh {
                dh_pub: "cd34".into(),
            },
            Message::PairReveal {
                dh_pub: "ef56".into(),
            },
            Message::PairResponse { accepted: true },
            Message::PairResponse { accepted: false },
            Message::Unpair,
            Message::Ping,
            Message::Pong,
            Message::Battery(BatteryStatus {
                level: 87,
                charging: true,
            }),
            Message::Clipboard {
                text: "hola \"mundo\"\n ñ 🙂".into(),
            },
            Message::FileOffer(offer()),
            Message::FileResult {
                id: "t1".into(),
                ok: false,
            },
        ]
    }

    fn json(message: &Message) -> serde_json::Value {
        serde_json::from_slice(&encode(message)).unwrap()
    }

    #[test]
    fn cada_mensaje_sobrevive_al_viaje_de_ida_y_vuelta() {
        for message in every_message() {
            let back = decode(&encode(&message)).expect("debe decodificar");
            assert_eq!(back, message);
        }
    }

    #[test]
    fn los_mensajes_sin_campos_llevan_solo_su_etiqueta() {
        assert_eq!(decode(br#"{"type":"ping"}"#).unwrap(), Message::Ping);
        assert_eq!(decode(br#"{"type":"pong"}"#).unwrap(), Message::Pong);
        assert_eq!(decode(br#"{"type":"unpair"}"#).unwrap(), Message::Unpair);
        assert_eq!(json(&Message::Ping), serde_json::json!({"type":"ping"}));
    }

    #[test]
    fn la_etiqueta_va_en_snake_case() {
        let tag = |m: Message| json(&m)["type"].as_str().unwrap().to_owned();
        assert_eq!(
            tag(Message::PairRequest {
                commitment: "1".into()
            }),
            "pair_request"
        );
        assert_eq!(tag(Message::PairDh { dh_pub: "1".into() }), "pair_dh");
        assert_eq!(
            tag(Message::PairReveal { dh_pub: "1".into() }),
            "pair_reveal"
        );
        assert_eq!(
            tag(Message::PairResponse { accepted: true }),
            "pair_response"
        );
        assert_eq!(tag(Message::FileOffer(offer())), "file_offer");
        assert_eq!(
            tag(Message::FileResult {
                id: "x".into(),
                ok: true
            }),
            "file_result"
        );
    }

    #[test]
    fn hello_battery_y_file_offer_aplanan_sus_campos_junto_al_type() {
        let hello = json(&Message::Hello(peer()));
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["device_id"], "abc-123");
        assert_eq!(hello["kind"], "phone");
        assert_eq!(hello["protocol_version"], PROTOCOL_VERSION);

        let battery = json(&Message::Battery(BatteryStatus {
            level: 5,
            charging: false,
        }));
        assert_eq!(
            battery,
            serde_json::json!({"type":"battery","level":5,"charging":false})
        );

        let file = json(&Message::FileOffer(offer()));
        assert_eq!(file["type"], "file_offer");
        assert_eq!(file["payload_port"], 1716);
        assert_eq!(file["size"], 4_000_000_000u64);
    }

    #[test]
    fn un_marco_de_la_app_movil_se_entiende() {
        let wire = r#"{"type":"clipboard","text":"pegá esto"}"#.as_bytes();
        assert_eq!(
            decode(wire).unwrap(),
            Message::Clipboard {
                text: "pegá esto".into()
            }
        );
    }

    #[test]
    fn bytes_basura_dan_error_y_no_panico() {
        assert!(decode(b"\xff\xfe\x00 no es json").is_err());
        assert!(decode(b"").is_err());
        assert!(decode(b"{").is_err());
    }

    #[test]
    fn un_type_desconocido_o_ausente_da_error() {
        assert!(decode(br#"{"type":"teleport"}"#).is_err());
        assert!(decode(br#"{"text":"sin type"}"#).is_err());
        // falta un campo obligatorio de la variante
        assert!(decode(br#"{"type":"pair_response"}"#).is_err());
    }

    #[test]
    fn un_tipo_de_aparato_desconocido_cae_en_unknown() {
        assert_eq!(DeviceKind::parse("smartwatch"), DeviceKind::Unknown);
        assert_eq!(DeviceKind::parse(""), DeviceKind::Unknown);
        assert_eq!(DeviceKind::parse(" phone "), DeviceKind::Phone);
    }

    #[test]
    fn as_str_y_parse_son_inversos() {
        for kind in [
            DeviceKind::Phone,
            DeviceKind::Tablet,
            DeviceKind::Desktop,
            DeviceKind::Unknown,
        ] {
            assert_eq!(DeviceKind::parse(kind.as_str()), kind);
        }
    }

    #[test]
    fn device_kind_viaja_en_minusculas() {
        for kind in [
            DeviceKind::Phone,
            DeviceKind::Tablet,
            DeviceKind::Desktop,
            DeviceKind::Unknown,
        ] {
            let text = serde_json::to_string(&kind).unwrap();
            assert_eq!(text, format!("\"{}\"", kind.as_str()));
            assert_eq!(serde_json::from_str::<DeviceKind>(&text).unwrap(), kind);
        }
    }
}
