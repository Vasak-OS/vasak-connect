//! El transporte: TLS mutuo con certificados autofirmados y fijados, y el
//! enmarcado de los mensajes sobre él.
//!
//! No hay CA, así que los verificadores de rustls **no** validan una cadena:
//! aceptan cualquier certificado autofirmado y dejan la decisión de confianza
//! para después del handshake, donde se compara la huella contra la fijada en el
//! pareo ([`super::pure::evaluate_peer_cert`]). Lo que los verificadores **sí**
//! hacen es comprobar la firma del handshake contra la clave del certificado
//! presentado: eso prueba que el otro lado tiene la clave privada, y sin eso un
//! atacante podría presentar el certificado (público) de un par de confianza sin
//! tenerla. Saltarse la cadena no es saltarse la prueba de posesión.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vasak_connect_protocol::wire::Message;

use super::identity::Identity;
use super::pure::{
    check_frame_len, decode_frame, encode_frame, fingerprint_from_der, frame_len, FrameError,
};

/// El proveedor criptográfico: `ring`, elegido explícitamente en vez de por
/// omisión para no arrastrar `aws-lc-sys` (que pide `cmake` al compilar) y para
/// no depender de un proveedor global instalado en otro lado.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Verificador del certificado del **servidor**, del lado que se conecta.
///
/// Acepta cualquier certificado —el pinning es posterior al handshake— pero
/// verifica la firma con la clave del certificado presentado.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Verificador del certificado del **cliente**, del lado que escucha.
///
/// Exige que el cliente presente un certificado (TLS mutuo) y acepta cualquiera,
/// con la misma prueba de posesión y el mismo pinning posterior que el de
/// servidor.
#[derive(Debug)]
struct AcceptAnyClientCert {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AcceptAnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// La configuración de servidor: presenta nuestra identidad y pide la del
/// cliente.
pub fn server_config(identity: &Identity) -> Result<ServerConfig, rustls::Error> {
    let provider = provider();
    ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCert { provider }))
        .with_single_cert(
            vec![identity.cert_der.clone()],
            identity.key_der.clone_key(),
        )
}

/// La configuración de cliente: presenta nuestra identidad y acepta la del
/// servidor para fijarla después.
pub fn client_config(identity: &Identity) -> Result<ClientConfig, rustls::Error> {
    let provider = provider();
    ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
        .with_client_auth_cert(
            vec![identity.cert_der.clone()],
            identity.key_der.clone_key(),
        )
}

/// La huella del certificado que presentó el otro lado, sacada de los
/// certificados del par de una conexión TLS ya establecida.
///
/// `None` si no presentó ninguno, que con el TLS mutuo de arriba no debería
/// pasar del lado servidor; del lado cliente siempre hay uno.
pub fn peer_fingerprint(peer_certificates: Option<&[CertificateDer<'static>]>) -> Option<String> {
    peer_certificates
        .and_then(<[_]>::first)
        .map(|cert| fingerprint_from_der(cert))
}

/// Un error de la sesión: de red, de enmarcado o de cierre limpio del otro lado.
#[derive(Debug)]
pub enum SessionError {
    Io(std::io::Error),
    Frame(FrameError),
    /// El otro lado cerró la conexión entre marcos.
    Closed,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Io(err) => write!(f, "{err}"),
            SessionError::Frame(err) => write!(f, "{err}"),
            SessionError::Closed => write!(f, "el par cerró la conexión"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Lee un marco completo: la cabecera de largo, el chequeo de tamaño y el cuerpo.
///
/// El tope lo hace valer [`check_frame_len`] **antes** de reservar el buffer, así
/// que un largo enorme se rechaza sin pedir esa memoria. Toda la validación es
/// pura; acá sólo está el movimiento de bytes.
pub async fn read_frame<R>(reader: &mut R) -> Result<Message, SessionError>
where
    R: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(SessionError::Closed)
        }
        Err(err) => return Err(SessionError::Io(err)),
    }
    let len = check_frame_len(frame_len(header)).map_err(SessionError::Frame)?;
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(SessionError::Io)?;
    decode_frame(&body).map_err(SessionError::Frame)
}

/// Escribe un marco: el cuerpo con su largo delante, y hace `flush` para que
/// salga ya y no se quede esperando a otro.
pub async fn write_frame<W>(writer: &mut W, message: &Message) -> Result<(), SessionError>
where
    W: AsyncWriteExt + Unpin,
{
    writer
        .write_all(&encode_frame(message))
        .await
        .map_err(SessionError::Io)?;
    writer.flush().await.map_err(SessionError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::pure::MAX_FRAME;

    #[tokio::test]
    async fn un_marco_escrito_se_lee_igual() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let sent = Message::Clipboard {
            text: "hola".into(),
        };
        write_frame(&mut a, &sent).await.unwrap();
        write_frame(&mut a, &Message::Ping).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), sent);
        assert_eq!(read_frame(&mut b).await.unwrap(), Message::Ping);
    }

    #[tokio::test]
    async fn un_marco_sobre_el_tope_se_rechaza_sin_leer_el_cuerpo() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let len = (MAX_FRAME as u32 + 1).to_be_bytes();
        a.write_all(&len).await.unwrap();
        assert!(matches!(
            read_frame(&mut b).await,
            Err(SessionError::Frame(FrameError::TooLarge(_)))
        ));
    }

    #[tokio::test]
    async fn un_marco_de_largo_cero_se_rechaza() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0, 0, 0]).await.unwrap();
        assert!(matches!(
            read_frame(&mut b).await,
            Err(SessionError::Frame(FrameError::Empty))
        ));
    }

    #[tokio::test]
    async fn cerrar_entre_marcos_es_cierre_limpio() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(matches!(
            read_frame(&mut b).await,
            Err(SessionError::Closed)
        ));
    }

    #[tokio::test]
    async fn un_cuerpo_truncado_o_corrupto_es_error() {
        // Cuerpo truncado: anuncia 10 bytes y entrega 3 antes de cerrar.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0, 0, 10, b'{', b'}', b'x']).await.unwrap();
        drop(a);
        assert!(matches!(read_frame(&mut b).await, Err(SessionError::Io(_))));
        // Cuerpo completo pero que no es un mensaje.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0, 0, 3, b'x', b'y', b'z']).await.unwrap();
        assert!(matches!(
            read_frame(&mut b).await,
            Err(SessionError::Frame(FrameError::Malformed))
        ));
    }

    #[test]
    fn los_errores_de_sesion_se_explican() {
        assert!(!SessionError::Closed.to_string().is_empty());
        assert!(!SessionError::Frame(FrameError::Empty)
            .to_string()
            .is_empty());
    }
}
