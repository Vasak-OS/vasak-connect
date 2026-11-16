//! La identidad TLS de larga vida del escritorio.
//!
//! Es un certificado autofirmado con su clave privada, como el de KDE Connect:
//! no lo valida ninguna CA, la seguridad la da el *pinning* de la huella durante
//! el pareo. La **clave privada** es un secreto y vive en el Secret Service
//! estándar (`org.freedesktop.secrets`, que en VasakOS implementa
//! `vasak-keyring`); el **certificado** es público y va a un archivo al lado del
//! resto de la configuración de la sesión. Al arrancar se leen los dos; si falta
//! cualquiera, se genera un par nuevo y se guarda.
//!
//! La generación del par y el acceso al llavero son lo único de acá que no se
//! puede probar sin entorno; el cálculo de la huella y del `device_id` sale de
//! [`crate::channel::pure`], que sí se prueba.

use std::collections::HashMap;
use std::path::PathBuf;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use super::pure::{device_id_from_fingerprint, fingerprint_from_der, identity_pair_matches};

/// Atributos con los que se guarda y se busca la clave en el Secret Service.
///
/// `application`/`type` alcanzan para que el ítem sea nuestro y único: el
/// servicio entrega sólo los ítems cuyos atributos coinciden exactamente.
fn secret_attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([("application", "vasak-connect"), ("type", "tls-identity")])
}

/// La etiqueta que ve la persona si abre el administrador de contraseñas.
const SECRET_LABEL: &str = "VasakOS Connect — identidad TLS";

/// La identidad cargada: lo que necesita rustls (certificado y clave) más la
/// huella y el `device_id` que se derivan del certificado.
pub struct Identity {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    /// SHA-256 del DER del certificado, con dos puntos, como en
    /// [`vasak_connect_protocol::wire::PeerInfo::fingerprint`].
    pub fingerprint: String,
    /// Identificador estable derivado de la huella.
    pub device_id: String,
}

impl Identity {
    /// Arma la identidad a partir del certificado y la clave en DER, derivando la
    /// huella y el `device_id`. No toca red, llavero ni disco.
    ///
    /// La clave llega envuelta en [`Zeroizing`] para que esa copia intermedia se
    /// borre de la memoria al salir. Queda una sola copia en claro —la que vive
    /// dentro de `key_der` para que rustls firme con ella—, que por fuerza persiste
    /// mientras el canal esté levantado; la frontera que la protege es el
    /// aislamiento del proceso y del bus de sesión (mitigado por AppArmor).
    fn from_parts(cert_der: Vec<u8>, key_pkcs8_der: Zeroizing<Vec<u8>>) -> Self {
        let fingerprint = fingerprint_from_der(&cert_der);
        let device_id = device_id_from_fingerprint(&fingerprint);
        Identity {
            cert_der: CertificateDer::from(cert_der),
            key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8_der.to_vec())),
            fingerprint,
            device_id,
        }
    }
}

/// Errores al cargar o crear la identidad. Cada uno dice qué falló para que el
/// que arranca el canal pueda registrarlo; ninguno hace entrar en pánico.
#[derive(Debug)]
pub enum IdentityError {
    Keyring(oo7::Error),
    Generate(rcgen::Error),
    CertFile(std::io::Error),
    NoConfigDir,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Keyring(err) => write!(f, "Secret Service: {err}"),
            IdentityError::Generate(err) => write!(f, "no se pudo generar el certificado: {err}"),
            IdentityError::CertFile(err) => write!(f, "archivo de certificado: {err}"),
            IdentityError::NoConfigDir => {
                write!(
                    f,
                    "sin HOME ni XDG_CONFIG_HOME: no hay dónde guardar el certificado"
                )
            }
        }
    }
}

impl std::error::Error for IdentityError {}

/// `~/.config/vasak/connect-cert.der`, al lado del resto de la configuración.
///
/// Con el mismo filtro de base absoluta que usa el registro: una base relativa
/// dejaría el certificado bajo el directorio de trabajo del demonio y la
/// identidad parecería perderse en cada arranque.
fn cert_path() -> Option<PathBuf> {
    let base = dirs::config_dir().filter(|base| base.is_absolute())?;
    Some(base.join("vasak").join("connect-cert.der"))
}

/// Genera un par nuevo: certificado y clave en DER.
///
/// La clave es ECDSA P-256 (el valor por omisión de `rcgen`), que el proveedor
/// `ring` de rustls firma y verifica. El certificado va con un único SAN que no
/// se usa para nada —no hay validación de nombre—, está sólo para que sea un
/// certificado bien formado.
fn generate() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), rcgen::Error> {
    let certified = rcgen::generate_simple_self_signed(vec!["vasak-connect".to_string()])?;
    let cert_der = certified.cert.der().to_vec();
    // La clave en claro se envuelve en `Zeroizing` ni bien se genera, para que su
    // copia intermedia se borre al moverla, no quede olvidada en el montón.
    let key_der = Zeroizing::new(certified.signing_key.serialize_der());
    Ok((cert_der, key_der))
}

/// Nombre del atributo que ata la clave guardada a su certificado: la huella del
/// certificado que forma par con esta clave. Al cargar se compara con la del
/// certificado en disco; si no coinciden, son de generaciones distintas.
const CERT_FINGERPRINT_ATTR: &str = "cert_fp";

/// La clave privada del llavero más la huella del certificado con el que se
/// guardó, si está.
async fn load_key() -> Result<Option<(Zeroizing<Vec<u8>>, Option<String>)>, oo7::Error> {
    let keyring = oo7::Keyring::new().await?;
    let items = keyring.search_items(&secret_attributes()).await?;
    match items.first() {
        Some(item) => {
            let stored_fp = item.attributes().await?.get(CERT_FINGERPRINT_ATTR).cloned();
            // El `Secret` de oo7 ya se borra solo al soltarse; la copia que sacamos
            // se envuelve en `Zeroizing` para que corra la misma suerte.
            let key = Zeroizing::new(item.secret().await?.to_vec());
            Ok(Some((key, stored_fp)))
        }
        None => Ok(None),
    }
}

/// Guarda (reemplazando) la clave privada en el Secret Service, con la huella de
/// su certificado como atributo, para poder detectar después un par desparejo.
async fn store_key(key_pkcs8_der: &[u8], cert_fingerprint: &str) -> Result<(), oo7::Error> {
    let keyring = oo7::Keyring::new().await?;
    let attributes = HashMap::from([
        ("application", "vasak-connect"),
        ("type", "tls-identity"),
        (CERT_FINGERPRINT_ATTR, cert_fingerprint),
    ]);
    keyring
        .create_item(SECRET_LABEL, &attributes, key_pkcs8_der, true)
        .await?;
    Ok(())
}

/// Carga la identidad, o la crea y la guarda si falta o si quedó desparejo.
///
/// Lee la clave del llavero y el certificado del archivo. Los usa sólo si los dos
/// están **y son el mismo par** —la huella guardada con la clave coincide con la
/// del certificado en disco—; si no, genera un par nuevo y lo persiste. Esto
/// recupera un corte entre guardar la clave y escribir el certificado: ahí la
/// clave nueva y el certificado viejo no se corresponden, el TLS fallaría siempre,
/// y sin esta comprobación el próximo arranque los daría por buenos.
pub async fn load_or_create() -> Result<Identity, IdentityError> {
    let path = cert_path().ok_or(IdentityError::NoConfigDir)?;

    let key = load_key().await.map_err(IdentityError::Keyring)?;
    let cert = match tokio::fs::read(&path).await {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(IdentityError::CertFile(err)),
    };

    if let (Some((key, stored_fp)), Some(cert)) = (key, cert) {
        if identity_pair_matches(stored_fp.as_deref(), &cert) {
            debug!("identidad TLS cargada del llavero y del archivo");
            return Ok(Identity::from_parts(cert, key));
        }
        warn!("la clave y el certificado guardados no son el mismo par: se regenera la identidad");
    }

    debug!("sin identidad TLS consistente: se genera una nueva");
    let (cert_der, key_der) = generate().map_err(IdentityError::Generate)?;
    let cert_fingerprint = fingerprint_from_der(&cert_der);
    store_key(&key_der[..], &cert_fingerprint)
        .await
        .map_err(IdentityError::Keyring)?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(IdentityError::CertFile)?;
    }
    tokio::fs::write(&path, &cert_der)
        .await
        .map_err(IdentityError::CertFile)?;

    Ok(Identity::from_parts(cert_der, key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_identidad_generada_deriva_huella_e_id_del_certificado() {
        let (cert, key) = generate().unwrap();
        let identity = Identity::from_parts(cert.clone(), key);
        assert_eq!(identity.fingerprint, fingerprint_from_der(&cert));
        assert_eq!(
            identity.device_id,
            device_id_from_fingerprint(&identity.fingerprint)
        );
        assert_eq!(identity.cert_der.as_ref(), cert.as_slice());
        assert!(matches!(identity.key_der, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn dos_identidades_generadas_no_comparten_huella() {
        let (a, _) = generate().unwrap();
        let (b, _) = generate().unwrap();
        assert_ne!(fingerprint_from_der(&a), fingerprint_from_der(&b));
    }

    #[test]
    fn los_atributos_del_llavero_son_los_de_vasak_connect() {
        let attrs = secret_attributes();
        assert_eq!(attrs["application"], "vasak-connect");
        assert_eq!(attrs["type"], "tls-identity");
    }

    #[test]
    fn los_errores_de_identidad_se_explican() {
        assert!(IdentityError::NoConfigDir.to_string().contains("HOME"));
        let io = std::io::Error::other("boom");
        assert!(IdentityError::CertFile(io).to_string().contains("boom"));
    }
}
