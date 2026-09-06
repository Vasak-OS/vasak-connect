//! Preguntar antes de encender la cámara del teléfono.
//!
//! # Por qué
//!
//! Este servicio expone la cámara del teléfono como un dispositivo de video más
//! del equipo. Es una cámara que el escritorio enciende, y hasta acá la
//! encendía **sin consultarle nada a nadie**.
//!
//! La regla del escritorio es que todo lo que se concede se pueda retirar, y la
//! cámara del equipo ya la cumple: se pregunta, queda anotada en Privacidad y
//! seguridad, y se revoca desde ahí. Ésta era la única que quedaba afuera.
//!
//! Y es la que más falta le hace preguntar. La del equipo tiene una luz al
//! lado; la del teléfono, cuando la enciende el escritorio, no necesariamente
//! da ninguna señal en el teléfono.
//!
//! # Cómo
//!
//! Se le pregunta al servicio de permisos con `CheckPermission`, que identifica
//! a quien llama por el ejecutable detrás de su pid — o sea, a nosotros. La
//! decisión que queda guardada es «el escritorio puede usar la cámara del
//! teléfono», que es la pregunta que la persona entiende.
//!
//! Distinguir además **qué programa** consume el dispositivo de video sería
//! otro trabajo: quien lo abre habla con el kernel, no con nosotros, así que no
//! hay forma de saberlo desde acá.
//!
//! # Dos buses
//!
//! El servicio de permisos vive en el bus del **sistema** y éste atiende en el
//! de **sesión**. Es una conexión aparte, abierta cuando hace falta y no al
//! arrancar: un equipo sin el servicio instalado tiene que poder levantar este
//! daemon igual.

use std::time::Duration;

/// El recurso, tal como lo nombra el servicio de permisos.
const RECURSO: &str = "camera";

/// Cuánto se espera una respuesta.
///
/// Generoso a propósito: si es la primera vez, del otro lado hay una persona
/// leyendo un diálogo. Pero con techo, porque sin él una sesión sin agente
/// dejaría la llamada colgada para siempre y el pedido de cámara no terminaría
/// nunca — ni con un sí ni con un no.
const ESPERA: Duration = Duration::from_secs(120);

/// Si se puede encender la cámara del teléfono.
///
/// **Falla cerrado.** Si el servicio no está, no contesta o tarda demasiado, la
/// respuesta es que no. La cámara es justo lo que no se concede por omisión: un
/// fallo del servicio no puede terminar en «bueno, dale», porque entonces
/// bastaría con voltear el servicio para saltearse el permiso.
///
/// `detalle` es para el diálogo —de qué teléfono se trata— y no cambia la
/// decisión guardada: sirve para que la pregunta diga algo, no para poder
/// hacerla dos veces con distinto texto.
pub async fn puede_usar_la_camara(detalle: &str) -> Result<(), String> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|e| format!("no se pudo hablar con el servicio de permisos: {e}"))?;

    let argumentos = (RECURSO, detalle);
    let llamada = connection.call_method(
        Some("ar.net.vasak.os.Permissions"),
        "/ar/net/vasak/os/Permissions",
        Some("ar.net.vasak.os.Permissions"),
        "CheckPermission",
        &argumentos,
    );

    let respuesta = tokio::time::timeout(ESPERA, llamada)
        .await
        .map_err(|_| "el permiso de cámara no se contestó a tiempo".to_string())?
        .map_err(|e| format!("no se pudo consultar el permiso de cámara: {e}"))?;

    let concedido: bool = respuesta
        .body()
        .deserialize()
        .map_err(|e| format!("respuesta inesperada del servicio de permisos: {e}"))?;

    if concedido {
        Ok(())
    } else {
        Err("no se permitió usar la cámara del teléfono".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El recurso tiene que ser el que el servicio conoce. Si se escribiera
    /// otro, el servicio lo rechazaría por desconocido y la cámara quedaría
    /// bloqueada sin que ninguna pantalla ofrezca desbloquearla — que es
    /// exactamente lo que este cambio viene a evitar.
    #[test]
    fn el_recurso_es_el_que_el_servicio_nombra() {
        assert_eq!(RECURSO, "camera");
    }

    /// La espera tiene techo, y no es corto.
    ///
    /// Sin techo, una sesión sin agente de permisos deja el pedido colgado para
    /// siempre. Corto, se cancelaría mientras la persona lee el diálogo, que es
    /// peor: sería un «no» que nadie dijo.
    #[test]
    fn la_espera_da_tiempo_a_leer_pero_no_es_infinita() {
        assert!(ESPERA >= Duration::from_secs(30));
        assert!(ESPERA <= Duration::from_secs(300));
    }
}
