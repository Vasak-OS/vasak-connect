//! Lo que la unidad de systemd tiene que dejar pasar.
//!
//! El endurecimiento de la unidad y lo que el programa necesita se escriben en
//! archivos distintos, y nada los ata. Ya pasó una vez: la lista de familias de
//! sockets quedó en `AF_UNIX AF_NETLINK`, y con eso ni la cámara del teléfono ni
//! las ventanas de aplicaciones funcionaron nunca —las dos salen de scrcpy, y
//! scrcpy abre un túnel TCP sobre loopback—. No falló ningún test ni ninguna
//! compilación; se veía sólo enchufando un teléfono.
//!
//! Esto ata las dos puntas desde el lado que se puede comprobar sin teléfono.

use std::path::PathBuf;

/// La unidad, tal como se empaqueta.
fn unidad() -> String {
    let ruta = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../packaging/vasak-connect.service")
        .canonicalize()
        .expect("no se encontró la unidad empaquetada");
    std::fs::read_to_string(ruta).expect("no se pudo leer la unidad")
}

/// El valor de una directiva, ignorando comentarios.
///
/// Se filtran las líneas que empiezan con `#` a propósito: el bloque que explica
/// por qué la lista es la que es **nombra las directivas que se descartaron**, y
/// buscar por subcadena a secas encontraría esas menciones antes que la de
/// verdad.
fn directiva(texto: &str, nombre: &str) -> Option<String> {
    texto
        .lines()
        .map(str::trim)
        .filter(|linea| !linea.starts_with('#'))
        .find_map(|linea| linea.strip_prefix(nombre)?.strip_prefix('=').map(str::trim))
        .map(str::to_string)
}

/// scrcpy no puede trabajar sin sockets IP: su túnel es TCP sobre loopback,
/// tanto con `adb reverse` —el modo por omisión— como con `adb forward`. Sin
/// estas dos familias, `socket()` devuelve `EAFNOSUPPORT` y scrcpy corta con
/// «Server connection failed», sin nombrar nunca a la restricción.
#[test]
fn scrcpy_tiene_las_familias_de_socket_que_necesita() {
    let texto = unidad();
    let familias = directiva(&texto, "RestrictAddressFamilies")
        .expect("la unidad tiene que declarar RestrictAddressFamilies");

    for familia in ["AF_INET", "AF_INET6"] {
        assert!(
            familias.split_whitespace().any(|f| f == familia),
            "falta {familia}: sin eso scrcpy no abre su túnel, y se caen \
             la cámara del teléfono y las ventanas de aplicaciones. \
             Lista actual: {familias}"
        );
    }
}

/// udev avisa por netlink, y es lo único que entera al demonio de que
/// enchufaron o desenchufaron el teléfono.
#[test]
fn udev_sigue_pudiendo_avisar() {
    let texto = unidad();
    let familias = directiva(&texto, "RestrictAddressFamilies")
        .expect("la unidad tiene que declarar RestrictAddressFamilies");

    assert!(
        familias.split_whitespace().any(|f| f == "AF_NETLINK"),
        "sin AF_NETLINK no hay detección automática. Lista actual: {familias}"
    );
}

/// `IPAddressDeny` se ignora en silencio en unidades de usuario: se comprobó que
/// con `IPAddressDeny=any` e `IPAddressAllow=localhost` puestas, la salida a
/// internet seguía abierta. Ponerla aparentaría un límite que no existe, y el
/// próximo que lea la unidad lo daría por hecho.
#[test]
fn no_se_finge_un_limite_de_red_que_no_se_aplica() {
    let texto = unidad();
    assert!(
        directiva(&texto, "IPAddressDeny").is_none(),
        "IPAddressDeny no hace nada en una unidad de usuario"
    );
}
