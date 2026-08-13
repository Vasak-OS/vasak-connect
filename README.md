# vasak-connect

Usá las aplicaciones de tu celular Android como ventanas de VasakOS.

No es un escritorio de Android dentro de una ventana: cada app se abre en su
**propia ventana nativa**, junto a las del sistema, en su propio escritorio
virtual del teléfono. La pantalla del celular sigue siendo tuya mientras tanto.

> **Estado: 0.1.0, sólo por USB.** Funciona de punta a punta y está probado
> contra hardware real, pero le faltan cosas — mirá [Limitaciones](#limitaciones).

## Cómo funciona

Un demonio escucha udev. Cuando enchufás un teléfono con la depuración USB
activada, arranca el servidor de adb, lee qué aplicaciones tiene y lo publica en
el bus de sesión. El panel, el centro de notificaciones y Ajustes leen de ahí.

Abrir una app es un proceso de [scrcpy](https://github.com/Genymobile/scrcpy) con
un display virtual propio. El demonio los supervisa y los cierra cuando
corresponde.

```
udev ──► vasak-connect ──► D-Bus (sesión) ──┬─► vasak-desktop   (menú, estado)
             │                              └─► vasak-settings  (dispositivos)
             └─► scrcpy (uno por app) ──────► una ventana Wayland cada uno
```

### Por qué un demonio y no una aplicación Tauri

Porque no dibuja nada. Las tres interfaces que necesita esta función —el menú
del panel, el estado en el centro de notificaciones y la lista de dispositivos en
Ajustes— viven en aplicaciones que ya existen, y ninguna puede dibujar dentro de
la ventana de otra. No queda ninguna ventana que un proceso de acá tenga que
crear, y cargar un WebKit residente para un servicio sin ventana es exactamente
el gasto que VasakOS viene sacando de otros demonios.

### Por qué el bus de sesión

El teléfono es de quien inició sesión, el servidor de adb es por usuario, las
ventanas tienen que aparecer en *esa* sesión y la lista de dispositivos es
configuración personal. Nada de eso necesita root ni polkit.

## Requisitos

| | |
|---|---|
| `android-tools` | el `adb` que habla con el teléfono |
| `scrcpy` ≥ 3.0 | los displays virtuales (`--new-display`) |
| Android | probado en 15; los displays virtuales necesitan una versión reciente |

En el teléfono hace falta **Opciones de desarrollador → Depuración por USB**, y
aceptar el diálogo la primera vez que lo conectás.

## Compilar y probar

```bash
cargo build --release
cargo test
```

Para probarlo sin instalar nada:

```bash
RUST_LOG=vasak_connect=debug ./target/release/vasak-connect
```

Y desde otra terminal:

```bash
busctl --user call ar.net.vasak.os.Connect /ar/net/vasak/os/Connect \
  ar.net.vasak.os.Connect ListDevices

busctl --user call ar.net.vasak.os.Connect /ar/net/vasak/os/Connect \
  ar.net.vasak.os.Connect ListApps sb "TU_SERIAL" false

busctl --user call ar.net.vasak.os.Connect /ar/net/vasak/os/Connect \
  ar.net.vasak.os.Connect LaunchApp ss "TU_SERIAL" "com.google.android.calculator"
```

## La interfaz D-Bus

Nombre `ar.net.vasak.os.Connect`, ruta `/ar/net/vasak/os/Connect`, bus de sesión.
El contrato está en [`protocol/`](protocol/src/lib.rs), que es la fuente de
verdad: el panel y Ajustes dependen de esa crate para no quedar desfasados.

### Métodos

| Método | Firma | Qué hace |
|---|---|---|
| `ListDevices` | `() → a(ssssbs)` | Los teléfonos visibles ahora |
| `ListKnownDevices` | `() → a(ssss)` | Los que ya se conectaron alguna vez |
| `ListApps` | `(s serial, b refresh) → a(ssbs)` | Aplicaciones instaladas |
| `LaunchApp` | `(s serial, s package) → u` | Abre la app; devuelve el PID |
| `StopApp` | `(s serial, s package) → b` | Cierra la ventana |
| `ListRunning` | `() → a(sssu)` | Ventanas abiertas |
| `SetAlias` | `(s serial, s alias) → b` | Renombra un dispositivo |
| `ForgetDevice` | `(s serial) → b` | Lo saca de la lista de conocidos |

### Señales

`DeviceAdded`, `DeviceRemoved`, `DeviceChanged`, `AppClosed`.

`DeviceChanged` es la que importa para el estado: un teléfono aparece como
`unauthorized` hasta que la persona acepta el diálogo, y pasa a `ready` sin que
haya que volver a enchufarlo.

## Configuración

`~/.config/vasak/connect.json` guarda los dispositivos conocidos: modelo, alias,
cuándo se vieron por primera vez y su última dirección.

**No guarda credenciales ni autorizaciones.** La confianza real es la de adb —un
par de claves RSA y el diálogo del teléfono— y es la única que decide si una
conexión funciona. Duplicarla acá crearía dos respuestas a la misma pregunta, y
la de este archivo sería la que no puede hacer cumplir nada. `ForgetDevice`
olvida el nombre; para revocar el acceso de verdad, **Revocar autorizaciones de
depuración USB** en las opciones de desarrollador del teléfono.

## Costo cuando no hay nada conectado

El demonio no sondea: se queda bloqueado en el socket netlink de udev. Sin
teléfono, no hay despertares ni CPU, y el servidor de adb **ni siquiera se
arranca** hasta que udev avisa que hay algo. Al arrancar consulta udev una vez,
por si ya había un teléfono enchufado.

Si no lo querés corriendo:

```bash
systemctl --user disable --now vasak-connect
```

## Limitaciones

**Sin iconos.** Las apps se listan con su nombre. Android no expone los iconos
por ninguna orden de shell: hay que bajarse el APK y sacarlos de sus recursos, o
instalar una app compañera en el teléfono. El campo `icon` ya está en el
contrato para que agregarlo después no lo rompa.

**Sólo USB.** La conexión inalámbrica está diseñada pero no implementada. Dos
cosas que ya sabemos y condicionan cómo se va a hacer:

- El `android-tools` de Arch está compilado **sin mDNS** (`adb mdns check` lo
  dice), así que el descubrimiento automático lo va a tener que hacer el demonio
  navegando `_adb-tls-connect._tcp` por su cuenta.
- mDNS es link-local: en una red segmentada —una oficina, una universidad— no
  cruza. Por eso el registro guarda `last_address`: reconectar directo es el
  único camino cuando no hay descubrimiento.

**El menú lista todo.** 128 aplicaciones en el teléfono de prueba, 39 de ellas
del sistema. El campo `system` está para que el panel las esconda por defecto,
pero falta decidir favoritos y buscador.

**Las ventanas comparten `app_id`.** Cada app es un proceso de scrcpy, y el panel
probablemente las agrupe todas bajo el mismo icono. Falta ver si se puede fijar
por instancia.

## Licencia

[GPL-3.0-or-later](LICENSE)
