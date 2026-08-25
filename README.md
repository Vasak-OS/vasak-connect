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
| `v4l2loopback` | el dispositivo donde se escribe la cámara (webcam) |
| Android | probado en 15; los displays virtuales necesitan una versión reciente |

El módulo `v4l2loopback` lo provee el propio kernel en varias distribuciones
—los kernels de CachyOS lo traen compilado— y en el resto sale de
`v4l2loopback-dkms`. Por eso el paquete depende del proveedor virtual
`V4L2LOOPBACK-MODULE` y no de un paquete concreto: nombrar el de DKMS obligaría
a recompilar en cada actualización de kernel a quien ya lo tiene.

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
| `ListCameras` | `(s serial, b refresh) → a(ssasau)` | Cámaras, con sus tamaños y fps |
| `StartWebcam` | `(s serial, s camera_id, s size, u fps) → s` | Conecta la cámara; devuelve `/dev/videoN` |
| `StopWebcam` | `() → b` | Corta el stream |
| `WebcamState` | `() → (bssss)` | Qué está haciendo el puente |

### Señales

`DeviceAdded`, `DeviceRemoved`, `DeviceChanged`, `AppClosed`, `WebcamChanged`.

`DeviceChanged` es la que importa para el estado: un teléfono aparece como
`unauthorized` hasta que la persona acepta el diálogo, y pasa a `ready` sin que
haya que volver a enchufarlo.

`WebcamChanged` existe porque el stream puede terminar sin que nadie lo pida
—el teléfono se bloquea, u otra app del teléfono se queda con el sensor—, y un
panel que siga mostrando «transmitiendo» diez minutos después es peor que no
mostrar nada.

## La cámara como webcam

La cámara del teléfono se puede usar en cualquier aplicación de videollamada.
scrcpy lee el sensor y escribe los cuadros en un dispositivo `v4l2loopback`;
Zoom, Firefox u OBS lo ven como una cámara más, llamada **VasakOS Phone**.

```bash
busctl --user call ar.net.vasak.os.Connect /ar/net/vasak/os/Connect \
  ar.net.vasak.os.Connect ListCameras sb "TU_SERIAL" false

busctl --user call ar.net.vasak.os.Connect /ar/net/vasak/os/Connect \
  ar.net.vasak.os.Connect StartWebcam sssu "TU_SERIAL" "0" "1280x720" 30
```

Tres decisiones que conviene conocer antes de cambiar algo acá:

**El dispositivo se busca por nombre, no por número.** `/dev/video0` es la
primera cámara que encontró el kernel, que en una notebook es la webcam
integrada: escribir ahí sería escribir encima de hardware real. El módulo se
carga con un `card_label` conocido y el demonio lo busca en sysfs, así que el
número puede ser cualquiera. Ojo: V4L2 trunca la etiqueta a 31 caracteres, y la
comparación es por igualdad — un nombre más largo no coincidiría con nada.

**El módulo se carga al arrancar, no cuando hace falta.** `modprobe` necesita
root y este servicio corre en la sesión; pedir una autorización de polkit para
encender una webcam sería peor que el problema que resuelve. Que esté siempre
cargado no molesta gracias a `exclusive_caps=1`: con esa opción el dispositivo
sólo se anuncia como cámara mientras algo esté escribiendo en él. Sin ella,
todas las aplicaciones de videollamada ofrecerían «VasakOS Phone»
permanentemente y mostrarían negro a quien la eligiera.

**Un stream a la vez.** Un dispositivo V4L2 admite una sola fuente. Conectar un
segundo teléfono no agregaría una cámara: corrompería la primera, así que el
puente es único y lo dice con un error propio.

Los tamaños y los fps salen del teléfono, no de una lista de resoluciones
comunes: pedir un modo que el sensor no tiene es la forma habitual de que el
stream abra y se muera medio segundo después.

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

**La webcam necesita un reinicio después de actualizar el kernel.** El módulo
que se instaló es el del kernel nuevo, y el que corre es el viejo; hasta
reiniciar, `WebcamState` devuelve el dispositivo vacío y `StartWebcam` explica
por qué. Es el único caso en que la función aparece como no disponible en un
sistema que la tiene instalada.

**La cámara no trae audio.** El puente pasa vídeo solamente. El micrófono del
teléfono es un stream aparte y mezclarlo acá significaría decidir por la
aplicación de videollamada, que ya tiene su propio selector de micrófono.

**El menú lista todo.** 128 aplicaciones en el teléfono de prueba, 39 de ellas
del sistema. El campo `system` está para que el panel las esconda por defecto,
pero falta decidir favoritos y buscador.

**Las ventanas comparten `app_id`.** Cada app es un proceso de scrcpy, y el panel
probablemente las agrupe todas bajo el mismo icono. Falta ver si se puede fijar
por instancia.

## Licencia

[GPL-3.0-or-later](LICENSE)
