//! Telling the person a phone showed up.
//!
//! Goes through the ordinary freedesktop notification interface, which on
//! VasakOS is `vasak-flare-daemon`. No special channel: a notification from
//! this service should look and behave like every other one, including landing
//! in the notification centre's history.

use tracing::debug;
use zbus::Connection;

const NOTIFICATIONS: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";

/// The icon shown on every notification from this service.
///
/// A freedesktop icon name, not a path: the notification daemon resolves it
/// against the theme in use, so it follows light and dark like every other
/// icon in the session. `smartphone` ships in vasakos-icon-theme under
/// `devices/`, at every size from 16 to 512.
pub const PHONE_ICON: &str = "smartphone";

/// Sends a notification, and says nothing if it cannot.
///
/// A missing notification daemon is not a reason to fail a connection: the
/// phone still works, the panel still lists it. This is an announcement, not a
/// step.
pub async fn send(connection: &Connection, summary: &str, body: &str, icon: &str) {
    let result = connection
        .call_method(
            Some(NOTIFICATIONS),
            NOTIFICATIONS_PATH,
            Some(NOTIFICATIONS),
            "Notify",
            &(
                "VasakOS",
                0u32, // 0 = new notification rather than a replacement
                icon,
                summary,
                body,
                Vec::<String>::new(),
                std::collections::HashMap::<String, zbus::zvariant::Value>::new(),
                5000i32,
            ),
        )
        .await;

    if let Err(err) = result {
        debug!(%err, "no se pudo enviar la notificación");
    }
}
