//! La lógica pura del canal se mudó al crate compartido `vasak-connect-protocol`
//! (módulo [`vasak_connect_protocol::pure`]), para que la app móvil la reúse en
//! vez de reimplementar código de seguridad. Se re-exporta acá, con el mismo
//! nombre `channel::pure`, para no reapuntar los usos del daemon.

pub use vasak_connect_protocol::pure::*;
