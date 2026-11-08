//! NetworkManager inventory and lifecycle over the system bus.
//!
//! NM owns the connection profile, its secrets (keyring), reconnection and
//! pushed routes/DNS. The daemon only lists VPN/WireGuard connections and
//! drives Activate/Deactivate so the app can orchestrate routes around
//! externally managed tunnels without ever seeing credentials.

use net_manager_core::daemon_protocol::{NmConnection, NmConnectionKind, NmConnectionState};
use std::collections::HashMap;
use std::io;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};

const NM: &str = "org.freedesktop.NetworkManager";
const NM_ROOT: &str = "/org/freedesktop/NetworkManager";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const NM_SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";
const NM_SETTINGS_CONNECTION: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const NM_ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const NM_DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const DBUS_PROPS: &str = "org.freedesktop.DBus.Properties";

/// NM `ActiveConnection.State`: 1 = activating, 2 = activated.
const NM_ACTIVE_ACTIVATING: u32 = 1;
const NM_ACTIVE_ACTIVATED: u32 = 2;

// NMSettingsConnectionFlags: profile represents an external device configuration.
const NM_SETTINGS_CONNECTION_FLAG_EXTERNAL: u32 = 0x08;

type SettingsMap = HashMap<String, HashMap<String, OwnedValue>>;

fn unavailable(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        format!("NetworkManager is not available: {err}"),
    )
}

fn invalid(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{err}"))
}

/// The system bus, connected lazily: a daemon started before D-Bus (or
/// inside a container) reports `NotConnected` instead of failing startup.
async fn bus() -> io::Result<&'static zbus::Connection> {
    static CELL: tokio::sync::OnceCell<zbus::Connection> = tokio::sync::OnceCell::const_new();
    CELL.get_or_try_init(|| async { zbus::Connection::system().await.map_err(unavailable) })
        .await
}

fn text(value: Option<&OwnedValue>) -> Option<String> {
    String::try_from(value?.clone()).ok()
}

fn number(value: Option<&OwnedValue>) -> Option<u32> {
    // zvariant TryFrom is type-exact — a D-Bus `u` (U32) fails u64
    // conversion — so try the unsigned widths NM actually emits.
    let value = value?.clone();
    u32::try_from(value.clone())
        .ok()
        .or_else(|| u64::try_from(value.clone()).ok().map(|v| v as u32))
        .or_else(|| u16::try_from(value.clone()).ok().map(u32::from))
        .or_else(|| u8::try_from(value).ok().map(u32::from))
}

fn object_paths(value: Option<&OwnedValue>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    Vec::<OwnedObjectPath>::try_from(value.clone())
        .map(|paths| paths.iter().map(|p| p.as_str().to_string()).collect())
        .unwrap_or_default()
}

async fn get_all(
    conn: &zbus::Connection,
    path: &str,
    interface: &str,
) -> io::Result<HashMap<String, OwnedValue>> {
    let reply = conn
        .call_method(Some(NM), path, Some(DBUS_PROPS), "GetAll", &(interface,))
        .await
        .map_err(unavailable)?;
    reply.body().deserialize().map_err(invalid)
}

async fn get<T>(conn: &zbus::Connection, path: &str, interface: &str, property: &str) -> Option<T>
where
    T: TryFrom<OwnedValue>,
{
    let reply = conn
        .call_method(
            Some(NM),
            path,
            Some(DBUS_PROPS),
            "Get",
            &(interface, property),
        )
        .await
        .ok()?;
    let value: OwnedValue = reply.body().deserialize().ok()?;
    T::try_from(value).ok()
}

struct ActiveEntry {
    path: String,
    state: u32,
    devices: Vec<String>,
}

/// Active connection UUID → object path, state and device paths.
async fn active_map(conn: &zbus::Connection) -> io::Result<HashMap<String, ActiveEntry>> {
    let reply = conn
        .call_method(
            Some(NM),
            NM_ROOT,
            Some(DBUS_PROPS),
            "Get",
            &(NM, "ActiveConnections"),
        )
        .await
        .map_err(unavailable)?;
    let value: OwnedValue = reply.body().deserialize().map_err(invalid)?;
    let paths = Vec::<OwnedObjectPath>::try_from(value).map_err(invalid)?;
    let mut active = HashMap::new();
    for path in paths {
        let props = match get_all(conn, path.as_str(), NM_ACTIVE).await {
            Ok(props) => props,
            Err(_) => continue,
        };
        let entry = ActiveEntry {
            path: path.as_str().to_string(),
            state: number(props.get("State")).unwrap_or(0),
            devices: object_paths(props.get("Devices")),
        };
        if let Some(uuid) = text(props.get("Uuid")) {
            active.insert(uuid, entry);
        }
    }
    Ok(active)
}

fn classify(settings: &SettingsMap) -> (NmConnectionKind, Option<String>) {
    let connection = settings.get("connection");
    let conn_type = connection
        .and_then(|s| text(s.get("type")))
        .unwrap_or_default();
    let interface = connection.and_then(|s| text(s.get("interface-name")));
    let service_type = settings
        .get("vpn")
        .and_then(|s| text(s.get("service-type")))
        .unwrap_or_default();
    let kind = if conn_type == "wireguard" || service_type.contains("wireguard") {
        NmConnectionKind::WireGuard
    } else if service_type.contains("openvpn") {
        NmConnectionKind::OpenVpn
    } else if conn_type == "vpn" || !service_type.is_empty() {
        NmConnectionKind::Vpn
    } else {
        NmConnectionKind::Other
    };
    (kind, interface)
}

fn inventory_kind(settings: &SettingsMap, flags: u32) -> (NmConnectionKind, Option<String>) {
    if flags & NM_SETTINGS_CONNECTION_FLAG_EXTERNAL != 0 {
        return (NmConnectionKind::Other, None);
    }
    classify(settings)
}

/// VPN and WireGuard connection profiles known to NM, with live state.
/// Plain ethernet/wifi entries are noise for routing orchestration and are
/// filtered out here.
pub async fn list_connections() -> io::Result<Vec<NmConnection>> {
    let conn = bus().await?;
    let reply = conn
        .call_method(
            Some(NM),
            NM_SETTINGS_PATH,
            Some(NM_SETTINGS),
            "ListConnections",
            &(),
        )
        .await
        .map_err(unavailable)?;
    let paths: Vec<OwnedObjectPath> = reply.body().deserialize().map_err(invalid)?;
    let active = active_map(conn).await.unwrap_or_default();
    let mut connections = Vec::new();
    for path in paths {
        let reply = conn
            .call_method(
                Some(NM),
                path.as_str(),
                Some(NM_SETTINGS_CONNECTION),
                "GetSettings",
                &(),
            )
            .await;
        let Ok(reply) = reply else { continue };
        let Ok(settings) = reply.body().deserialize::<SettingsMap>() else {
            continue;
        };
        let connection = settings.get("connection");
        let Some(uuid) = connection.and_then(|s| text(s.get("uuid"))) else {
            continue;
        };
        let id = connection
            .and_then(|s| text(s.get("id")))
            .unwrap_or_else(|| uuid.clone());
        let Some(flags) = get::<u32>(conn, path.as_str(), NM_SETTINGS_CONNECTION, "Flags").await
        else {
            continue;
        };
        let (kind, mut interface) = inventory_kind(&settings, flags);
        if kind == NmConnectionKind::Other {
            continue;
        }
        let mut state = NmConnectionState::Inactive;
        if let Some(entry) = active.get(&uuid) {
            state = match entry.state {
                NM_ACTIVE_ACTIVATED => NmConnectionState::Active,
                NM_ACTIVE_ACTIVATING => NmConnectionState::Activating,
                _ => NmConnectionState::Inactive,
            };
            // NM reports the live device for an active connection: the
            // tunnel iface name is `IpInterface` on each listed device.
            if interface.is_none() {
                for device in &entry.devices {
                    interface = get::<String>(conn, device, NM_DEVICE, "IpInterface")
                        .await
                        .filter(|name| !name.is_empty());
                    if interface.is_some() {
                        break;
                    }
                }
            }
        }
        connections.push(NmConnection {
            uuid,
            id,
            kind,
            interface_name: interface,
            state,
        });
    }
    connections.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(connections)
}

/// Activate or deactivate a profile by UUID. The daemon calls NM as root,
/// so NM's own permission checks pass; failures surface as NM errors.
pub async fn set_active(uuid: &str, active: bool) -> io::Result<()> {
    let conn = bus().await?;
    let root = ObjectPath::try_from("/").map_err(invalid)?;
    if active {
        let reply = conn
            .call_method(
                Some(NM),
                NM_SETTINGS_PATH,
                Some(NM_SETTINGS),
                "GetConnectionByUuid",
                &(uuid,),
            )
            .await
            .map_err(unavailable)?;
        let path: OwnedObjectPath = reply.body().deserialize().map_err(invalid)?;
        conn.call_method(
            Some(NM),
            NM_ROOT,
            Some(NM),
            "ActivateConnection",
            &(path.as_ref(), root.clone(), root),
        )
        .await
        .map_err(unavailable)?;
        return Ok(());
    }
    let active_map = active_map(conn).await?;
    let entry = active_map
        .get(uuid)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "connection is not active"))?;
    conn.call_method(
        Some(NM),
        NM_ROOT,
        Some(NM),
        "DeactivateConnection",
        &(ObjectPath::try_from(entry.path.as_str()).map_err(invalid)?,),
    )
    .await
    .map_err(unavailable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(entries: &[(&str, &str)]) -> HashMap<String, OwnedValue> {
        entries
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    OwnedValue::try_from(zbus::zvariant::Value::new(*v)).unwrap(),
                )
            })
            .collect()
    }

    fn settings(connection: &[(&str, &str)], vpn: Option<&[(&str, &str)]>) -> SettingsMap {
        let mut map = SettingsMap::new();
        map.insert("connection".to_string(), section(connection));
        if let Some(vpn) = vpn {
            map.insert("vpn".to_string(), section(vpn));
        }
        map
    }

    #[test]
    fn external_generated_wireguard_is_not_controllable() {
        let profile = settings(&[("type", "wireguard"), ("interface-name", "wt0")], None);
        assert_eq!(inventory_kind(&profile, 15).0, NmConnectionKind::Other);
    }

    #[test]
    fn managed_wireguard_and_vpn_remain_controllable() {
        let wireguard = settings(&[("type", "wireguard"), ("interface-name", "wt0")], None);
        let vpn = settings(
            &[("type", "vpn")],
            Some(&[("service-type", "org.freedesktop.NetworkManager.openvpn")]),
        );
        for flags in [0, 1] {
            assert_eq!(
                inventory_kind(&wireguard, flags).0,
                NmConnectionKind::WireGuard
            );
            assert_eq!(inventory_kind(&vpn, flags).0, NmConnectionKind::OpenVpn);
        }
    }

    #[test]
    fn number_accepts_all_unsigned_widths() {
        // Regression: NM's `u` props deserialize as U32 and zvariant's
        // TryFrom is type-exact — u64-only conversion silently dropped
        // every ActiveConnection State, marking live tunnels inactive.
        let u32v = OwnedValue::from(2u32);
        assert_eq!(number(Some(&u32v)), Some(2));
        let u64v = OwnedValue::from(2u64);
        assert_eq!(number(Some(&u64v)), Some(2));
        let bogus = OwnedValue::from(true);
        assert_eq!(number(Some(&bogus)), None);
    }

    #[test]
    fn classify_wireguard_by_connection_type() {
        let (kind, iface) = classify(&settings(
            &[("type", "wireguard"), ("interface-name", "wg-kzn2")],
            None,
        ));
        assert_eq!(kind, NmConnectionKind::WireGuard);
        assert_eq!(iface.as_deref(), Some("wg-kzn2"));
    }

    #[test]
    fn classify_openvpn_by_service_type() {
        let (kind, _) = classify(&settings(
            &[("type", "vpn")],
            Some(&[("service-type", "org.freedesktop.NetworkManager.openvpn")]),
        ));
        assert_eq!(kind, NmConnectionKind::OpenVpn);
    }

    #[test]
    fn classify_generic_vpn_service() {
        let (kind, _) = classify(&settings(
            &[("type", "vpn")],
            Some(&[("service-type", "org.freedesktop.NetworkManager.strongswan")]),
        ));
        assert_eq!(kind, NmConnectionKind::Vpn);
    }

    #[test]
    fn classify_plain_ethernet_is_other() {
        let (kind, iface) = classify(&settings(&[("type", "802-3-ethernet")], None));
        assert_eq!(kind, NmConnectionKind::Other);
        assert!(iface.is_none());
    }
}
