#[cfg(target_os = "linux")]
pub(crate) use net_manager_engine::linux_diagnostics::LocalProxy;
#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn scan_local_proxies() -> Result<Vec<LocalProxy>, String> {
    net_manager_engine::linux_diagnostics::scan_local_proxies().await
}
#[cfg(not(target_os = "linux"))]
pub(crate) use non_linux::*;
#[cfg(not(target_os = "linux"))]
mod non_linux {
    //! Localhost proxy discovery. Probes listeners bound to loopback/any with
    //! SOCKS5, HTTP CONNECT and SOCKS4 handshakes and reports real proxy
    //! services — an open port alone is never reported. Discovery only; nothing
    //! is connected or routed automatically.

    use serde::Serialize;
    use std::net::IpAddr;
    #[cfg(target_os = "linux")]
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    const PROBE_TIMEOUT: Duration = Duration::from_millis(300);
    /// Loopback listeners above this count are a misconfigured/broken host; stop
    /// early instead of probing thousands of ports.
    #[cfg(target_os = "linux")]
    const MAX_CANDIDATES: usize = 256;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub(crate) enum ProxyKind {
        Socks5,
        Socks4,
        Http,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct LocalProxy {
        pub address: IpAddr,
        pub port: u16,
        pub kind: ProxyKind,
    }

    /// One `/proc/net/tcp{,6}` row → `(ip, port)` when the socket is LISTENing on
    /// loopback or the wildcard address.
    #[cfg(target_os = "linux")]
    fn parse_listen_line(line: &str, v6: bool) -> Option<(IpAddr, u16)> {
        let mut f = line.split_whitespace();
        f.next()?; // sl
        let local = f.next()?;
        f.next()?; // rem_address
        if f.next()? != "0A" {
            return None; // not LISTEN
        }
        let (addr_hex, port_hex) = local.split_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        if port == 0 {
            return None;
        }
        let ip = if v6 {
            if addr_hex.len() != 32 {
                return None;
            }
            // procfs stores each 32-bit word little-endian.
            let mut w = [0u16; 8];
            for i in 0..4 {
                let be = u32::from_str_radix(&addr_hex[i * 8..i * 8 + 8], 16)
                    .ok()?
                    .swap_bytes();
                w[i * 2] = (be >> 16) as u16;
                w[i * 2 + 1] = (be & 0xffff) as u16;
            }
            IpAddr::V6(Ipv6Addr::new(
                w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
            ))
        } else {
            IpAddr::V4(Ipv4Addr::from(
                u32::from_str_radix(addr_hex, 16).ok()?.swap_bytes(),
            ))
        };
        if ip.is_loopback() || ip.is_unspecified() {
            Some((ip, port))
        } else {
            None
        }
    }

    /// Ports with a listener reachable via loopback, each mapped to a probe
    /// address: 127.0.0.1 when an IPv4 loopback/any bind covers it, else ::1.
    #[cfg(target_os = "linux")]
    fn loopback_listen_ports() -> Vec<(IpAddr, u16)> {
        let mut v4 = std::collections::HashSet::new();
        let mut v6 = std::collections::HashSet::new();
        for (path, is_v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for line in text.lines().skip(1) {
                if let Some((ip, port)) = parse_listen_line(line, is_v6) {
                    if ip.is_ipv4() {
                        v4.insert(port);
                    } else {
                        v6.insert(port);
                    }
                }
            }
        }
        let mut ports: Vec<u16> = v4.union(&v6).copied().collect();
        ports.sort_unstable();
        ports.truncate(MAX_CANDIDATES);
        ports
            .into_iter()
            .map(|p| {
                (
                    if v4.contains(&p) {
                        IpAddr::V4(Ipv4Addr::LOCALHOST)
                    } else {
                        IpAddr::V6(Ipv6Addr::LOCALHOST)
                    },
                    p,
                )
            })
            .collect()
    }

    #[cfg(not(target_os = "linux"))]
    fn loopback_listen_ports() -> Vec<(IpAddr, u16)> {
        Vec::new()
    }

    /// `05 01 00` — offer NOAUTH. A SOCKS5 server replies `05 <method>`.
    async fn probe_socks5(stream: &mut TcpStream) -> bool {
        if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
            return false;
        }
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.is_ok() && reply[0] == 0x05
    }

    /// `CONNECT` to a dead loopback port. A CONNECT-capable proxy answers with a
    /// failure status it generated itself (5xx/407/403/200). A plain HTTP server
    /// rejects the method outright (400/404/405/501) and is not a proxy.
    async fn probe_http(stream: &mut TcpStream) -> bool {
        if stream
            .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n")
            .await
            .is_err()
        {
            return false;
        }
        let mut line = String::new();
        let mut reader = BufReader::new(stream);
        let Ok(Ok(n)) = timeout(PROBE_TIMEOUT, reader.read_line(&mut line)).await else {
            return false;
        };
        if n == 0 {
            return false;
        }
        let Some(rest) = line.strip_prefix("HTTP/") else {
            return false;
        };
        let Some(status) = rest
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
        else {
            return false;
        };
        !matches!(status, 400 | 404 | 405 | 501)
    }

    /// `04 01 00 01 7F 00 00 01 00` — CONNECT to 127.0.0.1:1. A SOCKS4 server
    /// replies with 8 bytes: VN ∈ {0,4}, CD ∈ 0x5A..=0x5D.
    async fn probe_socks4(stream: &mut TcpStream) -> bool {
        if stream
            .write_all(&[0x04, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00])
            .await
            .is_err()
        {
            return false;
        }
        let mut reply = [0u8; 8];
        stream.read_exact(&mut reply).await.is_ok()
            && (reply[0] == 0x00 || reply[0] == 0x04)
            && (0x5a..=0x5d).contains(&reply[1])
    }

    async fn probe(addr: IpAddr, port: u16) -> Option<ProxyKind> {
        for kind in [ProxyKind::Socks5, ProxyKind::Http, ProxyKind::Socks4] {
            let Ok(Ok(mut stream)) = timeout(PROBE_TIMEOUT, TcpStream::connect((addr, port))).await
            else {
                return None; // listener vanished — nothing more to probe
            };
            let attempt = async {
                match kind {
                    ProxyKind::Socks5 => probe_socks5(&mut stream).await,
                    ProxyKind::Http => probe_http(&mut stream).await,
                    ProxyKind::Socks4 => probe_socks4(&mut stream).await,
                }
            };
            if timeout(PROBE_TIMEOUT, attempt).await.unwrap_or(false) {
                return Some(kind);
            }
        }
        None
    }

    async fn probe_targets(candidates: Vec<(IpAddr, u16)>) -> Vec<LocalProxy> {
        let mut set = tokio::task::JoinSet::new();
        for (addr, port) in candidates {
            set.spawn(async move { probe(addr, port).await.map(|k| (addr, port, k)) });
        }
        let mut found = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok(Some((address, port, kind))) = res {
                found.push(LocalProxy {
                    address,
                    port,
                    kind,
                });
            }
        }
        found.sort_by_key(|p| p.port);
        found
    }

    pub(crate) async fn run_scan() -> Vec<LocalProxy> {
        probe_targets(loopback_listen_ports()).await
    }

    #[tauri::command]
    pub(crate) async fn scan_local_proxies() -> Result<Vec<LocalProxy>, String> {
        Ok(run_scan().await)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[cfg(not(target_os = "linux"))]
        use std::net::Ipv4Addr;
        use tokio::net::TcpListener;

        #[cfg(target_os = "linux")]
        #[test]
        fn parses_proc_tcp_listen_line() {
            let listen =
            "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
            assert_eq!(
                parse_listen_line(listen, false),
                Some((IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
            );
            // ESTABLISHED (st=01) is skipped; non-loopback binds are skipped.
            let estab =
            "   0: 0100007F:1F90 0100007F:0046 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 0";
            let lan =
            "   0: 0B01A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
            let any =
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
            assert_eq!(parse_listen_line(estab, false), None);
            assert_eq!(parse_listen_line(lan, false), None);
            assert_eq!(
                parse_listen_line(any, false),
                Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80))
            );
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn parses_proc_tcp6_listen_line() {
            // ::1 (0000...0001 stored as four LE u32 words) on port 8080.
            let listen =
            "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
            assert_eq!(
                parse_listen_line(listen, true),
                Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 8080))
            );
        }

        /// Accept connections and serve `f` to each until the test ends.
        async fn responder<F, Fut>(f: F) -> (IpAddr, u16)
        where
            F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
            Fut: std::future::Future<Output = ()> + Send,
        {
            let f = std::sync::Arc::new(f);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let f = f.clone();
                    tokio::spawn(async move { f(stream).await });
                }
            });
            (IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        }

        #[tokio::test]
        async fn detects_socks5() {
            let (addr, port) = responder(|mut s| async move {
                let mut buf = [0u8; 3];
                let _ = s.read_exact(&mut buf).await;
                let _ = s.write_all(&[0x05, 0x00]).await;
            })
            .await;
            assert_eq!(probe(addr, port).await, Some(ProxyKind::Socks5));
        }

        #[tokio::test]
        async fn detects_http_connect_proxy() {
            let (addr, port) = responder(|mut s| async move {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf).await;
                if buf[0] == 0x05 {
                    return; // close on the socks greeting
                }
                let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            })
            .await;
            assert_eq!(probe(addr, port).await, Some(ProxyKind::Http));
        }

        #[tokio::test]
        async fn plain_http_server_is_not_a_proxy() {
            let (addr, port) = responder(|mut s| async move {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf).await;
                if buf[0] == 0x05 {
                    return;
                }
                let _ = s
                    .write_all(b"HTTP/1.0 405 Method Not Allowed\r\n\r\n")
                    .await;
            })
            .await;
            assert_eq!(probe(addr, port).await, None);
        }

        #[tokio::test]
        async fn detects_socks4() {
            let (addr, port) = responder(|mut s| async move {
                let mut buf = [0u8; 16];
                let _ = s.read(&mut buf).await;
                if buf[0] != 0x04 {
                    return; // not a SOCKS4 greeting
                }
                let mut reply = [0u8; 8];
                reply[1] = 0x5b; // request rejected — still proves SOCKS4
                let _ = s.write_all(&reply).await;
            })
            .await;
            assert_eq!(probe(addr, port).await, Some(ProxyKind::Socks4));
        }

        #[tokio::test]
        async fn silent_listener_is_rejected() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let _ = listener.accept().await; // never speak
                }
            });
            assert_eq!(probe(IpAddr::V4(Ipv4Addr::LOCALHOST), port).await, None);
        }

        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn scan_finds_real_listener() {
            let (addr, port) = responder(|mut s| async move {
                let mut buf = [0u8; 3];
                let _ = s.read_exact(&mut buf).await;
                let _ = s.write_all(&[0x05, 0x00]).await;
            })
            .await;
            // End to end: the listener surfaces in /proc enumeration, and the
            // probe classifies it. Probing is scoped to this test's own port —
            // a full host scan would consume accepts of concurrent tests'
            // listeners and flake them.
            assert!(loopback_listen_ports().contains(&(addr, port)));
            let found = probe_targets(vec![(addr, port)]).await;
            assert_eq!(
                found,
                vec![LocalProxy {
                    address: addr,
                    port,
                    kind: ProxyKind::Socks5
                }]
            );
        }
    }
}
