//! Blocking client for the privileged helper's `daemon_protocol` socket.
//! One short-lived connection per call: `hello`, the request, close.

use crate::daemon_protocol::{
    encode_line, method, ErrorBody, ErrorCode, HelloParams, HelloResult, RequestFrame,
    ResponseFrame, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug)]
pub enum HelperError {
    /// The socket is missing or refused the connection: the helper is not
    /// installed, not approved or not running.
    Unreachable(io::Error),
    /// The helper answered with an error.
    Rejected(ErrorBody),
    Protocol(String),
}

impl fmt::Display for HelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(_) => f.write_str("The privileged helper is not running"),
            Self::Rejected(body) => f.write_str(&body.message),
            Self::Protocol(message) => write!(f, "helper protocol error: {message}"),
        }
    }
}

impl std::error::Error for HelperError {}

pub struct HelperClient {
    socket: PathBuf,
    timeout: Duration,
    /// Sent in the handshake; the daemon logs it, never trusts it.
    client_name: String,
}

impl HelperClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: Duration::from_secs(10),
            client_name: format!("net-manager-macos/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// Names this client in the handshake (`netorch/0.9.0`).
    pub fn with_client_name(mut self, name: impl Into<String>) -> Self {
        self.client_name = name.into();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    fn connect(&self) -> Result<UnixStream, HelperError> {
        let stream = UnixStream::connect(&self.socket).map_err(HelperError::Unreachable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(HelperError::Unreachable)?;
        Ok(stream)
    }

    /// Handshake only: proves the helper answers and accepts this process.
    pub fn hello(&self) -> Result<HelloResult, HelperError> {
        let mut stream = self.connect()?;
        let mut reader = BufReader::new(stream.try_clone().map_err(HelperError::Unreachable)?);
        handshake(&mut stream, &mut reader, &self.client_name)
    }

    /// Handshake, then one request.
    pub fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method_name: &str,
        params: P,
    ) -> Result<R, HelperError> {
        self.call_requiring_capability(method_name, params, None)
    }

    /// Require a promise from this connection's hello before sending a request.
    pub fn call_with_capability<P: Serialize, R: DeserializeOwned>(
        &self,
        method_name: &str,
        params: P,
        capability: &str,
    ) -> Result<R, HelperError> {
        self.call_requiring_capability(method_name, params, Some(capability))
    }

    fn call_requiring_capability<P: Serialize, R: DeserializeOwned>(
        &self,
        method_name: &str,
        params: P,
        capability: Option<&str>,
    ) -> Result<R, HelperError> {
        let mut stream = self.connect()?;
        let mut reader = BufReader::new(stream.try_clone().map_err(HelperError::Unreachable)?);
        let hello = handshake(&mut stream, &mut reader, &self.client_name)?;
        if let Some(capability) = capability {
            require_capability(&hello, capability)?;
        }
        let params =
            serde_json::to_value(params).map_err(|err| HelperError::Protocol(err.to_string()))?;
        let request = RequestFrame {
            id: 2,
            method: method_name.into(),
            params,
        };
        send(&mut stream, &request)?;
        let response = receive(&mut reader)?;
        decode(response)
    }
}

/// Shared check for socket and injected privileged adapters.
pub fn require_capability(hello: &HelloResult, capability: &str) -> Result<(), HelperError> {
    if hello.capabilities.iter().any(|entry| entry == capability) {
        Ok(())
    } else {
        Err(HelperError::Protocol(format!(
            "The network daemon does not advertise {capability}. Update and restart network-orchestrator before retrying; IPv6 routes and DNS will not fall back to IPv4."
        )))
    }
}

fn handshake(
    stream: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    client: &str,
) -> Result<HelloResult, HelperError> {
    let hello = RequestFrame {
        id: 1,
        method: method::HELLO.into(),
        params: serde_json::to_value(HelloParams {
            protocol: PROTOCOL_VERSION,
            client: client.to_string(),
        })
        .map_err(|err| HelperError::Protocol(err.to_string()))?,
    };
    send(stream, &hello)?;
    decode(receive(reader)?)
}

fn send(stream: &mut UnixStream, request: &RequestFrame) -> Result<(), HelperError> {
    let line = encode_line(request).map_err(|err| HelperError::Protocol(err.to_string()))?;
    stream
        .write_all(&line)
        .and_then(|_| stream.flush())
        .map_err(HelperError::Unreachable)
}

fn receive(reader: &mut BufReader<UnixStream>) -> Result<ResponseFrame, HelperError> {
    let mut line = Vec::new();
    let read = reader
        .by_ref()
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(HelperError::Unreachable)?;
    if read == 0 || line.last() != Some(&b'\n') {
        return Err(HelperError::Protocol(
            "the helper closed the connection".into(),
        ));
    }
    serde_json::from_slice(&line).map_err(|err| HelperError::Protocol(err.to_string()))
}

fn decode<R: DeserializeOwned>(response: ResponseFrame) -> Result<R, HelperError> {
    match response.outcome {
        Ok(value) => {
            serde_json::from_value(value).map_err(|err| HelperError::Protocol(err.to_string()))
        }
        Err(body) => Err(HelperError::Rejected(body)),
    }
}

/// Whether an error means "not authorized" rather than "not there".
pub fn is_denied(error: &HelperError) -> bool {
    matches!(error, HelperError::Rejected(body) if body.code == ErrorCode::NotAuthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_protocol::HelloResult;
    use serde_json::json;
    use std::os::unix::net::UnixListener;

    fn serve_once(
        listener: UnixListener,
        reply: impl FnOnce(RequestFrame) -> ResponseFrame + Send + 'static,
    ) {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let hello: RequestFrame = serde_json::from_str(&line).unwrap();
            let result = HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: "9".into(),
                uid: 501,
                capabilities: vec!["owned.list".into()],
                tools: Default::default(),
            };
            let ok = ResponseFrame::ok(hello.id, serde_json::to_value(result).unwrap());
            stream.write_all(&encode_line(&ok).unwrap()).unwrap();
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() > 0 {
                let request: RequestFrame = serde_json::from_str(&line).unwrap();
                stream
                    .write_all(&encode_line(&reply(request)).unwrap())
                    .unwrap();
            }
        });
    }

    #[test]
    fn hello_reports_the_helper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.sock");
        serve_once(UnixListener::bind(&path).unwrap(), |_| unreachable!());
        let hello = HelperClient::new(&path).hello().unwrap();
        assert_eq!(hello.daemon_version, "9");
        assert_eq!(hello.capabilities, ["owned.list"]);
    }

    #[test]
    fn call_returns_typed_results_and_typed_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.sock");
        serve_once(UnixListener::bind(&path).unwrap(), |request| {
            ResponseFrame::ok(request.id, json!({"owners": []}))
        });
        let value: serde_json::Value = HelperClient::new(&path).call("owned.list", ()).unwrap();
        assert_eq!(value["owners"], json!([]));

        let path = dir.path().join("e.sock");
        serve_once(UnixListener::bind(&path).unwrap(), |request| {
            ResponseFrame::error(request.id, ErrorCode::NotAuthorized, "no")
        });
        let error = HelperClient::new(&path)
            .call::<_, serde_json::Value>("x", ())
            .unwrap_err();
        assert!(is_denied(&error));
    }

    #[test]
    fn required_capability_is_checked_on_the_request_connection_before_sending() {
        for advertised in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("h.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request: RequestFrame = serde_json::from_str(&line).unwrap();
                assert_eq!(request.method, method::HELLO);
                let capabilities = if advertised {
                    vec![crate::daemon_protocol::feature::XRAY_TUN_IPV6]
                } else {
                    vec![method::XRAY_CONNECT]
                };
                let hello = ResponseFrame::ok(
                    request.id,
                    json!({
                        "protocol": PROTOCOL_VERSION, "daemonVersion": "legacy", "uid": 1000,
                        "capabilities": capabilities
                    }),
                );
                stream.write_all(&encode_line(&hello).unwrap()).unwrap();
                line.clear();
                let read = reader.read_line(&mut line).unwrap();
                if !advertised {
                    assert_eq!(read, 0, "unsupported daemon must receive no mutation");
                    return;
                }
                let request: RequestFrame = serde_json::from_str(&line).unwrap();
                assert_eq!(request.method, method::XRAY_CONNECT);
                assert_eq!(request.params, json!({"routes": ["::/0"]}));
                let response = ResponseFrame::ok(request.id, json!({"sent": true}));
                stream.write_all(&encode_line(&response).unwrap()).unwrap();
            });
            let result: Result<serde_json::Value, _> = HelperClient::new(&path)
                .call_with_capability(
                    method::XRAY_CONNECT,
                    json!({"routes": ["::/0"]}),
                    crate::daemon_protocol::feature::XRAY_TUN_IPV6,
                );
            if advertised {
                assert_eq!(result.unwrap(), json!({"sent": true}));
            } else {
                let message = result.unwrap_err().to_string();
                assert!(message.contains("xray.tun.ipv6"));
                assert!(message.contains("Update"));
                assert!(message.contains("restart"));
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn a_missing_socket_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let error = HelperClient::new(dir.path().join("none.sock"))
            .hello()
            .unwrap_err();
        assert!(matches!(error, HelperError::Unreachable(_)));
    }
}
