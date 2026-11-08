use net_manager_core::daemon_protocol::{
    self, method, ErrorBody, ErrorCode, HelloParams, HelloResult, RequestFrame, ResponseFrame,
    DEFAULT_SOCKET_PATH, MAX_FRAME_BYTES, PROTOCOL_VERSION, SOCKET_ENV,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt;
use std::io;
use std::path::PathBuf;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Debug)]
pub(crate) enum ClientError {
    Transport(io::Error),
    Daemon(ErrorBody),
    Protocol(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(err) => write!(f, "daemon connection failed: {err}"),
            Self::Daemon(err) => write!(f, "{}", err.message),
            Self::Protocol(message) => write!(f, "daemon protocol error: {message}"),
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(err: io::Error) -> Self {
        Self::Transport(err)
    }
}

pub(crate) fn user_message(err: &ClientError) -> String {
    match err {
        ClientError::Daemon(ErrorBody { code: ErrorCode::NotAuthorized, .. }) =>
            "Authorization was denied by polkit. Check that a polkit authentication agent is running.".into(),
        ClientError::Daemon(ErrorBody { code: ErrorCode::AuthorizationDismissed, .. }) =>
            "The polkit authorization dialog was dismissed.".into(),
        _ => err.to_string(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DaemonClient {
    path: PathBuf,
}

impl DaemonClient {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn system() -> Self {
        Self::new(
            std::env::var_os(SOCKET_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|| DEFAULT_SOCKET_PATH.into()),
        )
    }

    /// GUI scheduling only: connection policy and protocol handling are the
    /// same LinuxEngine operations used by netorch.
    pub(crate) async fn engine_request<R: Send + 'static>(
        &self,
        operation: impl FnOnce(net_manager_engine::linux_engine::LinuxEngine) -> Result<R, String>
            + Send
            + 'static,
    ) -> Result<R, String> {
        self.engine_request_with_timeout(std::time::Duration::from_secs(330), operation)
            .await
    }

    pub(crate) async fn engine_observation<R: Send + 'static>(
        &self,
        operation: impl FnOnce(net_manager_engine::linux_engine::LinuxEngine) -> Result<R, String>
            + Send
            + 'static,
    ) -> Result<R, String> {
        self.engine_request_with_timeout(std::time::Duration::from_secs(2), operation)
            .await
    }

    async fn engine_request_with_timeout<R: Send + 'static>(
        &self,
        timeout: std::time::Duration,
        operation: impl FnOnce(net_manager_engine::linux_engine::LinuxEngine) -> Result<R, String>
            + Send
            + 'static,
    ) -> Result<R, String> {
        let engine = net_manager_engine::linux_engine::LinuxEngine::for_socket_with_timeout(
            self.path.clone(),
            format!("net-manager-app/{}", env!("NETORCH_VERSION")),
            timeout,
        );
        tauri::async_runtime::spawn_blocking(move || operation(engine))
            .await
            .map_err(|_| "Network operation worker failed".to_string())?
    }

    async fn exchange<P: Serialize, R: DeserializeOwned>(
        &self,
        method_name: &str,
        params: P,
    ) -> Result<R, ClientError> {
        let stream = UnixStream::connect(&self.path).await?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let hello = RequestFrame {
            id: 1,
            method: method::HELLO.into(),
            params: serde_json::to_value(HelloParams {
                protocol: PROTOCOL_VERSION,
                client: format!("net-manager-app/{}", env!("NETORCH_VERSION")),
            })
            .map_err(|e| ClientError::Protocol(e.to_string()))?,
        };
        writer
            .write_all(&daemon_protocol::encode_line(&hello)?)
            .await?;
        let hello: HelloResult = read_response(&mut reader, 1, method::HELLO).await?;
        if hello.protocol != PROTOCOL_VERSION {
            return Err(ClientError::Protocol(format!(
                "expected protocol {PROTOCOL_VERSION}, daemon speaks {}",
                hello.protocol
            )));
        }
        let request = RequestFrame {
            id: 2,
            method: method_name.into(),
            params: serde_json::to_value(params)
                .map_err(|e| ClientError::Protocol(e.to_string()))?,
        };
        writer
            .write_all(&daemon_protocol::encode_line(&request)?)
            .await?;
        read_response(&mut reader, 2, method_name).await
    }

    pub(crate) async fn request<P: Serialize, R: DeserializeOwned>(
        &self,
        method_name: &str,
        params: P,
    ) -> Result<R, ClientError> {
        self.exchange(method_name, params).await
    }
}

async fn read_response<R: tokio::io::AsyncBufRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
    id: u64,
    method_name: &str,
) -> Result<T, ClientError> {
    let frame = daemon_protocol::read_frame(reader, MAX_FRAME_BYTES);
    let line = if let Some(timeout) = response_timeout(method_name) {
        tokio::time::timeout(timeout, frame)
            .await
            .map_err(|_| ClientError::Protocol("daemon response timed out".into()))??
    } else {
        frame.await?
    }
    .ok_or_else(|| ClientError::Protocol("daemon closed connection".into()))?;
    let frame: ResponseFrame =
        serde_json::from_slice(&line).map_err(|e| ClientError::Protocol(e.to_string()))?;
    if frame.id != id {
        // Early-error frames (busy, frameTooLarge, malformed hello) carry
        // id 0 regardless of the request; surface their real message
        // instead of a misleading "id mismatch".
        return match frame.outcome {
            Err(err) => Err(ClientError::Daemon(err)),
            Ok(_) => Err(ClientError::Protocol("response id mismatch".into())),
        };
    }
    let value = frame.outcome.map_err(ClientError::Daemon)?;
    daemon_protocol::from_value(value).map_err(|e| ClientError::Protocol(e.to_string()))
}

fn response_timeout(method_name: &str) -> Option<std::time::Duration> {
    // Generous but finite: a wedged daemon must not pin a socket (and its
    // server-side connection permit) forever. Polkit prompts can block a
    // request for as long as the user takes to answer, so the bound sits
    // just above the daemon's own 300s dispatch timeout.
    let secs = if method_name == method::HELLO { 5 } else { 330 };
    Some(std::time::Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{method, ErrorCode, RequestFrame, ResponseFrame};
    use serde_json::{json, Value};
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn client_performs_hello_then_request() {
        let dir = crate::test_support::unique_dir("daemon-client");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let hello: RequestFrame = serde_json::from_slice(
                &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(hello.method, method::HELLO);
            writer
                .write_all(
                    &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                        hello.id,
                        json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
            let request: RequestFrame = serde_json::from_slice(
                &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(request.method, method::OWNED_LIST);
            writer
                .write_all(
                    &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                        request.id,
                        json!({"owners":[]}),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
        });
        let result: net_manager_core::daemon_protocol::OwnedListResult =
            DaemonClient::new(path.clone())
                .request(method::OWNED_LIST, json!(null))
                .await
                .unwrap();
        assert!(result.owners.is_empty());
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn not_authorized_message_mentions_polkit() {
        let message = user_message(&ClientError::Daemon(
            net_manager_core::daemon_protocol::ErrorBody {
                code: ErrorCode::NotAuthorized,
                message: "denied".into(),
            },
        ));
        assert!(message.contains("polkit"));
    }

    #[test]
    fn every_method_has_a_response_deadline() {
        assert_eq!(
            response_timeout(method::HELLO),
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(
            response_timeout(method::ROUTES_APPLY),
            Some(std::time::Duration::from_secs(330))
        );
        assert_eq!(
            response_timeout(method::LINK_SET_STATE),
            Some(std::time::Duration::from_secs(330))
        );
    }

    /// Early-error frames carry id 0 regardless of the request id; the
    /// client must surface their real error instead of "id mismatch".
    #[tokio::test]
    async fn busy_frame_surfaces_daemon_error() {
        let dir = crate::test_support::unique_dir("daemon-client-busy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let _hello = net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                .await
                .unwrap()
                .unwrap();
            writer
                .write_all(
                    &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::error(
                        0,
                        ErrorCode::Busy,
                        "too many connections",
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
        });
        let err = DaemonClient::new(path.clone())
            .request::<_, Value>(method::OWNED_LIST, Value::Null)
            .await
            .unwrap_err();
        match err {
            ClientError::Daemon(body) => {
                assert_eq!(body.code, ErrorCode::Busy);
                assert!(body.message.contains("too many connections"));
            }
            other => panic!("expected daemon error, got {other:?}"),
        }
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn daemon_error_codes_round_trip() {
        let dir = crate::test_support::unique_dir("daemon-error");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let hello: RequestFrame = serde_json::from_slice(
                &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            writer
                .write_all(
                    &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                        hello.id,
                        json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
            let request: RequestFrame = serde_json::from_slice(
                &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            writer
                .write_all(
                    &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::error(
                        request.id,
                        ErrorCode::NotAuthorized,
                        "denied",
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
        });
        let err = DaemonClient::new(path)
            .request::<_, serde_json::Value>(method::ROUTES_REMOVE, json!({"owner":"p1"}))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ClientError::Daemon(net_manager_core::daemon_protocol::ErrorBody {
                code: ErrorCode::NotAuthorized,
                ..
            })
        ));
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
