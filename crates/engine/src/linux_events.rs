//! Bounded, read-only daemon event subscription.
use net_manager_core::daemon_protocol::{
    encode_line, method, EventFrame, HelloParams, HelloResult, RequestFrame, ResponseFrame,
    PROTOCOL_VERSION,
};
use serde_json::Value;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_EVENT_FRAME: usize = 1024 * 1024;

#[derive(Debug)]
pub enum EventError {
    Unavailable,
    Unsupported,
    Incompatible,
    Protocol,
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "Daemon event connection unavailable",
            Self::Unsupported => "Daemon does not support event subscriptions",
            Self::Incompatible => "Daemon event protocol version is incompatible",
            Self::Protocol => "Invalid daemon event protocol",
        })
    }
}

impl std::error::Error for EventError {}

pub struct Subscription {
    stream: UnixStream,
    buffer: Vec<u8>,
    queued: VecDeque<EventFrame>,
    timeout: Duration,
}

impl Subscription {
    pub fn connect(path: &Path, timeout: Duration) -> Result<Self, EventError> {
        let stream = UnixStream::connect(path).map_err(|_| EventError::Unavailable)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| EventError::Unavailable)?;
        let mut sub = Self {
            stream,
            buffer: Vec::new(),
            queued: VecDeque::new(),
            timeout,
        };
        let deadline = Instant::now() + timeout;
        sub.send(
            1,
            method::HELLO,
            serde_json::to_value(HelloParams {
                protocol: PROTOCOL_VERSION,
                client: "netorch-observer".into(),
            })
            .map_err(|_| EventError::Protocol)?,
        )?;
        let response = sub.response(1, deadline, false)?;
        let hello: HelloResult =
            serde_json::from_value(response).map_err(|_| EventError::Protocol)?;
        if hello.protocol != PROTOCOL_VERSION {
            return Err(EventError::Incompatible);
        }
        if !hello.capabilities.iter().any(|c| c == method::SUBSCRIBE) {
            return Err(EventError::Unsupported);
        }
        sub.send(2, method::SUBSCRIBE, Value::Null)?;
        sub.response(2, deadline, true)?;
        Ok(sub)
    }

    fn send(&mut self, id: u64, method: &str, params: Value) -> Result<(), EventError> {
        let frame = RequestFrame {
            id,
            method: method.into(),
            params,
        };
        let bytes = encode_line(&frame).map_err(|_| EventError::Protocol)?;
        self.stream
            .write_all(&bytes)
            .map_err(|_| EventError::Unavailable)
    }

    fn response(&mut self, id: u64, deadline: Instant, events: bool) -> Result<Value, EventError> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(EventError::Unavailable)?;
            let value = self.read_frame(remaining)?.ok_or(EventError::Unavailable)?;
            if events && value.get("event").is_some() {
                let event = serde_json::from_value(value).map_err(|_| EventError::Protocol)?;
                if self.queued.len() >= 1024 {
                    return Err(EventError::Protocol);
                }
                self.queued.push_back(event);
                continue;
            }
            let response: ResponseFrame =
                serde_json::from_value(value).map_err(|_| EventError::Protocol)?;
            if response.id != id {
                return Err(EventError::Protocol);
            }
            return response.outcome.map_err(|_| EventError::Protocol);
        }
    }

    fn read_frame(&mut self, timeout: Duration) -> Result<Option<Value>, EventError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(end) = self.buffer.iter().position(|b| *b == b'\n') {
                let frame = serde_json::from_slice(&self.buffer[..=end])
                    .map(Some)
                    .map_err(|_| EventError::Protocol);
                drop(self.buffer.drain(..=end));
                return frame;
            }
            if self.buffer.len() >= MAX_EVENT_FRAME {
                return Err(EventError::Protocol);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| EventError::Unavailable)?;
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(EventError::Unavailable),
                Ok(n) => {
                    self.buffer.extend_from_slice(&chunk[..n]);
                    if self
                        .buffer
                        .iter()
                        .position(|b| *b == b'\n')
                        .unwrap_or(self.buffer.len())
                        >= MAX_EVENT_FRAME
                    {
                        return Err(EventError::Protocol);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None)
                }
                Err(_) => return Err(EventError::Unavailable),
            }
        }
    }

    /// Returns None on a timeout, preserving partial frame bytes for the next call.
    pub fn next_event(&mut self) -> Result<Option<EventFrame>, EventError> {
        if let Some(event) = self.queued.pop_front() {
            return Ok(Some(event));
        }
        self.read_frame(self.timeout)?
            .map(|value| serde_json::from_value(value).map_err(|_| EventError::Protocol))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn server(
        reply: Vec<u8>,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        thread::JoinHandle<()>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            socket.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"test\",\"uid\":1000,\"capabilities\":[\"subscribe\"]}}\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            socket
                .write_all(b"{\"id\":2,\"ok\":true,\"result\":null}\n")
                .unwrap();
            let _ = socket.write_all(&reply);
        });
        (dir, path, handle)
    }

    #[test]
    fn receives_resync_event() {
        let (_dir, path, server) = server(b"{\"event\":\"resync\"}\n".to_vec());
        let mut sub = Subscription::connect(&path, Duration::from_secs(1)).unwrap();
        assert_eq!(sub.next_event().unwrap().unwrap().event, "resync");
        server.join().unwrap();
    }

    #[test]
    fn timeout_preserves_partial_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            socket.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"test\",\"uid\":1000,\"capabilities\":[\"subscribe\"]}}\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            socket
                .write_all(b"{\"id\":2,\"ok\":true,\"result\":null}\n{\"event\":")
                .unwrap();
            thread::sleep(Duration::from_millis(150));
            socket.write_all(b"\"resync\"}\n").unwrap();
        });
        let mut sub = Subscription::connect(&path, Duration::from_millis(50)).unwrap();
        assert!(sub.next_event().unwrap().is_none());
        thread::sleep(Duration::from_millis(150));
        assert_eq!(sub.next_event().unwrap().unwrap().event, "resync");
        server.join().unwrap();
    }

    #[test]
    fn event_before_subscribe_response_is_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            socket.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":1,\"daemonVersion\":\"test\",\"uid\":1000,\"capabilities\":[\"subscribe\"]}}\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            socket
                .write_all(b"{\"event\":\"resync\"}\n{\"id\":2,\"ok\":true,\"result\":null}\n")
                .unwrap();
        });
        let mut sub = Subscription::connect(&path, Duration::from_secs(1)).unwrap();
        assert_eq!(sub.next_event().unwrap().unwrap().event, "resync");
        server.join().unwrap();
    }

    #[test]
    fn reports_incompatible_protocol_separately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            socket.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"protocol\":999,\"daemonVersion\":\"test\",\"uid\":1000,\"capabilities\":[\"subscribe\"]}}\n").unwrap();
        });
        assert!(matches!(
            Subscription::connect(&path, Duration::from_secs(1)),
            Err(EventError::Incompatible)
        ));
        server.join().unwrap();
    }

    #[test]
    fn rejects_malformed_and_oversized_events_without_echoing_input() {
        for frame in [
            b"not json secret\n".to_vec(),
            vec![b'x'; MAX_EVENT_FRAME + 1],
        ] {
            let (_dir, path, server) = server(frame);
            let mut sub = Subscription::connect(&path, Duration::from_secs(1)).unwrap();
            let message = sub.next_event().unwrap_err().to_string();
            assert!(!message.contains("secret"));
            server.join().unwrap();
        }
    }
}
