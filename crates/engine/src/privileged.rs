//! Where root work is done. The engine asks; something else mutates routes,
//! interfaces and DNS. On macOS that is the launchd helper over its socket
//! ([`HelperClient`]) or, for `sudo netorch`, executors running in the CLI's
//! own process (implemented in the CLI crate, which links the helper library).
//! Both speak `daemon_protocol` frames, so the engine is the same either way.
use net_manager_core::daemon_protocol::HelloResult;
use net_manager_core::helper_client::{require_capability, HelperClient, HelperError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;

pub trait Privileged: Send + Sync {
    /// Handshake: proves the privileged side answers and accepts this process,
    /// and lists the methods it implements.
    fn hello(&self) -> Result<HelloResult, HelperError>;
    /// One `daemon_protocol` request.
    fn call_raw(&self, method: &str, params: Value) -> Result<Value, HelperError>;
    /// Require handshake metadata before mutation. Socket adapters override this
    /// to check the same connection that sends the request.
    fn call_raw_with_capability(
        &self,
        method: &str,
        params: Value,
        capability: &str,
    ) -> Result<Value, HelperError> {
        require_capability(&self.hello()?, capability)?;
        self.call_raw(method, params)
    }
    /// Whether the engine may run the user's managed Xray to check a config
    /// before handing it over. False when this process is root itself: it
    /// must not execute a binary from a user-writable directory.
    fn validates_locally(&self) -> bool {
        true
    }
    /// Directory where the privileged side keeps the tunnels' logs
    /// (`xray-tun.log`, `openvpn.log`).
    fn log_dir(&self) -> PathBuf;
}

impl dyn Privileged + '_ {
    /// Typed request: params are encoded and the result decoded.
    pub fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, HelperError> {
        let params = serde_json::to_value(params)
            .map_err(|error| HelperError::Protocol(error.to_string()))?;
        let value = self.call_raw(method, params)?;
        serde_json::from_value(value).map_err(|error| HelperError::Protocol(error.to_string()))
    }

    /// Typed request gated by an explicit privileged-side promise.
    pub fn call_with_capability<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
        capability: &str,
    ) -> Result<R, HelperError> {
        let params = serde_json::to_value(params)
            .map_err(|error| HelperError::Protocol(error.to_string()))?;
        let value = self.call_raw_with_capability(method, params, capability)?;
        serde_json::from_value(value).map_err(|error| HelperError::Protocol(error.to_string()))
    }
}

impl Privileged for HelperClient {
    fn hello(&self) -> Result<HelloResult, HelperError> {
        HelperClient::hello(self)
    }

    fn call_raw(&self, method: &str, params: Value) -> Result<Value, HelperError> {
        HelperClient::call(self, method, params)
    }

    fn call_raw_with_capability(
        &self,
        method: &str,
        params: Value,
        capability: &str,
    ) -> Result<Value, HelperError> {
        HelperClient::call_with_capability(self, method, params, capability)
    }

    fn log_dir(&self) -> PathBuf {
        self.socket()
            .parent()
            .map(PathBuf::from)
            .unwrap_or_default()
    }
}
