//! QUIC transport layer using the `quinn` crate with self-signed TLS certificates.
//!
//! Provides the core networking abstraction for Shunkan P2P communication.
//! Uses QUIC over UDP (port 4433 by default per ADR-001) with self-signed
//! TLS 1.3 certificates generated via `rcgen`.
//!
//! QUIC provides:
//! - 0-RTT/1-RTT connection setup
//! - Independent stream multiplexing (clipboard text on one stream,
//!   file chunks on another — no head-of-line blocking)
//! - Built-in TLS 1.3 encryption

use crate::crypto;
use crate::protocol::Message;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Configuration for the QUIC transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// The local address to bind to.
    pub bind_addr: SocketAddr,
    /// Keep-alive interval in milliseconds (0 to disable).
    pub keep_alive_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], crate::DEFAULT_PORT)),
            keep_alive_ms: 5000,
        }
    }
}

/// A QUIC transport server that listens for incoming connections.
pub struct TransportServer {
    endpoint: quinn::Endpoint,
    _config: TransportConfig,
}

impl TransportServer {
    /// Create and start a new QUIC transport server.
    ///
    /// Generates self-signed TLS certificates and binds to the configured address.
    pub async fn start(config: TransportConfig) -> Result<Self> {
        let (server_tls_config, _client_tls_config) = crypto::generate_quinn_configs()
            .context("Failed to generate TLS configs for transport")?;

        let endpoint = quinn::Endpoint::server(server_tls_config, config.bind_addr)
            .context("Failed to bind QUIC endpoint")?;

        log::info!("QUIC server listening on {}", config.bind_addr);

        Ok(Self {
            endpoint,
            _config: config,
        })
    }

    /// Accept incoming QUIC connections and handle them.
    ///
    /// Returns a channel receiver that yields (connection, sender) pairs.
    /// Each connection gets its own message channel.
    pub async fn accept(&self) -> Result<Option<TransportConnection>> {
        if let Some(incoming) = self.endpoint.accept().await {
            let connection = incoming
                .await
                .context("Failed to accept incoming QUIC connection")?;

            let remote_addr = connection.remote_address();
            log::info!("Accepted connection from {}", remote_addr);

            Ok(Some(TransportConnection { connection }))
        } else {
            Ok(None)
        }
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("Failed to get local address")
    }

    /// Shut down the transport server gracefully.
    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"server shutting down");
        log::info!("QUIC server shut down");
    }
}

/// A QUIC transport client for connecting to peers.
pub struct TransportClient {
    endpoint: quinn::Endpoint,
}

impl TransportClient {
    /// Create a new transport client.
    pub fn new() -> Result<Self> {
        let (_server_tls_config, client_tls_config) = crypto::generate_quinn_configs()
            .context("Failed to generate TLS configs for client")?;

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .context("Failed to create client endpoint")?;

        endpoint.set_default_client_config(client_tls_config);

        Ok(Self { endpoint })
    }

    /// Connect to a remote peer.
    pub async fn connect(&self, addr: SocketAddr) -> Result<TransportConnection> {
        let connection = self
            .endpoint
            .connect(addr, "localhost")
            .context("Failed to initiate QUIC connection")?
            .await
            .context("Failed to establish QUIC connection")?;

        log::info!("Connected to {}", addr);

        Ok(TransportConnection { connection })
    }

    /// Shut down the client endpoint.
    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"client shutting down");
    }
}

/// An established QUIC connection to a peer.
pub struct TransportConnection {
    connection: quinn::Connection,
}

impl TransportConnection {
    /// Get the remote address of the connected peer.
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Send a protocol message over a new unidirectional stream.
    pub async fn send_message(&self, msg: &Message) -> Result<()> {
        let mut send = self
            .connection
            .open_uni()
            .await
            .context("Failed to open unidirectional stream")?;

        let framed = msg.to_framed_bytes()?;
        send.write_all(&framed)
            .await
            .context("Failed to write message to stream")?;
        send.finish()
            .context("Failed to finish stream")?;

        Ok(())
    }

    /// Receive a protocol message from an incoming unidirectional stream.
    pub async fn recv_message(&self) -> Result<Message> {
        let mut recv = self
            .connection
            .accept_uni()
            .await
            .context("Failed to accept unidirectional stream")?;

        // Read the 4-byte length prefix
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .context("Failed to read message length")?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Guard against unreasonably large messages (16 MiB max)
        anyhow::ensure!(len <= 16 * 1024 * 1024, "Message too large: {} bytes", len);

        // Read the message body
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf)
            .await
            .context("Failed to read message body")?;

        Message::from_bytes(&buf)
    }

    /// Open a bidirectional stream for interactive communication.
    pub async fn open_bi_stream(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .context("Failed to open bidirectional stream")?;
        Ok((send, recv))
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi_stream(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .context("Failed to accept bidirectional stream")?;
        Ok((send, recv))
    }

    /// Close the connection gracefully.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"connection closed");
    }
}

/// Send a framed message over a QUIC send stream.
pub async fn send_framed(send: &mut quinn::SendStream, msg: &Message) -> Result<()> {
    let framed = msg.to_framed_bytes()?;
    send.write_all(&framed)
        .await
        .context("Failed to write framed message")?;
    Ok(())
}

/// Receive a framed message from a QUIC receive stream.
pub async fn recv_framed(recv: &mut quinn::RecvStream) -> Result<Message> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("Failed to read frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    anyhow::ensure!(len <= 16 * 1024 * 1024, "Frame too large: {} bytes", len);

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .context("Failed to read frame body")?;

    Message::from_bytes(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.bind_addr.port(), crate::DEFAULT_PORT);
        assert_eq!(config.keep_alive_ms, 5000);
    }

    #[test]
    fn test_transport_config_custom() {
        let config = TransportConfig {
            bind_addr: "127.0.0.1:5555".parse().unwrap(),
            keep_alive_ms: 10000,
        };
        assert_eq!(config.bind_addr.port(), 5555);
    }

    #[tokio::test]
    async fn test_server_start_and_addr() {
        let config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(), // OS-assigned port
            keep_alive_ms: 5000,
        };
        let server = TransportServer::start(config).await.unwrap();
        let addr = server.local_addr().unwrap();
        assert!(addr.port() > 0);
        server.shutdown();
    }

    #[tokio::test]
    async fn test_client_creation() {
        let client = TransportClient::new();
        assert!(client.is_ok());
        if let Ok(c) = client {
            c.shutdown();
        }
    }

    #[tokio::test]
    async fn test_client_server_roundtrip() {
        // Start server on a random port
        let server_config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            keep_alive_ms: 5000,
        };
        let server = TransportServer::start(server_config).await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // We need matching certs for client and server to talk.
        // Since they use independent self-signed certs, we need a custom setup.
        // For this test, we generate shared configs.
        let (server_tls, client_tls) = crypto::generate_quinn_configs().unwrap();

        // Rebuild server with the shared config
        server.shutdown();
        let endpoint_server = quinn::Endpoint::server(
            server_tls,
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let actual_addr = endpoint_server.local_addr().unwrap();

        // Spawn server accept task
        let server_handle = tokio::spawn(async move {
            if let Some(incoming) = endpoint_server.accept().await {
                let conn = incoming.await.unwrap();
                let transport_conn = TransportConnection { connection: conn };
                let msg = transport_conn.recv_message().await.unwrap();
                transport_conn.close();
                endpoint_server.close(0u32.into(), b"done");
                msg
            } else {
                panic!("No incoming connection");
            }
        });

        // Client connects
        let mut client_endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_tls);

        let conn = client_endpoint
            .connect(actual_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let client_conn = TransportConnection { connection: conn };

        // Send a message
        let ping = Message::Ping { timestamp: 42 };
        client_conn.send_message(&ping).await.unwrap();

        // Verify server received it before shutting down client endpoint
        let received = server_handle.await.unwrap();
        assert_eq!(received, ping);

        client_conn.close();
        client_endpoint.close(0u32.into(), b"done");
    }
}
