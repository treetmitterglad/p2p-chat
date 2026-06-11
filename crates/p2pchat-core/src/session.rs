use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::crypto;
use crate::crypto::HandshakeRole;
use crate::message::WireMessage;
use crate::ratchet::Ratchet;
use crate::transport::{Ticket, Transport};
use crate::{identity, storage};

/// Events emitted by the session to the UI layer.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// Successfully connected to peer.
    Connected {
        /// 32-byte node ID of the remote peer.
        peer_id: [u8; 32],
        /// Human-readable fingerprint (first 16 bytes of SHA-256 of peer's public key).
        fingerprint: String,
    },
    /// Received a text message.
    MessageReceived {
        /// Decrypted plaintext message body.
        text: String,
        /// Wall-clock timestamp when the message was received.
        timestamp: chrono::DateTime<Utc>,
    },
    /// Session closed cleanly.
    Disconnected,
    /// Error occurred.
    Error(String),
}

/// Handle to an active chat session.
#[derive(Debug)]
pub struct SessionHandle {
    /// Send a text message to the peer.
    pub send_tx: mpsc::Sender<String>,
    /// Receive session events.
    pub recv_rx: mpsc::Receiver<SessionEvent>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Peer node id.
    pub peer_id: [u8; 32],
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

impl SessionHandle {
    /// Hex-encoded peer id.
    pub fn peer_id_hex(&self) -> String {
        hex::encode(self.peer_id)
    }

    /// Close the session gracefully.
    pub async fn close(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

/// Compute 16-byte fingerprint from a public key.
pub fn fingerprint(pub_key: &[u8; 32]) -> String {
    let hash = sha2::Sha256::digest(pub_key);
    hex::encode(&hash[..16])
}

// ---------------------------------------------------------------------------
// Public constructors
// ---------------------------------------------------------------------------

/// Connect to a peer as initiator.
pub async fn connect_to_peer(
    store: storage::Store,
    identity: identity::Identity,
    ticket_str: &str,
) -> Result<SessionHandle> {
    let transport = Transport::bind()
        .await
        .context("bind transport")?;

    let ticket: Ticket = ticket_str
        .parse()
        .context("parse ticket")?;

    let ticket_addr = ticket.addr();
    eprintln!(
        "connecting to {} via relay {:?} ...",
        ticket_addr.id,
        ticket_addr.relay_urls().next()
    );
    let conn = transport
        .connect(ticket_addr)
        .await
        .context("connect to peer")?;

    let peer_id = *conn.remote_id().as_bytes();
    let (send_stream, recv_stream) = conn.open_bi().await?;

    let mut reader = tokio::io::BufReader::new(recv_stream);
    let mut writer = tokio::io::BufWriter::new(send_stream);

    let result = crypto::perform_handshake(
        HandshakeRole::Initiator,
        &identity.seed(),
        &mut reader,
        &mut writer,
    )
    .await?;

    spawn_session(store, identity, result, peer_id, reader, writer, transport).await
}

/// Listen for an incoming connection as responder.
///
/// Returns our ticket (share with peer) and a [`SessionHandle`] once connected.
pub async fn listen_for_peer(
    store: storage::Store,
    identity: identity::Identity,
) -> Result<(String, SessionHandle)> {
    let transport = Transport::bind()
        .await
        .context("bind transport")?;
    transport.ensure_online().await;

    let ticket = transport.ticket();
    eprintln!("waiting for incoming connection...");
    eprintln!("share this ticket: {ticket}");
    let ticket_str = ticket.to_string();

    let conn = transport
        .accept()
        .await?
        .ok_or_else(|| anyhow!("endpoint closed before accept"))?;

    let peer_id = *conn.remote_id().as_bytes();
    let (send_stream, recv_stream) = conn.accept_bi().await?;

    let mut reader = tokio::io::BufReader::new(recv_stream);
    let mut writer = tokio::io::BufWriter::new(send_stream);

    let result = crypto::perform_handshake(
        HandshakeRole::Responder,
        &identity.seed(),
        &mut reader,
        &mut writer,
    )
    .await?;

    spawn_session(store, identity, result, peer_id, reader, writer, transport)
        .await
        .map(|handle| (ticket_str, handle))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async fn spawn_session<R, W>(
    store: storage::Store,
    identity: identity::Identity,
    handshake: crypto::HandshakeResult,
    peer_id: [u8; 32],
    reader: R,
    writer: W,
    transport: Transport,
) -> Result<SessionHandle>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let peer_static = handshake.peer_static.unwrap_or_default();
    let is_initiator = identity.node_id() < peer_static;

    let ratchet = Ratchet::new(
        &handshake.handshake_hash,
        &identity.seed(),
        &peer_static,
        is_initiator,
    );

    let fp = fingerprint(&peer_static);
    store
        .upsert_contact(&storage::Contact {
            id: uuid::Uuid::new_v4(),
            peer_id,
            label: hex::encode(&peer_id[..4]),
            fingerprint: fp.clone(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            verified: false,
        })
        .await
        .ok();

    let (send_tx, send_rx) = mpsc::channel::<String>(64);
    let (event_tx, recv_rx) = mpsc::channel::<SessionEvent>(64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    event_tx
        .send(SessionEvent::Connected {
            peer_id,
            fingerprint: fp,
        })
        .await
        .ok();

    tokio::spawn(async move {
        run_message_loop(
            reader, writer, store, peer_id, send_rx, event_tx, shutdown_rx, ratchet,
        )
        .await;
        transport.close().await;
    });

    Ok(SessionHandle {
        send_tx,
        recv_rx,
        shutdown_tx: Some(shutdown_tx),
        peer_id,
    })
}

async fn run_message_loop<R, W>(
    reader: R,
    writer: W,
    store: storage::Store,
    peer_id: [u8; 32],
    send_rx: mpsc::Receiver<String>,
    event_tx: mpsc::Sender<SessionEvent>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ratchet: Ratchet,
) where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    // Split into explicit halves so we can pass &mut to each future.
    let mut reader = reader;
    let mut writer = writer;
    let mut send_rx = send_rx;
    let mut shutdown_rx = shutdown_rx;
    let mut ratchet = ratchet;

    loop {
        tokio::select! {
            frame = read_one_frame(&mut reader) => {
                match frame {
                    Ok(data) => {
                        if let Err(e) = handle_incoming(&data, &mut ratchet, &store, peer_id, &event_tx).await {
                            let _ = event_tx.send(SessionEvent::Error(e.to_string())).await;
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = event_tx.send(SessionEvent::Disconnected).await;
                        break;
                    }
                }
            }
            text = send_rx.recv() => {
                let text = match text {
                    Some(t) => t,
                    None => break,
                };
                let encrypted = ratchet.encrypt(text.as_bytes());
                let frame = match encrypted.encode() {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = event_tx.send(SessionEvent::Error(e.to_string())).await;
                        break;
                    }
                };
                if let Err(e) = writer.write_all(&frame).await {
                    let _ = event_tx.send(SessionEvent::Error(e.to_string())).await;
                    break;
                }
                store_message(&store, peer_id, &text, true).await;
            }
            result = shutdown_rx.changed() => {
                let do_break = match result {
                    Ok(()) => *shutdown_rx.borrow_and_update(),
                    Err(_) => true,
                };
                if do_break {
                    break;
                }
            }
        }
    }
    let _ = event_tx.send(SessionEvent::Disconnected).await;
}

async fn read_one_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|e| anyhow!("read frame header: {e}"))?;
    let len = u32::from_le_bytes(header) as usize;
    if len > crate::message::MAX_FRAME_SIZE {
        anyhow::bail!("frame too large: {len} > {}", crate::message::MAX_FRAME_SIZE);
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| anyhow!("read frame payload: {e}"))?;
    Ok(payload)
}

async fn handle_incoming(
    data: &[u8],
    ratchet: &mut Ratchet,
    store: &storage::Store,
    peer_id: [u8; 32],
    event_tx: &mpsc::Sender<SessionEvent>,
) -> Result<()> {
    let wire_msg = WireMessage::decode(data)?;
    let plaintext = ratchet.decrypt(&wire_msg)?;
    let text = String::from_utf8(plaintext)
        .map_err(|_| anyhow!("decrypted message is not valid UTF-8"))?;
    let now = Utc::now();
    store_message(store, peer_id, &text, false).await;
    event_tx
        .send(SessionEvent::MessageReceived {
            text,
            timestamp: now,
        })
        .await
        .ok();
    Ok(())
}

async fn store_message(store: &storage::Store, peer_id: [u8; 32], text: &str, is_outgoing: bool) {
    let _ = store
        .save_message(&storage::Message {
            id: uuid::Uuid::new_v4(),
            peer_id,
            direction: if is_outgoing {
                storage::Direction::Outgoing
            } else {
                storage::Direction::Incoming
            },
            body: text.to_string(),
            is_encrypted: true,
            created_at: Utc::now(),
            read_at: if is_outgoing { Some(Utc::now()) } else { None },
        })
        .await;
}

// ---------------------------------------------------------------------------
// Identity loading convenience
// ---------------------------------------------------------------------------

/// Load identity from disk, prompting for passphrase.
pub async fn load_identity_interactive() -> Result<identity::Identity> {
    let path = crate::config::identity_path();
    if !path.exists() {
        anyhow::bail!("no identity found – run `p2pchat init` first");
    }
    let passphrase = tokio::task::spawn_blocking(|| {
        rpassword::prompt_password("identity passphrase: ")
    })
    .await
    .context("passphrase prompt task")??;
    identity::load_from_path(&passphrase, &path)
        .map_err(|e| anyhow!("load identity: {e}"))
}

/// Load identity from a passphrase string (no prompt).
pub fn load_identity(passphrase: &str) -> Result<identity::Identity> {
    let path = crate::config::identity_path();
    identity::load_from_path(passphrase, &path)
        .map_err(|e| anyhow!("load identity: {e}"))
}

// ---------------------------------------------------------------------------
// CLI chat loop
// ---------------------------------------------------------------------------

/// Run an interactive text-chat loop on stdin/stdout using a session handle.
pub async fn run_cli_chat(mut handle: SessionHandle) -> Result<()> {
    let peer_hex = handle.peer_id_hex();
    println!("connected to: {peer_hex}");
    println!("type /quit to exit");
    println!();

    let (line_tx, mut line_rx) = mpsc::channel::<String>(64);
    let line_tx2 = line_tx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        loop {
            buf.clear();
            use std::io::BufRead;
            let stdin = std::io::stdin();
            let mut locked = stdin.lock();
            match locked.read_line(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    let line = buf.trim().to_string();
                    if line_tx2.blocking_send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            Some(line) = line_rx.recv() => {
                if line == "/quit" {
                    break;
                }
                if !line.is_empty() {
                    handle.send_tx.send(line).await.ok();
                }
            }
            Some(event) = handle.recv_rx.recv() => {
                match event {
                    SessionEvent::Connected { peer_id, fingerprint } => {
                        println!("[connected] peer: {} fp: {}", hex::encode(peer_id), fingerprint);
                    }
                    SessionEvent::MessageReceived { text, timestamp } => {
                        let t = timestamp.format("%H:%M:%S");
                        println!("[{t}] {text}");
                    }
                    SessionEvent::Disconnected => {
                        println!("[disconnected]");
                        break;
                    }
                    SessionEvent::Error(e) => {
                        eprintln!("[error] {e}");
                        break;
                    }
                }
            }
        }
    }

    handle.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_32_hex_chars() {
        let key = [0x42u8; 32];
        let fp = fingerprint(&key);
        assert_eq!(fp.len(), 32);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let key = [0xABu8; 32];
        assert_eq!(fingerprint(&key), fingerprint(&key));
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        let a = fingerprint(&[0x01u8; 32]);
        let b = fingerprint(&[0x02u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_matches_known_value() {
        let key = [0x00u8; 32];
        // SHA-256 of [0; 32] truncated to first 16 bytes
        let hash = sha2::Sha256::digest(&key);
        let expected = hex::encode(&hash[..16]);
        assert_eq!(fingerprint(&key), expected);
    }

    #[test]
    fn session_handle_drop_sends_shutdown() {
        let (send_tx, _recv_rx) = mpsc::channel::<String>(64);
        let (_event_tx, recv_rx) = mpsc::channel::<SessionEvent>(64);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        {
            let _handle = SessionHandle {
                send_tx,
                recv_rx,
                shutdown_tx: Some(shutdown_tx),
                peer_id: [0u8; 32],
            };
            // handle dropped here
        }

        // shutdown should have been triggered
        assert!(*shutdown_rx.borrow_and_update());
    }

    #[test]
    fn session_handle_peer_id_hex() {
        let (send_tx, _recv_rx) = mpsc::channel::<String>(64);
        let (_event_tx, recv_rx) = mpsc::channel::<SessionEvent>(64);
        let peer_id = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                       0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                       0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
                       0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C];
        let handle = SessionHandle {
            send_tx,
            recv_rx,
            shutdown_tx: None,
            peer_id,
        };
        assert_eq!(handle.peer_id_hex(), hex::encode(peer_id));
    }

    #[tokio::test]
    async fn session_handle_close_sends_shutdown() {
        let (send_tx, _recv_rx) = mpsc::channel::<String>(64);
        let (_event_tx, recv_rx) = mpsc::channel::<SessionEvent>(64);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = SessionHandle {
            send_tx,
            recv_rx,
            shutdown_tx: Some(shutdown_tx),
            peer_id: [0u8; 32],
        };

        handle.close().await;
        assert!(*shutdown_rx.borrow_and_update());
    }

    #[tokio::test]
    async fn send_and_receive_session_events() {
        let (_send_tx, _send_rx) = mpsc::channel::<String>(64);
        let (event_tx, mut recv_rx) = mpsc::channel::<SessionEvent>(64);
        let (_shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);

        event_tx
            .send(SessionEvent::Connected {
                peer_id: [1u8; 32],
                fingerprint: "abcd".into(),
            })
            .await
            .unwrap();

        let event = recv_rx.recv().await.unwrap();
        match event {
            SessionEvent::Connected { peer_id, fingerprint } => {
                assert_eq!(peer_id, [1u8; 32]);
                assert_eq!(fingerprint, "abcd");
            }
            _ => panic!("expected Connected event"),
        }
    }
}
