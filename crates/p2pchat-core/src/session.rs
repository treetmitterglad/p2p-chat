use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use sha2::Digest;
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
        peer_id: [u8; 32],
        fingerprint: String,
    },
    /// Received a text message.
    MessageReceived {
        text: String,
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

    eprintln!("connecting...");
    let conn = transport
        .connect(ticket.addr())
        .await
        .context("connect to peer")?;

    let peer_id = *conn.remote_id().as_bytes();
    let (send_stream, recv_stream) = conn.open_bi().await?;

    let result = crypto::perform_handshake(
        HandshakeRole::Initiator,
        &identity.seed(),
        &mut tokio::io::BufReader::new(recv_stream),
        &mut tokio::io::BufWriter::new(send_stream),
    )
    .await?;

    spawn_session(store, identity, result, peer_id).await
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

    let ticket = transport.ticket().to_string();
    eprintln!("waiting for incoming connection...");
    eprintln!("share this ticket: {ticket}");

    let conn = transport
        .accept()
        .await?
        .ok_or_else(|| anyhow!("endpoint closed before accept"))?;

    let peer_id = *conn.remote_id().as_bytes();
    let (send_stream, recv_stream) = conn.accept_bi().await?;

    let result = crypto::perform_handshake(
        HandshakeRole::Responder,
        &identity.seed(),
        &mut tokio::io::BufReader::new(recv_stream),
        &mut tokio::io::BufWriter::new(send_stream),
    )
    .await?;

    spawn_session(store, identity, result, peer_id)
        .await
        .map(|handle| (ticket, handle))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async fn spawn_session(
    store: storage::Store,
    identity: identity::Identity,
    handshake: crypto::HandshakeResult,
    peer_id: [u8; 32],
) -> Result<SessionHandle> {
    let peer_static = handshake.peer_static.unwrap_or_default();
    let is_initiator = identity.node_id() < peer_static;

    let mut ratchet = Ratchet::new(
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
            store, send_rx, event_tx, shutdown_rx, &mut ratchet,
        )
        .await;
    });

    Ok(SessionHandle {
        send_tx,
        recv_rx,
        shutdown_tx: Some(shutdown_tx),
        peer_id,
    })
}

async fn run_message_loop(
    _store: storage::Store,
    mut send_rx: mpsc::Receiver<String>,
    event_tx: mpsc::Sender<SessionEvent>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    _ratchet: &mut Ratchet,
) {
    // For now, the message loop just waits for shutdown.
    // In a future iteration, we'll wire up network I/O here.
    // The handshake has already completed and the reader/writer
    // streams need to be passed into this function for actual
    // message exchange.
    loop {
        tokio::select! {
            Ok(()) = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(_text) = send_rx.recv() => {
                // TODO: encrypt and send via network writer
            }
            else => break,
        }
    }
    let _ = event_tx.send(SessionEvent::Disconnected).await;
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
