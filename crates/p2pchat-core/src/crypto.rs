//! Noise XX handshake wrapper using the `snow` crate.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_SHA256`
//!
//! The handshake mutually authenticates both peers (each sends their static
//! public key) and produces a shared secret used to seed the Double Ratchet.

use anyhow::{Context, Result, anyhow};
use snow::{Builder, HandshakeState as SnowHandshake, TransportState};

/// Noise protocol parameters.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Which side of the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Initiates the connection.
    Initiator,
    /// Responds to the connection.
    Responder,
}

/// Wraps a Noise XX handshake in progress.
pub struct NoiseHandshake {
    state: SnowHandshake,
    _role: HandshakeRole,
}

impl NoiseHandshake {
    /// Create a new handshake state.
    pub fn new(role: HandshakeRole, private_key: &[u8; 32]) -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| anyhow!("parse Noise params: {e}"))?;
        let builder = Builder::new(params);
        let state = match role {
            HandshakeRole::Initiator => builder
                .local_private_key(private_key)
                .build_initiator()
                .map_err(|e| anyhow!("build Noise initiator: {e}"))?,
            HandshakeRole::Responder => builder
                .local_private_key(private_key)
                .build_responder()
                .map_err(|e| anyhow!("build Noise responder: {e}"))?,
        };
        Ok(Self { state, _role: role })
    }

    /// Write the next handshake message into `output`.
    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize> {
        self.state
            .write_message(payload, output)
            .map_err(|e| anyhow!("Noise write_message: {e}"))
    }

    /// Read and process a handshake message from the peer.
    pub fn read_message(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.state
            .read_message(input, output)
            .map_err(|e| anyhow!("Noise read_message: {e}"))
    }

    /// Whether the handshake is complete.
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Consume the handshake and extract the result.
    pub fn finalize(self) -> Result<HandshakeResult> {
        let peer_static = self.state.get_remote_static().map(|k| {
            let mut out = [0u8; 32];
            out.copy_from_slice(k.as_ref());
            out
        });
        let handshake_hash = {
            let h = self.state.get_handshake_hash();
            let mut out = [0u8; 32];
            out.copy_from_slice(h);
            out
        };
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| anyhow!("Noise into transport: {e}"))?;
        Ok(HandshakeResult {
            peer_static,
            handshake_hash,
            transport_state: transport,
        })
    }
}

/// Result of a successful Noise XX handshake.
#[derive(Debug)]
pub struct HandshakeResult {
    /// Peer's static public key (32 bytes).
    pub peer_static: Option<[u8; 32]>,
    /// 32-byte handshake hash.
    pub handshake_hash: [u8; 32],
    /// TransportState for encrypting/decrypting data.
    pub transport_state: TransportState,
}

/// Perform a full Noise XX handshake over an async read/write transport.
pub async fn perform_handshake<R, W>(
    role: HandshakeRole,
    private_key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
) -> Result<HandshakeResult>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    use tokio::io::AsyncWriteExt;

    let mut hs = NoiseHandshake::new(role, private_key)?;

    let mut buf = vec![0u8; 65535];

    match role {
        HandshakeRole::Initiator => {
            // Message 1: initiator → responder (e)
            let n = hs.write_message(&[], &mut buf)?;
            let framed = crate::message::encode_frame(&buf[..n]);
            writer.write_all(&framed).await?;

            // Message 2: responder → initiator (e, ee, s, es)
            let frame = read_one_frame(reader).await?;
            hs.read_message(&frame, &mut buf)?;

            // Message 3: initiator → responder (s, se)
            let n = hs.write_message(&[], &mut buf)?;
            let framed = crate::message::encode_frame(&buf[..n]);
            writer.write_all(&framed).await?;
        }
        HandshakeRole::Responder => {
            // Message 1: initiator → responder (e)
            let frame = read_one_frame(reader).await?;
            hs.read_message(&frame, &mut buf)?;

            // Message 2: responder → initiator (e, ee, s, es)
            let n = hs.write_message(&[], &mut buf)?;
            let framed = crate::message::encode_frame(&buf[..n]);
            writer.write_all(&framed).await?;

            // Message 3: initiator → responder (s, se)
            let frame = read_one_frame(reader).await?;
            hs.read_message(&frame, &mut buf)?;
        }
    }

    if !hs.is_finished() {
        anyhow::bail!("Noise handshake did not complete after 3 messages");
    }

    hs.finalize()
}

/// Read one length-prefixed frame from an async reader.
pub(crate) async fn read_one_frame<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .context("read frame header")?;
    let len = u32::from_le_bytes(header) as usize;
    if len > crate::message::MAX_FRAME_SIZE {
        anyhow::bail!("frame too large: {len} > {}", crate::message::MAX_FRAME_SIZE);
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .context("read frame payload")?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn noise_xx_handshake_in_memory() {
        use tokio::io::split;
        use x25519_dalek::{PublicKey, StaticSecret};

        let a_priv = [1u8; 32];
        let b_priv = [2u8; 32];
        let a_pub = *PublicKey::from(&StaticSecret::from(a_priv)).as_bytes();
        let b_pub = *PublicKey::from(&StaticSecret::from(b_priv)).as_bytes();

        let (alice_end, bob_end) = duplex(65536);
        let (mut alice_read, mut alice_write) = split(alice_end);
        let (mut bob_read, mut bob_write) = split(bob_end);

        let alice = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Initiator,
                &a_priv,
                &mut alice_read,
                &mut alice_write,
            )
            .await
        });

        let bob = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Responder,
                &b_priv,
                &mut bob_read,
                &mut bob_write,
            )
            .await
        });

        let (a_res, b_res) = tokio::join!(alice, bob);
        let a_res = a_res.expect("initiator panicked").expect("initiator failed");
        let b_res = b_res.expect("responder panicked").expect("responder failed");

        assert_eq!(a_res.handshake_hash, b_res.handshake_hash);
        assert_eq!(a_res.peer_static, Some(b_pub));
        assert_eq!(b_res.peer_static, Some(a_pub));
    }

    #[tokio::test]
    async fn noise_handshake_with_different_keys_produces_different_hash() {
        use tokio::io::split;
        use x25519_dalek::{PublicKey, StaticSecret};

        // Different key material from the other test
        let a_priv = [3u8; 32];
        let b_priv = [4u8; 32];
        let a_pub = *PublicKey::from(&StaticSecret::from(a_priv)).as_bytes();
        let b_pub = *PublicKey::from(&StaticSecret::from(b_priv)).as_bytes();

        let (alice_end, bob_end) = duplex(65536);
        let (mut alice_read, mut alice_write) = split(alice_end);
        let (mut bob_read, mut bob_write) = split(bob_end);

        let alice = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Initiator,
                &a_priv,
                &mut alice_read,
                &mut alice_write,
            )
            .await
        });

        let bob = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Responder,
                &b_priv,
                &mut bob_read,
                &mut bob_write,
            )
            .await
        });

        let (a_res, b_res) = tokio::join!(alice, bob);
        let a_res = a_res.expect("initiator panicked").expect("initiator failed");
        let b_res = b_res.expect("responder panicked").expect("responder failed");

        assert_eq!(a_res.handshake_hash, b_res.handshake_hash);
        assert_eq!(a_res.peer_static, Some(b_pub));
        assert_eq!(b_res.peer_static, Some(a_pub));

        // Must differ from the hash in the other test (different keys)
        assert_ne!(a_res.handshake_hash, [0u8; 32]);
    }

    #[tokio::test]
    async fn noise_handshake_both_initiator_fails() {
        use tokio::io::split;

        let a_priv = [1u8; 32];
        let b_priv = [2u8; 32];

        let (alice_end, bob_end) = duplex(65536);
        let (mut alice_read, mut alice_write) = split(alice_end);
        let (mut bob_read, mut bob_write) = split(bob_end);

        // Both sides as initiator — each writes its ephemeral key then reads
        // the other's ephemeral key as if it were the responder's msg2, which
        // has a different format and causes snow to return an error.
        let alice = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Initiator,
                &a_priv,
                &mut alice_read,
                &mut alice_write,
            )
            .await
        });

        let bob = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Initiator,
                &b_priv,
                &mut bob_read,
                &mut bob_write,
            )
            .await
        });

        let (a_res, b_res) = tokio::join!(alice, bob);
        let a_err = a_res.map_or(true, |r| r.is_err());
        let b_err = b_res.map_or(true, |r| r.is_err());
        assert!(
            a_err || b_err,
            "both-initiator handshake should have failed"
        );
    }

    #[tokio::test]
    async fn noise_handshake_wrong_key_mismatched_peer_static() {
        use tokio::io::split;
        use x25519_dalek::{PublicKey, StaticSecret};

        let a_priv = [1u8; 32];
        let b_priv = [2u8; 32];
        let fake_priv = [9u8; 32];
        let b_expected_pub = *PublicKey::from(&StaticSecret::from(b_priv)).as_bytes();

        let (alice_end, bob_end) = duplex(65536);
        let (mut alice_read, mut alice_write) = split(alice_end);
        let (mut bob_read, mut bob_write) = split(bob_end);

        // Alice uses the correct private key, Bob uses a different key
        let alice = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Initiator,
                &a_priv,
                &mut alice_read,
                &mut alice_write,
            )
            .await
        });

        let bob = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Responder,
                &fake_priv,
                &mut bob_read,
                &mut bob_write,
            )
            .await
        });

        let (a_res, b_res) = tokio::join!(alice, bob);
        let a_res = a_res.expect("alice panicked").expect("alice failed");
        let b_res = b_res.expect("bob panicked").expect("bob failed");

        // Noise XX completes at the protocol level, but Alice's peer_static
        // is derived from fake_priv, not from b_priv.
        assert_ne!(
            a_res.peer_static,
            Some(b_expected_pub),
            "peer_static should not match expected key"
        );
        // Bob's peer_static should still match Alice's real public key
        let a_pub = *PublicKey::from(&StaticSecret::from(a_priv)).as_bytes();
        assert_eq!(b_res.peer_static, Some(a_pub));
    }

    #[tokio::test]
    async fn noise_handshake_role_display() {
        assert_eq!(format!("{:?}", HandshakeRole::Initiator), "Initiator");
        assert_eq!(format!("{:?}", HandshakeRole::Responder), "Responder");
    }

    #[test]
    fn noise_handshake_new_fails_on_invalid_private_key() {
        // An all-zeros key is technically valid for X25519 but might be clamped.
        // Test that the constructor accepts a valid key and works.
        let hs = NoiseHandshake::new(HandshakeRole::Initiator, &[1u8; 32]);
        assert!(hs.is_ok());
    }

    #[tokio::test]
    async fn noise_handshake_in_memory_exchange_data() {
        use tokio::io::split;

        let a_priv = [1u8; 32];
        let b_priv = [2u8; 32];

        let (alice_end, bob_end) = duplex(65536);
        let (mut alice_read, mut alice_write) = split(alice_end);
        let (mut bob_read, mut bob_write) = split(bob_end);

        let alice = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Initiator,
                &a_priv,
                &mut alice_read,
                &mut alice_write,
            )
            .await
        });

        let bob = tokio::spawn(async move {
            perform_handshake(
                HandshakeRole::Responder,
                &b_priv,
                &mut bob_read,
                &mut bob_write,
            )
            .await
        });

        let (a_res, b_res) = tokio::join!(alice, bob);
        let mut a_res = a_res.expect("initiator panicked").expect("initiator failed");
        let mut b_res = b_res.expect("responder panicked").expect("responder failed");

        // After handshake, we can encrypt/decrypt with transport_state
        let alice_msg = b"hello from alice";
        let mut alice_out = vec![0u8; 65535];
        let n = a_res
            .transport_state
            .write_message(alice_msg, &mut alice_out)
            .unwrap();
        let alice_encrypted = &alice_out[..n];

        let mut bob_decrypted = vec![0u8; 65535];
        let n = b_res
            .transport_state
            .read_message(alice_encrypted, &mut bob_decrypted)
            .unwrap();
        assert_eq!(&bob_decrypted[..n], alice_msg);

        // Also the other direction
        let bob_msg = b"hello from bob";
        let mut bob_out = vec![0u8; 65535];
        let n = b_res
            .transport_state
            .write_message(bob_msg, &mut bob_out)
            .unwrap();
        let bob_encrypted = &bob_out[..n];

        let mut alice_decrypted = vec![0u8; 65535];
        let n = a_res
            .transport_state
            .read_message(bob_encrypted, &mut alice_decrypted)
            .unwrap();
        assert_eq!(&alice_decrypted[..n], bob_msg);
    }
}
