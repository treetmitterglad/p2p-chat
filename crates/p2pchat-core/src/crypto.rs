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
}
