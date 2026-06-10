//! Wire format: length-prefixed frames + message types.
//!
//! All data on the wire is framed as:
//! ```text
//! [4 bytes LE length][payload]
//! ```
//!
//! During Noise XX handshake, the payload is a raw Noise handshake message.
//! After handshake, the payload is a [`WireMessage`] encoded via postcard.



/// Maximum frame payload size (64 KiB).
pub const MAX_FRAME_SIZE: usize = 65536;

/// Decode one length-prefixed frame from the front of `data`.
/// Returns `(frame_payload, remaining_bytes)` or `None` if incomplete.
pub fn decode_frame(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if len > MAX_FRAME_SIZE {
        return None;
    }
    if data.len() < 4 + len {
        return None;
    }
    Some((&data[4..4 + len], &data[4 + len..]))
}

/// Encode a payload into a length-prefixed frame.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Post-handshake message types.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WireMessage {
    /// Plain text chat message.
    Text {
        /// The message text.
        text: String,
    },
    /// Double Ratchet encrypted payload (after Noise handshake).
    RatchetEncrypted {
        /// Ephemeral DH public key (32 bytes) for the ratchet step.
        dh_public_key: [u8; 32],
        /// Number of messages in previous sending chain (PN).
        previous_chain_len: u32,
        /// Message number in current sending chain (N).
        message_num: u32,
        /// Nonce for the AEAD (12 bytes).
        nonce: [u8; 24],
        /// Ciphertext (message encrypted with message key).
        ciphertext: Vec<u8>,
    },
    /// Acknowledge receipt of a message.
    Ack {
        /// Message id (128-bit random).
        message_id: [u8; 16],
    },
    /// Error message.
    Error {
        /// Human-readable error.
        msg: String,
    },
}

impl WireMessage {
    /// Serialize to a length-prefixed frame.
    pub fn encode(&self) -> Result<Vec<u8>, postcard::Error> {
        let payload = postcard::to_stdvec(self)?;
        Ok(encode_frame(&payload))
    }

    /// Deserialize from a byte slice.
    pub fn decode(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}
