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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_frame_round_trip() {
        let payload = b"hello world";
        let frame = encode_frame(payload);
        let (decoded, rest) = decode_frame(&frame).unwrap();
        assert_eq!(decoded, payload);
        assert!(rest.is_empty());
    }

    #[test]
    fn encode_decode_frame_empty_payload() {
        let frame = encode_frame(b"");
        let (decoded, rest) = decode_frame(&frame).unwrap();
        assert!(decoded.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn frame_remaining_bytes() {
        let payload = b"hello";
        let frame = encode_frame(payload);
        // append extra data
        let mut extended = frame.clone();
        extended.extend_from_slice(b"extra");
        let (decoded, rest) = decode_frame(&extended).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(rest, b"extra");
    }

    #[test]
    fn decode_frame_returns_none_for_incomplete_header() {
        assert!(decode_frame(b"").is_none());
        assert!(decode_frame(b"\x01").is_none());
        assert!(decode_frame(b"\x01\x00").is_none());
        assert!(decode_frame(b"\x01\x00\x00").is_none());
    }

    #[test]
    fn decode_frame_returns_none_for_truncated_payload() {
        // length says 10 but only 3 bytes follow
        let mut frame = vec![10u8, 0, 0, 0];
        frame.extend_from_slice(b"abc");
        assert!(decode_frame(&frame).is_none());
    }

    #[test]
    fn decode_frame_returns_none_for_excessive_length() {
        let mut frame = vec![0u8; 4];
        // Set length to MAX_FRAME_SIZE + 1
        let len = (MAX_FRAME_SIZE + 1) as u32;
        frame.copy_from_slice(&len.to_le_bytes());
        assert!(decode_frame(&frame).is_none());
    }

    #[test]
    fn encode_frame_max_size() {
        let payload = vec![0xABu8; MAX_FRAME_SIZE];
        let frame = encode_frame(&payload);
        let (decoded, _) = decode_frame(&frame).unwrap();
        assert_eq!(decoded.len(), MAX_FRAME_SIZE);
        assert!(decoded.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn wire_message_text_round_trip() {
        let msg = WireMessage::Text { text: "hi there".into() };
        let frame = msg.encode().unwrap();
        let (payload, _) = decode_frame(&frame).unwrap();
        let decoded = WireMessage::decode(payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn wire_message_ack_round_trip() {
        let msg = WireMessage::Ack { message_id: [0x42u8; 16] };
        let frame = msg.encode().unwrap();
        let (payload, _) = decode_frame(&frame).unwrap();
        let decoded = WireMessage::decode(payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn wire_message_error_round_trip() {
        let msg = WireMessage::Error { msg: "something went wrong".into() };
        let frame = msg.encode().unwrap();
        let (payload, _) = decode_frame(&frame).unwrap();
        let decoded = WireMessage::decode(payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn wire_message_ratchet_encrypted_round_trip() {
        let msg = WireMessage::RatchetEncrypted {
            dh_public_key: [0x01u8; 32],
            previous_chain_len: 5,
            message_num: 3,
            nonce: [0xABu8; 24],
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let frame = msg.encode().unwrap();
        let (payload, _) = decode_frame(&frame).unwrap();
        let decoded = WireMessage::decode(payload).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn wire_message_decode_returns_error_on_garbage() {
        let result = WireMessage::decode(b"not valid postcard");
        assert!(result.is_err());
    }

    #[test]
    fn wire_message_encode_is_length_prefixed() {
        let msg = WireMessage::Text { text: "test".into() };
        let frame = msg.encode().unwrap();
        assert!(frame.len() >= 4);
        let payload_len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 4 + payload_len);
    }

    #[test]
    fn multiple_frames_in_stream() {
        let msgs = vec![
            WireMessage::Text { text: "first".into() },
            WireMessage::Text { text: "second".into() },
            WireMessage::Ack { message_id: [0u8; 16] },
        ];
        let mut stream = Vec::new();
        for m in &msgs {
            stream.extend_from_slice(&m.encode().unwrap());
        }

        let mut cursor = &stream[..];
        for expected in &msgs {
            let (payload, rest) = decode_frame(cursor).unwrap();
            let decoded = WireMessage::decode(payload).unwrap();
            assert_eq!(&decoded, expected);
            cursor = rest;
        }
        assert!(cursor.is_empty());
    }
}
