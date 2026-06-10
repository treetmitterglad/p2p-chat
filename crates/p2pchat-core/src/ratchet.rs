//! Double Ratchet per-message encryption.
//!
//! Implementation of the Signal Double Ratchet algorithm for post-compromise
//! security and forward secrecy. Uses X25519 DH ratchet stepping, HKDF-based
//! key derivation, and XChaCha20-Poly1305 AEAD for message encryption.

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::message::WireMessage;

/// Default number of messages per ratchet before forcing a DH step.
const DEFAULT_MAX_MESSAGES: u32 = 100;

/// A Double Ratchet instance for one direction of a conversation.
pub struct Ratchet {
    dh_secret: StaticSecret,
    dh_public: PublicKey,
    peer_dh_public: PublicKey,

    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],

    send_msg_num: u32,
    recv_msg_num: u32,
    prev_chain_len: u32,

    max_messages: u32,
    _is_initiator: bool,
}

impl std::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ratchet")
            .field("dh_public", &hex::encode(self.dh_public.as_bytes()))
            .field(
                "peer_dh_public",
                &hex::encode(self.peer_dh_public.as_bytes()),
            )
            .field("send_msg_num", &self.send_msg_num)
            .field("recv_msg_num", &self.recv_msg_num)
            .field("prev_chain_len", &self.prev_chain_len)
            .field("max_messages", &self.max_messages)
            .finish_non_exhaustive()
    }
}

impl Ratchet {
    /// Create a new Ratchet from the Noise XX handshake output.
    ///
    /// * `root_key` — the 32-byte handshake hash from Noise XX.
    /// * `our_static_private` — our Ed25519 seed (converted for X25519).
    /// * `peer_static_public` — peer's 32-byte static public key.
    /// * `is_initiator` — whether we initiated the connection.
    pub fn new(
        root_key: &[u8; 32],
        our_static_private: &[u8; 32],
        peer_static_public: &[u8; 32],
        is_initiator: bool,
    ) -> Self {
        let dh_secret = StaticSecret::from(*our_static_private);
        let dh_public = PublicKey::from(&dh_secret);
        let peer_dh_public = PublicKey::from(*peer_static_public);

        let shared_secret = dh_secret.diffie_hellman(&peer_dh_public);
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), shared_secret.as_bytes());
        let mut output = [0u8; 96];
        hkdf.expand(b"p2pchat-ratchet-init", &mut output)
            .expect("HKDF expand with valid length");

        let mut new_rk = [0u8; 32];
        let mut ck_a = [0u8; 32];
        let mut ck_b = [0u8; 32];
        new_rk.copy_from_slice(&output[0..32]);
        ck_a.copy_from_slice(&output[32..64]);
        ck_b.copy_from_slice(&output[64..96]);

        let (send_chain_key, recv_chain_key) = if is_initiator {
            (ck_a, ck_b)
        } else {
            (ck_b, ck_a)
        };

        Ratchet {
            dh_secret,
            dh_public,
            peer_dh_public,
            root_key: new_rk,
            send_chain_key,
            recv_chain_key,
            send_msg_num: 0,
            recv_msg_num: 0,
            prev_chain_len: 0,
            max_messages: DEFAULT_MAX_MESSAGES,
            _is_initiator: is_initiator,
        }
    }

    /// Encrypt a plaintext message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> WireMessage {
        if self.send_msg_num >= self.max_messages {
            self.ratchet_step_send();
        }

        let (msg_key, new_ck) = derive_message_key(&self.send_chain_key);
        self.send_chain_key = new_ck;

        let mut nonce = [0u8; 24];
        rand_core::OsRng.fill_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&msg_key));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .expect("XChaCha20-Poly1305 encryption should not fail");

        let msg_num = self.send_msg_num;
        self.send_msg_num += 1;

        WireMessage::RatchetEncrypted {
            dh_public_key: *self.dh_public.as_bytes(),
            previous_chain_len: self.prev_chain_len,
            message_num: msg_num,
            nonce,
            ciphertext,
        }
    }

    /// Decrypt a message received from the peer.
    pub fn decrypt(&mut self, msg: &WireMessage) -> Result<Vec<u8>> {
        let (dh_pub, _pn, n, nonce, ciphertext) = match msg {
            WireMessage::RatchetEncrypted {
                dh_public_key,
                previous_chain_len,
                message_num,
                nonce,
                ciphertext,
            } => (
                *dh_public_key,
                *previous_chain_len,
                *message_num,
                *nonce,
                ciphertext,
            ),
            _ => anyhow::bail!("expected RatchetEncrypted message"),
        };

        let peer_key = PublicKey::from(dh_pub);

        if peer_key.as_bytes() != self.peer_dh_public.as_bytes() {
            let shared_secret = self.dh_secret.diffie_hellman(&peer_key);
            let hkdf = Hkdf::<Sha256>::new(Some(&self.root_key), shared_secret.as_bytes());
            let mut output = [0u8; 96];
            hkdf.expand(b"p2pchat-ratchet-step", &mut output)
                .expect("HKDF expand");

            let mut new_rk = [0u8; 32];
            let mut new_send_ck = [0u8; 32];
            let mut new_recv_ck = [0u8; 32];
            new_rk.copy_from_slice(&output[0..32]);
            new_send_ck.copy_from_slice(&output[32..64]);
            new_recv_ck.copy_from_slice(&output[64..96]);

            let old_send_num = self.send_msg_num;
            self.root_key = new_rk;
            // We received a ratchet step, so the first output chain key
            // (output[32..64]) is used for receiving (peer→us), and
            // the second (output[64..96]) for sending (us→peer).
            self.recv_chain_key = new_send_ck;
            self.send_chain_key = new_recv_ck;
            self.send_msg_num = 0;
            self.recv_msg_num = 0;
            self.prev_chain_len = old_send_num;
            self.peer_dh_public = peer_key;

            let new_secret = StaticSecret::random_from_rng(
                &mut rand_core::OsRng,
            );
            self.dh_secret = new_secret;
            self.dh_public = PublicKey::from(&self.dh_secret);
        }

        // With in-order delivery (QUIC), n should equal recv_msg_num.
        // We always derive at position 0 because the chain key is already
        // advanced past previously received messages.
        let (msg_key, next_ck) = derive_message_key_at(&self.recv_chain_key, 0)?;
        self.recv_chain_key = next_ck;
        self.recv_msg_num = self.recv_msg_num.max(n + 1);

        let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&msg_key));
        let plaintext = cipher
            .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| anyhow!("Double Ratchet decryption failed"))?;

        Ok(plaintext)
    }

    /// Access the current DH public key (ours).
    pub fn dh_public_bytes(&self) -> [u8; 32] {
        *self.dh_public.as_bytes()
    }

    /// Access the peer's current DH public key.
    pub fn peer_dh_public_bytes(&self) -> [u8; 32] {
        *self.peer_dh_public.as_bytes()
    }

    /// Set max messages before forced DH ratchet step.
    pub fn set_max_messages(&mut self, max: u32) {
        self.max_messages = max;
    }

    fn ratchet_step_send(&mut self) {
        self.prev_chain_len = self.send_msg_num;

        let new_secret = StaticSecret::random_from_rng(
            &mut rand_core::OsRng,
        );
        let new_public = PublicKey::from(&new_secret);

        let shared_secret = new_secret.diffie_hellman(&self.peer_dh_public);
        let hkdf = Hkdf::<Sha256>::new(Some(&self.root_key), shared_secret.as_bytes());
        let mut output = [0u8; 96];
        hkdf.expand(b"p2pchat-ratchet-step", &mut output)
            .expect("HKDF expand");

        let mut new_rk = [0u8; 32];
        let mut new_send_ck = [0u8; 32];
        let mut new_recv_ck = [0u8; 32];
        new_rk.copy_from_slice(&output[0..32]);
        new_send_ck.copy_from_slice(&output[32..64]);
        new_recv_ck.copy_from_slice(&output[64..96]);

        self.root_key = new_rk;
        self.send_chain_key = new_send_ck;
        self.recv_chain_key = new_recv_ck;
        self.send_msg_num = 0;
        self.dh_secret = new_secret;
        self.dh_public = new_public;
    }
}

fn derive_message_key(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ck).expect("HMAC key");
    mac.update(&[0x01u8]);
    let mk = mac.finalize().into_bytes();

    let mut mac2 = <Hmac<Sha256> as Mac>::new_from_slice(ck).expect("HMAC key");
    mac2.update(&[0x02u8]);
    let next = mac2.finalize().into_bytes();

    let mut msg_key = [0u8; 32];
    let mut next_ck = [0u8; 32];
    msg_key.copy_from_slice(&mk);
    next_ck.copy_from_slice(&next);
    (msg_key, next_ck)
}

/// Derive the message key at position `n` in a chain, and return the
/// next chain key (at position n+1).
fn derive_message_key_at(ck: &[u8; 32], n: u32) -> Result<([u8; 32], [u8; 32])> {
    let mut current = *ck;
    for i in 0..=n {
        let (msg_key, next) = derive_message_key(&current);
        if i == n {
            return Ok((msg_key, next));
        }
        current = next;
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ratchets() -> (Ratchet, Ratchet) {
        let root = [0x42u8; 32];
        let alice_priv = [1u8; 32];
        let bob_priv = [2u8; 32];
        let alice_pub = {
            let s = StaticSecret::from(alice_priv);
            *PublicKey::from(&s).as_bytes()
        };
        let bob_pub = {
            let s = StaticSecret::from(bob_priv);
            *PublicKey::from(&s).as_bytes()
        };

        let alice = Ratchet::new(&root, &alice_priv, &bob_pub, true);
        let bob = Ratchet::new(&root, &bob_priv, &alice_pub, false);
        (alice, bob)
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let (mut alice, mut bob) = make_test_ratchets();
        let msg = b"hello world";
        let encrypted = alice.encrypt(msg);
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, msg);
    }

    #[test]
    fn multiple_messages_in_order() {
        let (mut alice, mut bob) = make_test_ratchets();
        for i in 0..10 {
            let msg = format!("message {i}");
            let encrypted = alice.encrypt(msg.as_bytes());
            let decrypted = bob.decrypt(&encrypted).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), msg);
        }
    }

    #[test]
    fn bidirectional_messages() {
        let (mut alice, mut bob) = make_test_ratchets();
        let a_msg = b"from alice";
        let encrypted = alice.encrypt(a_msg);
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, a_msg);

        let b_msg = b"from bob";
        let encrypted = bob.encrypt(b_msg);
        let decrypted = alice.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, b_msg);
    }

    #[test]
    fn auto_ratchet_step_after_max_messages() {
        let (mut alice, mut bob) = make_test_ratchets();
        alice.set_max_messages(5);
        bob.set_max_messages(5);
        for i in 0..10 {
            let msg = format!("msg {i}");
            let encrypted = alice.encrypt(msg.as_bytes());
            let decrypted = bob.decrypt(&encrypted).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), msg);
        }
    }
}
